# Run from an independent Administrator Windows PowerShell. Default is read-only.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BuildDirectory,[string]$Python='python',[switch]$Install,[switch]$Recover)
$ErrorActionPreference='Stop'
if($Install -and $Recover) {throw 'Choose one deployment action.'}
$directory=(Resolve-Path -LiteralPath $BuildDirectory).ProviderPath
$plan=Get-Content -Raw -LiteralPath (Join-Path $directory 'plan.json') | ConvertFrom-Json
$core=Join-Path $PSScriptRoot 'fast_patch.py'
$profilePath=Join-Path (Split-Path -Parent $PSScriptRoot) ("profiles\{0}.json" -f $plan.BaseVersion)
if(-not(Test-Path -LiteralPath $profilePath)) {throw 'Unsupported plan version.'}
$profile=Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json
if($plan.Publisher -cne $profile.publisher) {throw 'Plan publisher mismatch.'}
$base=[version]$plan.BaseVersion
$expectedFast='{0}.{1}.{2}.{3}' -f $base.Major,$base.Minor,$base.Build,($base.Revision+1)
$expectedRecovery='{0}.{1}.{2}.{3}' -f $base.Major,$base.Minor,$base.Build,($base.Revision+2)
if($plan.FastVersion -cne $expectedFast -or $plan.RecoveryVersion -cne $expectedRecovery) {throw 'Unexpected deployment versions.'}
if([IO.Path]::GetFullPath($plan.FastPath) -ine (Join-Path $directory 'fast-unsigned.msix') -or
   [IO.Path]::GetFullPath($plan.RecoveryPath) -ine (Join-Path $directory 'recovery-unsigned.msix')) {throw 'Artifacts must belong to the selected build directory.'}
function Hash-Check($Path,$Hash) {if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) {throw 'Artifact hash mismatch.'}}
Hash-Check $core $plan.CoreHash
Hash-Check $plan.FastPath $plan.FastHash
Hash-Check $plan.RecoveryPath $plan.RecoveryHash
foreach($path in @($plan.FastPath,$plan.RecoveryPath)) {
    & $Python $core msix $path
    if($LASTEXITCODE) {throw 'MSIX payload verification failed.'}
    $manifestIdentity=& $Python $core identity $path
    if($LASTEXITCODE) {throw 'MSIX identity inspection failed.'}
    $manifestIdentity=($manifestIdentity -join "`n") | ConvertFrom-Json
    $artifactVersion=if($path -eq $plan.FastPath){$plan.FastVersion}else{$plan.RecoveryVersion}
    if($manifestIdentity.Name -cne 'OpenAI.Codex' -or $manifestIdentity.Publisher -cne $plan.Publisher -or
        $manifestIdentity.Version -cne $artifactVersion -or $manifestIdentity.ProcessorArchitecture -cne 'x64') {throw 'MSIX identity mismatch.'}
}
$pkg=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
$expected=if($Recover){$plan.FastVersion}else{$plan.BaseVersion}
if(-not $pkg -or [string]$pkg.Version -ne $expected -or $pkg.Publisher -cne $plan.Publisher) {throw 'Installed version/publisher changed; rebuild instead of downgrading.'}
if(-not $Recover -and [string]$pkg.SignatureKind -ne 'Store') {throw 'Expected the original Store package.'}
if(-not($Install -or $Recover)) {Write-Host 'CHECK-ONLY-OK. No certificate, process or package changes.';return}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.User.Value -ne $plan.UserSid) {throw 'Use the same Windows user who built the package.'}
if(-not([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Open Administrator Windows PowerShell from Start.'}
# Reject executors whose ancestors include any Codex WindowsApps process.
$ancestor=$PID;$seen=@{}
while($ancestor -gt 0 -and -not $seen.ContainsKey($ancestor)) {
    $seen[$ancestor]=$true
    if($seen.Count -gt 64) {throw 'Cannot verify executor ancestry.'}
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$ancestor" -ErrorAction Stop
    if(-not $process) {break}
    if($process.ExecutablePath -match '(?i)[\\/]WindowsApps[\\/]OpenAI\.Codex_[^\\/]+[\\/]') {throw 'Run outside the Codex process tree.'}
    $ancestor=[int]$process.ParentProcessId
}
$session=(Get-Process -Id $PID).SessionId
if($session -eq 0) {throw 'An interactive user session is required.'}
$phrase=if($Recover){'RECOVER ORIGINAL'}else{'INSTALL FAST'}
Write-Host 'This trusts a local public signing certificate in LocalMachine TrustedPeople (never Root), then closes this session''s Codex processes and updates in place.' -ForegroundColor Yellow
if((Read-Host "Type $phrase to continue") -cne $phrase) {Write-Host 'Cancelled before certificate/process/package changes.';return}
$lock=[IO.File]::Open((Join-Path $directory 'installer.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $signTool=Join-Path $plan.WindowsSdkBin 'signtool.exe'
    if(-not(Test-Path -LiteralPath $signTool)) {throw 'SignTool missing. No app closed.'}
    $cert=Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.Subject -ceq $plan.Publisher -and $_.FriendlyName -ceq 'Codex Fast Minimal local signing' -and
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3')
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if(-not $cert) {
        $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject $plan.Publisher -CertStoreLocation Cert:\CurrentUser\My `
            -FriendlyName 'Codex Fast Minimal local signing' -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(1)
    }
    $public=Join-Path $directory 'local-signing.cer'
    Export-Certificate -Cert $cert -FilePath $public -Force | Out-Null
    if(-not(Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object Thumbprint -eq $cert.Thumbprint)) {
        Import-Certificate -FilePath $public -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
    }
    $signed=@{}
    foreach($pair in @(@('recovery',$plan.RecoveryPath),@('fast',$plan.FastPath))) {
        $destination=Join-Path $directory ($pair[0]+'-signed.msix')
        Copy-Item -LiteralPath $pair[1] -Destination $destination -Force
        & $signTool sign /fd SHA256 /sha1 $cert.Thumbprint $destination | Out-Null
        if($LASTEXITCODE) {throw 'Signing failed; app still open.'}
        $signature=Get-AuthenticodeSignature -LiteralPath $destination
        if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {throw 'Signature verification failed; app still open.'}
        & $Python $core msix $destination
        if($LASTEXITCODE) {throw 'Signed payload failed verification.'}
        $signed[$pair[0]]=$destination
    }
    $current=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
    if($current.PackageFullName -ne $pkg.PackageFullName) {throw 'Source version changed before shutdown.'}
    $prefix=$pkg.InstallLocation.TrimEnd('\')+'\'
    Write-Host 'All checks passed. Closing Codex now.'
    for($attempt=0;$attempt -lt 3;$attempt++) {
        Get-CimInstance Win32_Process | Where-Object {
            $_.SessionId -eq $session -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)
        } | ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
        Start-Sleep -Milliseconds 700
    }
    $target=if($Recover){$signed['recovery']}else{$signed['fast']}
    Add-AppxPackage -Path $target -ForceApplicationShutdown -ErrorAction Stop
    $installed=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
    $version=if($Recover){$plan.RecoveryVersion}else{$plan.FastVersion}
    if([string]$installed.Version -ne $version -or $installed.Publisher -cne $plan.Publisher) {throw 'Installed identity mismatch. Inspect deployment logs; no blind retry.'}
    $app=@(Get-AppxPackageManifest -Package $installed).Package.Applications.Application | Select-Object -First 1
    Start-Process explorer.exe -ArgumentList ("shell:AppsFolder\{0}!{1}" -f $installed.PackageFamilyName,$app.Id)
    Write-Host 'Package registered and launch requested. Verify the Desktop window and Fast with your own request.'
} finally {$lock.Dispose()}
