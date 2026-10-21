# Run from an independent Administrator Windows PowerShell. Default is read-only.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BuildDirectory,[string]$Python='python',[switch]$Install,[switch]$Recover,
    [ValidateRange(1,16)][int]$Workers=4)
$ErrorActionPreference='Stop'
if($Install -and $Recover) {throw 'Choose one deployment action.'}
$directory=(Resolve-Path -LiteralPath $BuildDirectory).ProviderPath
$plan=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $directory 'plan.json') | ConvertFrom-Json
$core=Join-Path $PSScriptRoot 'fast_patch.py'
$profilePath=Join-Path (Split-Path -Parent $PSScriptRoot) ("profiles\{0}.json" -f $plan.BaseVersion)
if(-not(Test-Path -LiteralPath $profilePath)) {throw 'Unsupported plan version.'}
$profile=Get-Content -Raw -Encoding UTF8 -LiteralPath $profilePath | ConvertFrom-Json
if($plan.Publisher -cne $profile.publisher) {throw 'Plan publisher mismatch.'}
$base=[version]$plan.BaseVersion
$expectedFast='{0}.{1}.{2}.{3}' -f $base.Major,$base.Minor,$base.Build,($base.Revision+1)
$expectedRecovery='{0}.{1}.{2}.{3}' -f $base.Major,$base.Minor,$base.Build,($base.Revision+2)
if($plan.FastVersion -cne $expectedFast -or $plan.RecoveryVersion -cne $expectedRecovery) {throw 'Unexpected deployment versions.'}
if([IO.Path]::GetFullPath($plan.FastPath) -ine (Join-Path $directory 'fast-unsigned.msix') -or
   [IO.Path]::GetFullPath($plan.RecoveryPath) -ine (Join-Path $directory 'recovery-unsigned.msix')) {throw 'Artifacts must belong to the selected build directory.'}
function Hash-Check($Path,$Hash) {if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) {throw 'Artifact hash mismatch.'}}
function Read-SignedCache($CachePath,$Directory,$Plan,$Thumbprint) {
    if(-not(Test-Path -LiteralPath $CachePath -PathType Leaf)) {return $null}
    $cache=Get-Content -Raw -Encoding UTF8 -LiteralPath $CachePath | ConvertFrom-Json
    # Old/other builds and certificates cannot reuse this record.
    if($cache.CertificateThumbprint -ine $Thumbprint -or $cache.SourceFastHash -ine $Plan.FastHash -or
       $cache.SourceRecoveryHash -ine $Plan.RecoveryHash) {return $null}
    $paths=@{}
    foreach($label in @('fast','recovery')) {
        $path=if($label -eq 'fast'){$cache.FastPath}else{$cache.RecoveryPath}
        if(-not $path) {throw 'Incomplete signed artifact record.'}
        $full=[IO.Path]::GetFullPath($path)
        if((Split-Path -Parent $full) -ine $Directory -or (Split-Path -Leaf $full) -notmatch ('^'+$label+'-signed-[0-9a-f]{8}\.msix$')) {
            throw 'Signed artifact record points outside this build.'
        }
        if(-not(Test-Path -LiteralPath $full -PathType Leaf)) {return $null}
        $entry=@($cache.Artifacts | Where-Object path -eq $full)
        if($entry.Count -ne 1 -or $entry[0].sha256 -notmatch '^[0-9a-fA-F]{64}$') {throw 'Incomplete signed artifact digest.'}
        $paths[$label]=$full
    }
    return [pscustomobject]@{Paths=$paths;Artifacts=$cache.Artifacts}
}
Hash-Check $core $plan.CoreHash
$pkg=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
$expected=if($Recover){$plan.FastVersion}else{$plan.BaseVersion}
if(-not $pkg -or [string]$pkg.Version -ne $expected -or $pkg.Publisher -cne $plan.Publisher) {throw 'Installed version/publisher changed; rebuild instead of downgrading.'}
if(-not $Recover -and [string]$pkg.SignatureKind -ne 'Store') {throw 'Expected the original Store package.'}
$timer=[Diagnostics.Stopwatch]::StartNew();$timings=[ordered]@{}
function Stage([string]$Name) {$timings[$Name]=[math]::Round($timer.Elapsed.TotalSeconds,3);$timer.Restart();Write-Host "Completed $Name in $($timings[$Name])s"}
$packageJson=& $Python $core packages $plan.FastPath $plan.RecoveryPath --workers $Workers
if($LASTEXITCODE) {throw 'Parallel MSIX payload verification failed.'}
$artifacts=($packageJson -join "`n") | ConvertFrom-Json
foreach($artifact in $artifacts) {
    $path=$artifact.path
    $manifestIdentity=$artifact.identity
    $expectedHash=if($path -eq $plan.FastPath){$plan.FastHash}elseif($path -eq $plan.RecoveryPath){$plan.RecoveryHash}else{throw 'Unexpected artifact.'}
    if($artifact.sha256 -ine $expectedHash) {throw 'Artifact hash mismatch.'}
    $artifactVersion=if($path -eq $plan.FastPath){$plan.FastVersion}else{$plan.RecoveryVersion}
    if($manifestIdentity.Name -cne 'OpenAI.Codex' -or $manifestIdentity.Publisher -cne $plan.Publisher -or
        $manifestIdentity.Version -cne $artifactVersion -or $manifestIdentity.ProcessorArchitecture -cne 'x64') {throw 'MSIX identity mismatch.'}
}
Stage 'parallel_unsigned_payload_and_hashes'
if(-not($Install -or $Recover)) {Write-Host 'CHECK-ONLY-OK. No certificate, process or package changes.';return}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.User.Value -ne $plan.UserSid) {throw 'Use the same Windows user who built the package.'}
if(-not([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Open Administrator Windows PowerShell from Start.'}
function Assert-NoNewerPackage {
    $all=@(Get-AppxPackage -AllUsers -Name OpenAI.Codex -ErrorAction Stop)
    if($all | Where-Object {[version]$_.Version -gt [version]$expected}) {throw 'A newer registered or staged package exists. Rebuild for that version; no downgrade will be attempted.'}
}
Assert-NoNewerPackage
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
$previousTemp=$env:TEMP;$previousTmp=$env:TMP
$phase='preparing';$shutdownStarted=$false
function Save-Status([string]$State,[string]$Message='') {
    [pscustomobject]@{state=$State;phase=$phase;shutdownStarted=$shutdownStarted;message=$Message} | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $directory 'install-status.json') -Encoding UTF8
}
try {
    Save-Status 'running'
    $signTemp=Join-Path $directory 'signing-temp'
    New-Item -ItemType Directory -Path $signTemp -Force | Out-Null
    $env:TEMP=$signTemp;$env:TMP=$signTemp
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
    $cache=Read-SignedCache (Join-Path $directory 'signed-artifacts.json') $directory $plan $cert.Thumbprint
    if($null -ne $cache) {
        $signed=$cache.Paths
        Write-Host 'Reusing prepared signed packages; Windows signature and full payload checks still run.'
        Stage 'reuse_signed_packages'
    } else {
        $signed=@{};$jobs=@();$stamp=[guid]::NewGuid().ToString('N').Substring(0,8)
        foreach($label in @('recovery','fast')) {
            $source=if($label -eq 'fast'){$plan.FastPath}else{$plan.RecoveryPath}
            $sourceHash=if($label -eq 'fast'){$plan.FastHash}else{$plan.RecoveryHash}
            $destination=Join-Path $directory ($label+'-signed-'+$stamp+'.msix')
            $signed[$label]=$destination
            $jobs+=[pscustomobject]@{source=$source;destination=$destination;sha256=$sourceHash}
        }
        $signPlan=Join-Path $directory ('sign-plan-'+$stamp+'.json')
        [pscustomobject]@{signtool=$signTool;thumbprint=$cert.Thumbprint;jobs=$jobs} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $signPlan -Encoding UTF8
        Write-Host 'Copying with SHA256 in one pass, then signing both packages (Codex stays open).'
        $signJson=& $Python $core sign $signPlan --workers ([math]::Min(2,$Workers))
        if($LASTEXITCODE) {throw 'Signing failed; app still open.'}
        $signReport=($signJson -join "`n") | ConvertFrom-Json
        $signReport | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'signing-timings.json') -Encoding UTF8
        Write-Host "Verified copy: $($signReport.copy_and_sha256_seconds)s; SignTool: $($signReport.signtool_seconds)s"
        Stage 'verified_copy_and_sign'
    }
    foreach($destination in @($signed['fast'],$signed['recovery'])) {
        $signature=Get-AuthenticodeSignature -LiteralPath $destination
        if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {throw 'Signature verification failed; app still open.'}
    }
    Stage 'windows_signature_verification'
    $signedJson=& $Python $core packages $signed['fast'] $signed['recovery'] --workers $Workers
    if($LASTEXITCODE) {throw 'Parallel signed payload verification failed; app still open.'}
    $signedArtifacts=($signedJson -join "`n") | ConvertFrom-Json
    foreach($item in $signedArtifacts) {
        if($null -ne $cache) {
            $saved=@($cache.Artifacts | Where-Object path -eq $item.path)
            if($saved.Count -ne 1 -or $saved[0].sha256 -ine $item.sha256) {throw 'Previously signed artifact changed; app still open.'}
        }
        $original=if($item.path -eq $signed['fast']){@($artifacts|Where-Object path -eq $plan.FastPath)[0]}else{@($artifacts|Where-Object path -eq $plan.RecoveryPath)[0]}
        if(($item.identity|ConvertTo-Json -Compress) -cne ($original.identity|ConvertTo-Json -Compress)) {throw 'Signing changed package identity.'}
    }
    [pscustomobject]@{FastPath=$signed['fast'];RecoveryPath=$signed['recovery'];Artifacts=$signedArtifacts
        CertificateThumbprint=$cert.Thumbprint;SourceFastHash=$plan.FastHash;SourceRecoveryHash=$plan.RecoveryHash} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'signed-artifacts.json') -Encoding UTF8
    Stage 'parallel_signed_payload_and_hashes'
    # Artifacts are fully prepared before any shutdown; refuse Store-version races.
    Assert-NoNewerPackage
    $current=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
    if($current.PackageFullName -ne $pkg.PackageFullName) {throw 'Source version changed before shutdown.'}
    $timings | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'install-timings.json') -Encoding UTF8
    $prefix=$pkg.InstallLocation.TrimEnd('\')+'\'
    $phase='closing_codex';Save-Status 'running'
    Write-Host 'All checks passed. Closing Codex now.'
    $shutdownStarted=$true
    for($attempt=0;$attempt -lt 3;$attempt++) {
        Get-CimInstance Win32_Process | Where-Object {
            $_.SessionId -eq $session -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)
        } | ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
        Start-Sleep -Milliseconds 700
    }
    $target=if($Recover){$signed['recovery']}else{$signed['fast']}
    $phase='deploying';Save-Status 'running'
    Add-AppxPackage -Path $target -ForceApplicationShutdown -ErrorAction Stop
    $installed=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
    $version=if($Recover){$plan.RecoveryVersion}else{$plan.FastVersion}
    if([string]$installed.Version -ne $version -or $installed.Publisher -cne $plan.Publisher) {throw 'Installed identity mismatch. Inspect deployment logs; no blind retry.'}
    $app=@(Get-AppxPackageManifest -Package $installed).Package.Applications.Application | Select-Object -First 1
    Start-Process explorer.exe -ArgumentList ("shell:AppsFolder\{0}!{1}" -f $installed.PackageFamilyName,$app.Id)
    $phase='registered_launch_requested';Save-Status 'installed-awaiting-user-verification'
    Write-Host 'Package registered and launch requested. Verify the Desktop window and Fast with your own request.'
} catch {Save-Status 'failed' $_.Exception.Message;throw} finally {
    $env:TEMP=$previousTemp;$env:TMP=$previousTmp
    $lock.Dispose()
}
