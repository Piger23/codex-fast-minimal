[CmdletBinding()]
param([string]$OutputRoot,[string]$Python='python',[string]$WindowsSdkBin,[switch]$Build,[switch]$Compress,
    [ValidateRange(1,16)][int]$Workers=4)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$core=Join-Path $PSScriptRoot 'fast_patch.py'
$timer=[Diagnostics.Stopwatch]::StartNew();$timings=[ordered]@{}
function Stage([string]$Name) {$timings[$Name]=[math]::Round($timer.Elapsed.TotalSeconds,3);$timer.Restart();Write-Host "Completed $Name in $($timings[$Name])s"}
$pkg=Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | Select-Object -First 1
if(-not $pkg -or [string]$pkg.SignatureKind -ne 'Store') { throw 'A supported original Store package is required.' }
$profilePath=Join-Path $repo ("profiles\{0}.json" -f $pkg.Version)
if(-not(Test-Path -LiteralPath $profilePath)) { throw "Unsupported version: $($pkg.Version). No changes made." }
$profile=Get-Content -Raw -Encoding UTF8 -LiteralPath $profilePath | ConvertFrom-Json
if($pkg.Publisher -cne $profile.publisher) { throw 'Unexpected publisher.' }
function Python-Run([string[]]$Arguments) {
    & $Python $core @Arguments
    if($LASTEXITCODE -ne 0) { throw 'Python verification failed.' }
}
$originalAsar=Join-Path $pkg.InstallLocation 'app\resources\app.asar'
Python-Run @('inspect',$originalAsar,'--profile',$profilePath)
Stage 'inspect'
if(-not $Build) { Write-Host 'Inspection passed. Use -Build -OutputRoot <new-directory> to create unsigned packages.'; return }
if(-not $OutputRoot) { throw '-OutputRoot is required for a build.' }
$output=[IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
if($output.StartsWith($pkg.InstallLocation.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
    $output -eq $pkg.InstallLocation -or (Test-Path -LiteralPath $output)) { throw 'Output must be a NEW directory outside the installed package.' }
if(-not $WindowsSdkBin) {
    $WindowsSdkBin=Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe' -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 | ForEach-Object {$_.DirectoryName}
}
if(-not $WindowsSdkBin) {throw 'Windows SDK was not found. Supply -WindowsSdkBin; no tools are downloaded.'}
$make=Join-Path $WindowsSdkBin 'makeappx.exe'
if(-not(Test-Path -LiteralPath $make)) { throw 'Install Windows SDK MakeAppx/SignTool first, or supply -WindowsSdkBin. This tool downloads nothing.' }
New-Item -ItemType Directory -Path $output | Out-Null
$work=Join-Path $output 'package'
New-Item -ItemType Directory -Path $work | Out-Null
& robocopy.exe $pkg.InstallLocation $work /E /COPY:DAT /XJ /MT:8 /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
if($LASTEXITCODE -gt 7) { throw 'Package copy failed.' }
Stage 'copy'
foreach($rel in @('AppxSignature.p7x','AppxBlockMap.xml','AppxMetadata\CodeIntegrity.cat')) {
    $path=Join-Path $work $rel
    if(Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
$manifest=Join-Path $work 'AppxManifest.xml'
Set-ItemProperty -LiteralPath $manifest -Name IsReadOnly -Value $false
$base=[version]$pkg.Version
if($base.Revision -gt 65533) { throw 'Cannot safely allocate patch and recovery versions.' }
$fastVersion='{0}.{1}.{2}.{3}' -f $base.Major,$base.Minor,$base.Build,($base.Revision+1)
$recoveryVersion='{0}.{1}.{2}.{3}' -f $base.Major,$base.Minor,$base.Build,($base.Revision+2)
function Manifest-Version([string]$Version) {
    [xml]$xml=Get-Content -Raw -Encoding UTF8 -LiteralPath $manifest
    $xml.Package.Identity.SetAttribute('Version',$Version)
    $settings=[Xml.XmlWriterSettings]::new();$settings.Encoding=[Text.UTF8Encoding]::new($false)
    $writer=[Xml.XmlWriter]::Create($manifest,$settings)
    try {$xml.Save($writer)} finally {$writer.Dispose()}
}
function Pack([string]$Destination) {
    $options=@('pack','/d',$work,'/p',$Destination)
    if(-not $Compress) {$options+='/nc'}
    & $make @options | Out-Null
    if($LASTEXITCODE) {throw 'MakeAppx failed.'}
}
# Pack original program content first; only manifest version/package metadata differ.
Manifest-Version $recoveryVersion
$recovery=Join-Path $output 'recovery-unsigned.msix'
Pack $recovery
Stage 'pack_recovery'
$newAsar=Join-Path $output 'patched.asar'
Python-Run @('patch',$originalAsar,$newAsar,'--profile',$profilePath,'--workers',"$Workers")
$exe=Join-Path $work 'app\ChatGPT.exe'
Set-ItemProperty -LiteralPath $exe -Name IsReadOnly -Value $false
Python-Run @('launcher',$originalAsar,$newAsar,$exe)
$workAsar=Join-Path $work 'app\resources\app.asar'
Set-ItemProperty -LiteralPath $workAsar -Name IsReadOnly -Value $false
Copy-Item -LiteralPath $newAsar -Destination $workAsar -Force
Stage 'patch_and_verify_asar'
Manifest-Version $fastVersion
$fast=Join-Path $output 'fast-unsigned.msix'
Pack $fast
Stage 'pack_fast'
Python-Run @('package-scope',$pkg.InstallLocation,$recovery,'--mode','recovery')
Python-Run @('package-scope',$pkg.InstallLocation,$fast,'--mode','fast')
Stage 'store_blockmap_and_manifest_scope'
# Verify the entire package scope, beyond just the packed ASAR target.
Python-Run @('scope',$pkg.InstallLocation,$work,'--workers',"$Workers")
Stage 'parallel_package_scope'
$packageJson=& $Python $core packages $fast $recovery --workers $Workers
if($LASTEXITCODE) {throw 'Parallel MSIX verification failed.'}
$packages=($packageJson -join "`n") | ConvertFrom-Json
$fastInfo=@($packages|Where-Object path -eq $fast)[0]
$recoveryInfo=@($packages|Where-Object path -eq $recovery)[0]
if($fastInfo.identity.Version -ne $fastVersion -or $recoveryInfo.identity.Version -ne $recoveryVersion) {throw 'Packed identity mismatch.'}
$packageJson | Set-Content -LiteralPath (Join-Path $output 'payload-verification.json') -Encoding UTF8
Stage 'parallel_msix_payload_and_hashes'
$plan=[pscustomobject]@{
    SourcePackage=$pkg.PackageFullName;BaseVersion=[string]$pkg.Version;Publisher=$pkg.Publisher
    FastVersion=$fastVersion;RecoveryVersion=$recoveryVersion;FastPath=$fast;RecoveryPath=$recovery
    FastHash=$fastInfo.sha256
    RecoveryHash=$recoveryInfo.sha256
    UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    WindowsSdkBin=$WindowsSdkBin;Compressed=[bool]$Compress
    CoreHash=(Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash
    Workers=$Workers
}
$plan | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'plan.json') -Encoding UTF8
$timings | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'build-timings.json') -Encoding UTF8
Write-Host "Unsigned Fast/recovery packages ready in $output. No certificate or installation changes made."
