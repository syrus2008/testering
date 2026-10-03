# Windows packaging smoke test (ACC-001/025 building blocks, run by CI on a hosted runner).
#
# Exercises the real artifacts, not the Python sources:
#   1. the frozen build in dist\ACET runs with no Python on PATH: --version, a FAST analysis
#      (workers started through `acet.exe __worker__`) and `doctor --full`;
#   2. the Inno Setup installer installs silently per user; the installed acet.exe works;
#   3. the uninstaller removes the application and keeps the workspaces (INV-015).
# A hosted runner is not a clean VM: the manual protocols MP-001/MP-002 remain required.
param(
    [Parameter(Mandatory = $true)][string]$Dist,
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Demo
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "SMOKE FAILED: $Message" }
    Write-Host "ok - $Message"
}

function Invoke-Acet([string]$Exe, [string[]]$CliArgs, [int[]]$Allowed = @(0)) {
    $out = & $Exe @CliArgs
    Assert-True ($Allowed -contains $LASTEXITCODE) "acet $($CliArgs -join ' ') exited $LASTEXITCODE"
    return ($out -join "`n")
}

function Test-Analysis([string]$Exe, [string]$Label) {
    $ws = (Invoke-Acet $Exe @("workspace", "create", "smoke-$Label", "--json")) | ConvertFrom-Json
    $env:ACET_WORKSPACE = $ws.path
    Invoke-Acet $Exe @("product", "create", "Fictional Guard", "--json") | Out-Null
    $imp = (Invoke-Acet $Exe @("import", (Join-Path $Demo "builds\v1"), "--product", "Fictional Guard", "--json")) | ConvertFrom-Json
    $run = (Invoke-Acet $Exe @("analyze", $imp.build_id, "--profile", "FAST@1", "--json")) | ConvertFrom-Json
    Assert-True ($run.status -eq "COMPLETED") "$Label FAST analysis through acet.exe workers (status $($run.status))"
    Remove-Item Env:\ACET_WORKSPACE
    return $ws.path
}

# Isolated ACET home; no Python reachable from PATH.
$env:ACET_HOME = Join-Path $env:RUNNER_TEMP "acet-smoke-home"
# (WindowsApps holds the Microsoft Store "python.exe" alias stub.)
$env:PATH = (($env:PATH -split ";") | Where-Object { $_ -and ($_ -notmatch "(?i)python|hostedtoolcache|WindowsApps") }) -join ";"
$py = Get-Command python, python3 -CommandType Application -ErrorAction SilentlyContinue
Assert-True ($null -eq $py) "no python on PATH ($(($py | ForEach-Object Source) -join ', '))"

# 1. Frozen build
$frozen = Join-Path $Dist "acet.exe"
$ver = Invoke-Acet $frozen @("--version")
Assert-True ($ver -match "^acet \d+\.\d+") "frozen acet --version ($ver)"
Test-Analysis $frozen "frozen" | Out-Null
$doc = (Invoke-Acet $frozen @("doctor", "--full", "--json") @(0, 10)) | ConvertFrom-Json
$st = ($doc.checks | Where-Object { $_.name -eq "golden self-test" }).data.self_test
Assert-True ($st.verdict -ne "FAILED") "doctor --full golden self-test not FAILED (verdict $($st.verdict), engines $($st.engine_mode))"
foreach ($c in @("import", "FAST facts")) {
    Assert-True ((($st.checks | Where-Object { $_.name -eq $c }).ok) -eq $true) "self-test check '$c' uses the packaged demo dataset"
}
Assert-True (Test-Path (Join-Path $Dist "licenses\THIRD-PARTY-NOTICES.txt")) "third-party notices shipped"

# 2. Installer (per-user, silent)
$installDir = Join-Path $env:RUNNER_TEMP "acet-smoke-install"
$log = Join-Path $env:RUNNER_TEMP "acet-smoke-install.log"
$p = Start-Process -FilePath $Installer -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/DIR=`"$installDir`"", "/LOG=`"$log`"") -Wait -PassThru
Assert-True ($p.ExitCode -eq 0) "installer exit code $($p.ExitCode)"
$installed = Join-Path $installDir "acet.exe"
Assert-True (Test-Path $installed) "acet.exe installed"
Assert-True (Test-Path (Join-Path $installDir "acet-ui.exe")) "acet-ui.exe installed"
$wsPath = Test-Analysis $installed "installed"

# 3. Uninstall keeps research data
$unins = Get-ChildItem $installDir -Filter "unins*.exe" | Select-Object -First 1
Assert-True ($null -ne $unins) "uninstaller present"
$p = Start-Process -FilePath $unins.FullName -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART") -Wait -PassThru
Assert-True ($p.ExitCode -eq 0) "uninstaller exit code $($p.ExitCode)"
# The uninstaller re-spawns itself from %TEMP%; wait for the files to disappear.
for ($i = 0; $i -lt 60 -and (Test-Path $installed); $i++) { Start-Sleep -Seconds 1 }
Assert-True (-not (Test-Path $installed)) "application removed by uninstall"
Assert-True (Test-Path $wsPath) "workspace kept after uninstall (INV-015)"
Write-Host "packaging smoke test passed"
