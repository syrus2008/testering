# Production signing (spec §64, ACET-SUP-002, ACC-056). Keys/certificates are never in the repo.
# Usage: ./sign.ps1 -Files dist\ACET\acet.exe,Output\ACET-Setup-x.y.z.exe -CertThumbprint <sha1>
param([string[]]$Files, [string]$CertThumbprint, [string]$TimestampUrl = "http://timestamp.digicert.com")
$ErrorActionPreference = "Stop"
foreach ($f in $Files) {
  signtool sign /sha1 $CertThumbprint /fd sha256 /tr $TimestampUrl /td sha256 /d "ACET" $f
  signtool verify /pa /v $f   # CI fails if signature or RFC 3161 timestamp is invalid
  (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower() + "  " + (Split-Path $f -Leaf) | Add-Content signed-hashes.txt
}
