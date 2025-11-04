param(
  [string]$RenderedFile = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_AGENT_RENDEFILE)) { $env:VAULT_AGENT_RENDEFILE } else { '../vault/agent/config/ad-creds.json' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail($msg) {
  Write-Error $msg
  exit 1
}

if (-not (Test-Path -LiteralPath $RenderedFile)) {
  Fail "Rendered credentials file not found: $RenderedFile"
}

try {
  $jsonText = Get-Content -LiteralPath $RenderedFile -Raw -ErrorAction Stop
  $creds = $jsonText | ConvertFrom-Json -ErrorAction Stop
} catch {
  Fail "Failed to read/parse rendered credentials file '$RenderedFile'. $_"
}

$username = $creds.username
$password = $creds.password

if ([string]::IsNullOrWhiteSpace($username)) { Fail "Username missing in rendered file '$RenderedFile' (expected property: username)." }
if ([string]::IsNullOrWhiteSpace($password)) { Fail "Password missing in rendered file '$RenderedFile' (expected property: password)." }

$domain = $env:VAULT_CRED_DOMAIN
if (-not [string]::IsNullOrWhiteSpace($domain) -and ($username -notmatch '^[^\\]+\\')) {
  $username = "$domain\$username"
}

Write-Host "Fetching credential for user via Vault Agent: $username, password is: $password"

Write-Host 'Success.'