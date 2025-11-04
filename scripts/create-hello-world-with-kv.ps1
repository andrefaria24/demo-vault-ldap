param(
  [string]$MountPoint = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_KV_MOUNT)) { $env:VAULT_KV_MOUNT } else { 'kv' }),
  [string]$SecretPath = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_KV_PATH)) { $env:VAULT_KV_PATH } else { 'python_app' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail($msg) {
  Write-Error $msg
  exit 1
}

$vaultAddr = $env:VAULT_ADDR
$vaultToken = $env:VAULT_TOKEN
$vaultNamespace = $env:VAULT_NAMESPACE

if ([string]::IsNullOrWhiteSpace($vaultAddr)) { Fail 'Environment variable VAULT_ADDR is not set.' }
if ([string]::IsNullOrWhiteSpace($vaultToken)) { Fail 'Environment variable VAULT_TOKEN is not set.' }

if ($vaultAddr.EndsWith('/')) { $vaultAddr = $vaultAddr.TrimEnd('/') }

$kvUrl = "$vaultAddr/v1/$MountPoint/data/$SecretPath"

$headers = @{ 'X-Vault-Token' = $vaultToken }
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  $headers['X-Vault-Namespace'] = $vaultNamespace
}

Write-Host "Reading KVv2 secret from $MountPoint/$SecretPath..."

try {
  $resp = Invoke-RestMethod -Method GET -Uri $kvUrl -Headers $headers
} catch {
  Fail "Failed to read secret from Vault at $kvUrl. $_"
}

if (-not $resp -or -not $resp.data -or -not $resp.data.data) {
  Fail 'Secret response missing expected data (data.data).'
}

$username = $resp.data.data.username
$password = $resp.data.data.password

if ([string]::IsNullOrWhiteSpace($username)) { Fail 'Username not found in secret (data.data.username).' }
if ([string]::IsNullOrWhiteSpace($password)) { Fail 'Password not found in secret (data.data.password).' }

$domain = $env:VAULT_CRED_DOMAIN
if (-not [string]::IsNullOrWhiteSpace($domain) -and ($username -notmatch '^[^\\]+\\')) {
  $username = "$domain\$username"
}

Write-Host "Using credential for user: $username"

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

$inner = @'
New-Item -ItemType Directory -Path "C:\dev" -Force | Out-Null
New-Item -ItemType File -Path "C:\dev\hello_world.txt" -Force | Out-Null
Write-Host "Created file: C:\dev\hello_world.txt"
'@

$argList = @('-NoProfile', '-NonInteractive', '-Command', $inner)

try {
  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Credential $cred -PassThru -Wait -WindowStyle Hidden
} catch {
  Fail "Failed to start process with supplied credentials. $_"
}

if ($p.ExitCode -ne 0) {
  Fail "Child PowerShell exited with code $($p.ExitCode)."
}

Write-Host 'Success.'