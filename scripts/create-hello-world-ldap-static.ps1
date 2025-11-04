param(
  [string]$MountPoint = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_LDAP_MOUNT)) { $env:VAULT_LDAP_MOUNT } else { 'ldap' }),
  [string]$RoleName = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_LDAP_ROLE)) { $env:VAULT_LDAP_ROLE } else { 'python-static' })
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

$MountPoint = $MountPoint.Trim('/').Trim()
if ($MountPoint -like 'v1/*') { $MountPoint = $MountPoint.Substring(3) }
if ($MountPoint -match '^(?<ns>[^/]+)/(?<mp>[^/].*)$') {
  $mpNs = $Matches['ns']
  $mpOnly = $Matches['mp']
  if ([string]::IsNullOrWhiteSpace($vaultNamespace) -or $vaultNamespace -eq $mpNs) {
    $vaultNamespace = if ([string]::IsNullOrWhiteSpace($vaultNamespace)) { $mpNs } else { $vaultNamespace }
    $MountPoint = $mpOnly
  }
}

$ldapUrl = "$vaultAddr/v1/$MountPoint/static-cred/$RoleName"

$headers = @{ 'X-Vault-Token' = $vaultToken }
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  $headers['X-Vault-Namespace'] = $vaultNamespace
}

Write-Host "Reading LDAP static credentials from $MountPoint/static-cred/$RoleName..."
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  Write-Host "Using Vault namespace: $vaultNamespace"
}

try {
  $resp = Invoke-RestMethod -Method GET -Uri $ldapUrl -Headers $headers
} catch {
  Fail "Failed to read LDAP static credentials from Vault at $ldapUrl. $_"
}

if (-not $resp -or -not $resp.data) {
  Fail 'LDAP response missing expected data.'
}

$username = $resp.data.username
$password = $resp.data.password

if ([string]::IsNullOrWhiteSpace($username)) { Fail 'Username not found in LDAP static creds (data.username).' }
if ([string]::IsNullOrWhiteSpace($password)) { Fail 'Password not found in LDAP static creds (data.password).' }

$domain = $env:VAULT_CRED_DOMAIN
if (-not [string]::IsNullOrWhiteSpace($domain) -and ($username -notmatch '^[^\\]+\\')) {
  $username = "$domain\$username"
}

Write-Host "Using credential for user: $username"

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

$inner = @'
New-Item -ItemType Directory -Path "C:\dev" -Force | Out-Null
New-Item -ItemType File -Path "C:\dev\hello_world_ldap.txt" -Force | Out-Null
Write-Host "Created file: C:\dev\hello_world_ldap.txt"
'@

$argList = "-NoProfile -NonInteractive -Command `"$inner`""

try {
  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Credential $cred -PassThru -Wait -WindowStyle Hidden
} catch {
  Fail "Failed to start process with supplied credentials. $_"
}

if ($p.ExitCode -ne 0) {
  Fail "Child PowerShell exited with code $($p.ExitCode)."
}

Write-Host 'Success.'