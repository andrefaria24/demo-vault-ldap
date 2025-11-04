param(
  [string]$MountPoint = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_LDAP_MOUNT)) { $env:VAULT_LDAP_MOUNT } else { 'ldap' }),
  [string]$RoleName = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_LDAP_ROLE)) { $env:VAULT_LDAP_ROLE } else { 'powershell-dynamic' })
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

$ldapUrl = "$vaultAddr/v1/$MountPoint/creds/$RoleName"

$headers = @{ 'X-Vault-Token' = $vaultToken }
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  $headers['X-Vault-Namespace'] = $vaultNamespace
}

Write-Host "Reading LDAP dynamic credentials from $MountPoint/creds/$RoleName..."
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  Write-Host "Using Vault namespace: $vaultNamespace"
}

try {
  $resp = Invoke-RestMethod -Method GET -Uri $ldapUrl -Headers $headers
} catch {
  Fail "Failed to read LDAP dynamic credentials from Vault at $ldapUrl. $_"
}

if (-not $resp -or -not $resp.data) {
  Fail 'LDAP dynamic response missing expected data.'
}

$username = $resp.data.username
$password = $resp.data.password
$ttl = $resp.lease_duration

if ([string]::IsNullOrWhiteSpace($username)) { Fail 'Username not found in LDAP dynamic creds (data.username).' }
if ([string]::IsNullOrWhiteSpace($password)) { Fail 'Password not found in LDAP dynamic creds (data.password).' }

$domain = $env:VAULT_CRED_DOMAIN
$netbios = $env:VAULT_CRED_NETBIOS

$candidateUsernames = New-Object System.Collections.Generic.List[string]
if ($username -match '\\' -or $username -match '@') {
  $candidateUsernames.Add($username)
} else {
  $candidateUsernames.Add($username)
  if (-not [string]::IsNullOrWhiteSpace($domain)) {
    if ($domain -match '\.') {
      $candidateUsernames.Add("$username@$domain")
      if (-not [string]::IsNullOrWhiteSpace($netbios)) {
        $candidateUsernames.Add("$netbios\$username")
      }
    } else {
      $candidateUsernames.Add("$domain\$username")
    }
  }
}
$candidateUsernames = $candidateUsernames | Select-Object -Unique
Write-Host ("Trying username variants: " + ($candidateUsernames -join ', '))
if ($ttl) { Write-Host "Credential TTL (seconds): $ttl" }

# We will attempt each username variant; for the successful one, write creds to file

$lastError = $null
foreach ($u in $candidateUsernames) {
  Write-Host "Attempting logon as: $u"
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential ($u, $securePassword)
  # Build per-attempt command embedding the selected username and password
  $fileContent = "username=$u`npassword=$password"
  $fileContentB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($fileContent))
  $inner = @"
New-Item -ItemType Directory -Path 'C:\dev' -Force | Out-Null
[IO.File]::WriteAllText('C:\dev\hello_world_ldap-dynamic.txt',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$fileContentB64')))
Write-Host 'Wrote credentials to C:\dev\hello_world_ldap-dynamic.txt'
"@
  $argList = @(
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    $inner
  )
  try {
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Credential $cred -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
    if ($p.ExitCode -eq 0) {
      Write-Host 'Success.'
      return
    } else {
      Write-Host "Process exited with code $($p.ExitCode) for user $u. Trying next variant..."
      $lastError = "ExitCode=$($p.ExitCode)"
    }
  } catch {
    Write-Host "Logon failed for ${u}: $($_.Exception.Message)"
    $lastError = $_.Exception.Message
  }
}

Fail ("Failed to start process with supplied credentials. Tried: " + ($candidateUsernames -join ', ') + ". Last error: $lastError")
