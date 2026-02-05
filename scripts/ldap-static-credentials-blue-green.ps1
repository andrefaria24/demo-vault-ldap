param(
  [string]$MountPoint = $(if (-not [string]::IsNullOrWhiteSpace($env:VAULT_LDAP_MOUNT)) { $env:VAULT_LDAP_MOUNT } else { 'ldap' }),
  [string]$PrimaryRoleName = 'static-service-account-a',
  [string]$FallbackRoleName = 'static-service-account-b',
  [int]$MaxRetries = 3,
  [int]$RetryDelaySeconds = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail($msg) {
  Write-Error $msg
  exit 1
}

function Write-TimestampedMessage {
  param(
    [string]$Message,
    [string]$Color = 'White'
  )
  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Get-VaultLdapCredentials {
  param(
    [string]$VaultAddr,
    [hashtable]$Headers,
    [string]$MountPoint,
    [string]$RoleName
  )
  
  $ldapUrl = "$VaultAddr/v1/$MountPoint/static-cred/$RoleName"
  
  try {
    $response = Invoke-RestMethod -Method GET -Uri $ldapUrl -Headers $Headers -ErrorAction Stop
    
    if (-not $response -or -not $response.data) {
      throw "Response missing expected data structure"
    }
    
    $username = $response.data.username
    $password = $response.data.password
    
    if ([string]::IsNullOrWhiteSpace($username)) {
      throw "Username not found in response (data.username)"
    }
    
    if ([string]::IsNullOrWhiteSpace($password)) {
      throw "Password not found in response (data.password)"
    }
    
    return @{
      Success = $true
      Username = $username
      Password = $password
      Error = $null
    }
  }
  catch {
    return @{
      Success = $false
      Username = $null
      Password = $null
      Error = $_.Exception.Message
    }
  }
}

# Display script header
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Vault LDAP Credentials Retrieval" -ForegroundColor Cyan
Write-Host "  with Retry & Fallback Logic" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get Vault configuration from environment variables
$vaultAddr = $env:VAULT_ADDR
$vaultToken = $env:VAULT_TOKEN
$vaultNamespace = $env:VAULT_NAMESPACE

# Validate required environment variables
if ([string]::IsNullOrWhiteSpace($vaultAddr)) { 
  Fail 'Environment variable VAULT_ADDR is not set.' 
}
if ([string]::IsNullOrWhiteSpace($vaultToken)) { 
  Fail 'Environment variable VAULT_TOKEN is not set.' 
}

# Clean up Vault address
if ($vaultAddr.EndsWith('/')) { 
  $vaultAddr = $vaultAddr.TrimEnd('/') 
}

# Process mount point
$MountPoint = $MountPoint.Trim('/').Trim()
if ($MountPoint -like 'v1/*') { 
  $MountPoint = $MountPoint.Substring(3) 
}

# Handle namespace in mount point
if ($MountPoint -match '^(?<ns>[^/]+)/(?<mp>[^/].*)$') {
  $mpNs = $Matches['ns']
  $mpOnly = $Matches['mp']
  if ([string]::IsNullOrWhiteSpace($vaultNamespace) -or $vaultNamespace -eq $mpNs) {
    $vaultNamespace = if ([string]::IsNullOrWhiteSpace($vaultNamespace)) { $mpNs } else { $vaultNamespace }
    $MountPoint = $mpOnly
  }
}

# Prepare headers for authentication
$headers = @{ 'X-Vault-Token' = $vaultToken }
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  $headers['X-Vault-Namespace'] = $vaultNamespace
}

Write-TimestampedMessage "Vault Address: $vaultAddr" -Color Cyan
Write-TimestampedMessage "LDAP Mount Point: $MountPoint" -Color Cyan
if (-not [string]::IsNullOrWhiteSpace($vaultNamespace)) {
  Write-TimestampedMessage "Vault Namespace: $vaultNamespace" -Color Cyan
}
Write-TimestampedMessage "Primary Service Account: $PrimaryRoleName" -Color Cyan
Write-TimestampedMessage "Fallback Service Account: $FallbackRoleName" -Color Cyan
Write-TimestampedMessage "Max Retries: $MaxRetries" -Color Cyan
Write-TimestampedMessage "Retry Delay: $RetryDelaySeconds seconds" -Color Cyan
Write-Host ""

# Track overall statistics
$totalAttempts = 0
$startTime = Get-Date

# Attempt to retrieve credentials from primary service account with retries
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Attempting Primary Service Account" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

$primarySuccess = $false
$result = $null

for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
  $totalAttempts++
  $attemptStartTime = Get-Date
  
  Write-TimestampedMessage "Attempt $attempt of $MaxRetries for service account: $PrimaryRoleName" -Color White
  Write-TimestampedMessage "Connecting to: $MountPoint/static-cred/$PrimaryRoleName" -Color Gray
  
  $result = Get-VaultLdapCredentials -VaultAddr $vaultAddr -Headers $headers -MountPoint $MountPoint -RoleName $PrimaryRoleName
  
  if ($result.Success) {
    Write-TimestampedMessage "SUCCESS: Retrieved credentials for $PrimaryRoleName" -Color Green
    Write-TimestampedMessage "Username: $($result.Username)" -Color Green
    $primarySuccess = $true
    break
  }
  else {
    Write-TimestampedMessage "FAILED: Attempt $attempt failed" -Color Red
    Write-TimestampedMessage "Error Reason: $($result.Error)" -Color Red
    
    if ($attempt -lt $MaxRetries) {
      Write-TimestampedMessage "Waiting $RetryDelaySeconds seconds before retry..." -Color Yellow
      Start-Sleep -Seconds $RetryDelaySeconds
    }
  }
  Write-Host ""
}

# If primary failed, fall back to secondary service account
if (-not $primarySuccess) {
  Write-Host "========================================" -ForegroundColor Magenta
  Write-Host "  PRIMARY ACCOUNT FAILED - INITIATING FALLBACK" -ForegroundColor Magenta
  Write-Host "========================================" -ForegroundColor Magenta
  Write-Host ""
  
  Write-TimestampedMessage "All $MaxRetries attempts to $PrimaryRoleName failed" -Color Red
  Write-TimestampedMessage "Falling back to service account: $FallbackRoleName" -Color Magenta
  Write-Host ""
  
  # Attempt fallback service account with retries
  Write-Host "========================================" -ForegroundColor Yellow
  Write-Host "  Attempting Fallback Service Account" -ForegroundColor Yellow
  Write-Host "========================================" -ForegroundColor Yellow
  Write-Host ""
  
  $fallbackSuccess = $false
  
  for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
    $totalAttempts++
    $attemptStartTime = Get-Date
    
    Write-TimestampedMessage "Attempt $attempt of $MaxRetries for service account: $FallbackRoleName" -Color White
    Write-TimestampedMessage "Connecting to: $MountPoint/static-cred/$FallbackRoleName" -Color Gray
    
    $result = Get-VaultLdapCredentials -VaultAddr $vaultAddr -Headers $headers -MountPoint $MountPoint -RoleName $FallbackRoleName
    
    if ($result.Success) {
      Write-TimestampedMessage "SUCCESS: Retrieved credentials for $FallbackRoleName" -Color Green
      Write-TimestampedMessage "Username: $($result.Username)" -Color Green
      $fallbackSuccess = $true
      break
    }
    else {
      Write-TimestampedMessage "FAILED: Attempt $attempt failed" -Color Red
      Write-TimestampedMessage "Error Reason: $($result.Error)" -Color Red
      
      if ($attempt -lt $MaxRetries) {
        Write-TimestampedMessage "Waiting $RetryDelaySeconds seconds before retry..." -Color Yellow
        Start-Sleep -Seconds $RetryDelaySeconds
      }
    }
    Write-Host ""
  }
  
  if (-not $fallbackSuccess) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  CRITICAL FAILURE" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-TimestampedMessage "Both primary and fallback service accounts failed" -Color Red
    Write-TimestampedMessage "Total attempts made: $totalAttempts" -Color Red
    Fail "Unable to retrieve credentials from either $PrimaryRoleName or $FallbackRoleName"
  }
}

# Calculate total execution time
$endTime = Get-Date
$totalDuration = ($endTime - $startTime).TotalSeconds

# Display final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  CREDENTIALS RETRIEVED SUCCESSFULLY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

$finalServiceAccount = if ($primarySuccess) { $PrimaryRoleName } else { $FallbackRoleName }
$accountType = if ($primarySuccess) { "Primary" } else { "Fallback" }

Write-Host "Service Account Type:  $accountType" -ForegroundColor White
Write-Host "Service Account Name:  $finalServiceAccount" -ForegroundColor White
Write-Host "Username:              $($result.Username)" -ForegroundColor White
Write-Host "Password:              $('*' * $result.Password.Length) (hidden)" -ForegroundColor White
Write-Host ""
Write-Host "Execution Statistics:" -ForegroundColor Cyan
Write-Host "  Total Attempts:      $totalAttempts" -ForegroundColor White
Write-Host "  Total Duration:      $([math]::Round($totalDuration, 2)) seconds" -ForegroundColor White
Write-Host "  Start Time:          $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "  End Time:            $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host ""

if (-not $primarySuccess) {
  Write-Host "NOTE: Primary service account ($PrimaryRoleName) was unavailable." -ForegroundColor Yellow
  Write-Host "      Fallback to $FallbackRoleName was successful." -ForegroundColor Yellow
  Write-Host ""
}

Write-TimestampedMessage "Credential retrieval completed successfully" -Color Green
Write-Host ""

# Return the credentials object for potential script usage
return @{
  ServiceAccount = $finalServiceAccount
  Username = $result.Username
  Password = $result.Password
  IsFallback = -not $primarySuccess
  TotalAttempts = $totalAttempts
  Duration = $totalDuration
}

# Made with Bob
