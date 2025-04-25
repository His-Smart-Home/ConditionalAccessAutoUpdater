Import-Module -Name Microsoft.Graph.Authentication
Import-Module -Name Microsoft.Graph.Identity.DirectoryManagement
Import-Module -Name CredentialManager

# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Function to read from the registry
function Get-RegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )

    # Check if the registry path exists
    if (-not (Test-Path -Path $Path)) {
        Write-Error "The registry path '$Path' does not exist."
        return $null
    }

    # Get the registry value
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        return $value
    } catch {
        Write-Error "The registry key '$Name' does not exist in '$Path'."
        return $null
    }
}

# Function to write to the registry
function Write-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value
}

# Registry path
$regPath = "HKLM:\SOFTWARE\eduthing\ConditionalAccessAutoUpdate"

# Define your application details
Write-Host "Attempting to get credentials from the store" -ForegroundColor Yellow
$AppId = (Get-StoredCredential -Target "ConditionalAccessAutoUpdate_ClientID" -AsCredentialObject).Password
Write-Host "Retreived ClientId from the store" -ForegroundColor Yellow
$CertThumbprint = (Get-StoredCredential -Target "ConditionalAccessAutoUpdate_CertThumbprint" -AsCredentialObject).Password
Write-Host "Retreived CertThumbprint from the store $CertThumbprint" -ForegroundColor Yellow
$TenantId = Get-RegistryValue -Path $regPath -Name "TenantID"
Write-Host "Retreived TenantId from the registry" -ForegroundColor Yellow

Write-Host "Got all credential details" -ForegroundColor Green

#  Connect to Microsoft Graph Using the Tenant ID and Client Secret Credential
Write-Host "Attempting connection to MG" -ForegroundColor Yellow
Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $CertThumbprint -NoWelcome

# Get tenant details
$tenant = Get-MgOrganization

# Write out tenants name and store in registry
Write-Host "Successfully connected to $($tenant.DisplayName)!" -ForegroundColor Green
Write-RegistryValue -Path $regPath -Name "TenantName" -Value $tenant.DisplayName

# Get Conditional Access Named Locations
$trustedLocations = Get-MgIdentityConditionalAccessNamedLocation | ForEach-Object {
    if ($_.AdditionalProperties.isTrusted -eq $true) {
        $_
    }
}

# Select our site using name from registry
$SiteNameFR = Get-RegistryValue -Path $regPath -Name "SiteName"
$CASite = $trustedLocations | ForEach-Object {
    if ($_.AdditionalProperties['isTrusted'] -eq $true -and $_.DisplayName -match "Site-$($SiteNameFR)") {
        $_
    }
}

Write-Host "Successfully found named location $($CASite.DisplayName)" -ForegroundColor Green

# Retrieve the public IPv4 address from icanhazip.com
$PublicIPv4 = (Invoke-RestMethod -Uri "https://icanhazip.com/ipv4").Trim()
Write-Host "Our IP address is $($PublicIPv4)" -ForegroundColor Green

# Update trusted location for our site with our IP address
$ipRanges = @(
    @{
        "@odata.type" = "#microsoft.graph.iPv4CidrRange"
        cidrAddress  = "$($PublicIPv4)/32"
    }
)

$params = @{
    NamedLocationId = $CASite.Id
    BodyParameter   = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        displayName   = $CASite.DisplayName
        ipRanges      = $ipRanges
        isTrusted     = $CASite.IsTrusted  # Retain existing trust setting
    }
}

Update-MgIdentityConditionalAccessNamedLocation @params

# Finish
Write-Host "$($CASite.DisplayName) location updated to new IPv4 address of $($PublicIPv4)!" -ForegroundColor Green