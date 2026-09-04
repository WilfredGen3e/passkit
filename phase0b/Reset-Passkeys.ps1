<#
.SYNOPSIS
    Verwijdert alle FIDO2-/passkey-methoden van een testaccount, zodat er met een
    schone lei één nieuw credential geregistreerd kan worden.

.DESCRIPTION
    Tijdens fase 0b bleek dat een credential onbruikbaar kan raken door de
    signature counter. Chrome's virtuele authenticator hoogt die altijd op
    (0 -> 1) en Entra weigert dat op een credential dat als "synced"
    geregistreerd staat, met AADSTS135017 ("Unexpected Signature Counter").
    Daarna wordt ook counter 0 als terugval gezien, en is dat credential dood.

    Dit script maakt schoon. Daarna registreer je er één nieuwe met
    phase0/Invoke-Phase0Test.ps1 en test je die met
    phase0b/Invoke-PasskeySignIn.ps1, dat de counter vast op 0 houdt.

    Het script toont eerst wat het aantreft en vraagt om bevestiging voordat er
    iets weggaat.

.PARAMETER CustomerTenantId
    Tenant-ID van de (test)tenant.

.PARAMETER UserPrincipalName
    Het account waarvan de passkeys verwijderd worden.

.PARAMETER ClientId
    App-registratie waarmee aangemeld wordt. Zonder deze gebruikt Connect-MgGraph
    de Microsoft Graph Command Line Tools-app, die per klanttenant apart
    ingericht moet worden.

.PARAMETER UseDeviceCode
    Meld aan met device code in plaats van een venster. Het WAM-venster opent
    achter de terminal en wordt na twee minuten afgebroken; vanuit een sessie
    zonder eigen desktop is device code de enige werkbare weg.

.PARAMETER Force
    Sla de bevestiging over.

.PARAMETER GraphApiVersion
    Standaard v1.0, zoals in fase 0a vastgesteld.

.EXAMPLE
    .\Reset-Passkeys.ps1 -CustomerTenantId 0d89711e-71b0-4e19-893a-eba5dbcf7e16 `
        -UserPrincipalName ChrisG@cwtesttentant.onmicrosoft.com `
        -ClientId e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a

.NOTES
    Dit verwijdert authenticatiemethoden. Uitsluitend tegen een testtenant
    gebruiken. Het script noemt tenant en account expliciet voordat het iets doet,
    conform de projectafspraak dat nooit tegen een omgeving gewerkt wordt zonder
    dat vaststaat welke dat is.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $CustomerTenantId,
    [Parameter(Mandatory)][string] $UserPrincipalName,
    [string] $ClientId,
    [switch] $UseDeviceCode,
    [switch] $Force,
    [string] $GraphApiVersion = 'v1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$T) Write-Host "`n== $T" -ForegroundColor Cyan }
function Write-Info { param([string]$T) Write-Host "   $T" }
function Write-Ok   { param([string]$T) Write-Host "   $T" -ForegroundColor Green }
function Write-Warn { param([string]$T) Write-Host "   $T" -ForegroundColor Yellow }

# --- Aanmelden ---------------------------------------------------------------

Write-Step 'Aanmelden bij Graph'
Write-Info "tenant : $CustomerTenantId"
Write-Info "account: $UserPrincipalName"

$scopes = @('UserAuthMethod-Passkey.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All', 'User.Read.All')

$connectArgs = @{ TenantId = $CustomerTenantId; NoWelcome = $true }
if ($ClientId)      { $connectArgs.ClientId = $ClientId; Write-Info "app    : $ClientId" }
if ($UseDeviceCode) { $connectArgs.UseDeviceAuthentication = $true }

Connect-MgGraph @connectArgs -Scopes $scopes
$context = Get-MgContext
if (-not $context) { throw 'Geen Graph-sessie tot stand gekomen.' }

Write-Ok "ingelogd als $($context.Account) tegen tenant $($context.TenantId)"
if ($context.TenantId -ne $CustomerTenantId) {
    Write-Warn "LET OP: de sessie staat tegen een andere tenant dan opgegeven."
}

# --- Ophalen -----------------------------------------------------------------

Write-Step 'Bestaande passkeys ophalen'

$uri = "$GraphApiVersion/users/$UserPrincipalName/authentication/fido2Methods"
$methods = @()
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    if ($resp.PSObject.Properties.Name -contains 'value') { $methods = @($resp.value) }
} catch {
    throw "Ophalen mislukte: $($_.Exception.Message)"
}

if ($methods.Count -eq 0) {
    Write-Ok 'Geen FIDO2-methoden op dit account. Er valt niets op te ruimen.'
    return
}

Write-Info "gevonden: $($methods.Count)"
foreach ($m in $methods) {
    Write-Host ''
    Write-Info "  id               : $($m.id)"
    Write-Info "  displayName      : $($m.displayName)"
    Write-Info "  aaGuid           : $($m.aaGuid)"
    Write-Info "  attestationLevel : $($m.attestationLevel)"
    if ($m.PSObject.Properties.Name -contains 'createdDateTime') {
        Write-Info "  createdDateTime  : $($m.createdDateTime)"
    }
}

# --- Bevestigen --------------------------------------------------------------

if (-not $Force) {
    Write-Host ''
    Write-Warn "Alle $($methods.Count) methoden hierboven worden verwijderd van"
    Write-Warn "$UserPrincipalName in tenant $CustomerTenantId."
    $answer = Read-Host '   Typ JA om door te gaan'
    if ($answer -ne 'JA') {
        Write-Info 'Afgebroken; er is niets verwijderd.'
        return
    }
}

# --- Verwijderen -------------------------------------------------------------

Write-Step 'Verwijderen'

$removed = 0
$failed  = @()
foreach ($m in $methods) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "$uri/$($m.id)" | Out-Null
        Write-Ok "verwijderd: $($m.id)"
        $removed++
    } catch {
        Write-Warn "mislukt: $($m.id) - $($_.Exception.Message)"
        $failed += $m.id
    }
}

# --- Controleren -------------------------------------------------------------

Write-Step 'Controle'
try {
    $after = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $rest = if ($after.PSObject.Properties.Name -contains 'value') { @($after.value) } else { @() }
    if ($rest.Count -eq 0) {
        Write-Ok 'Het account heeft nu geen FIDO2-methoden meer.'
    } else {
        Write-Warn "Er staan er nog $($rest.Count):"
        $rest | ForEach-Object { Write-Info "  $($_.id)" }
    }
} catch {
    Write-Warn "Nacontrole mislukte: $($_.Exception.Message)"
}

Write-Step 'Klaar'
Write-Info "verwijderd: $removed van $($methods.Count)"
if ($failed.Count) { Write-Warn "mislukt: $($failed -join ', ')" }
Write-Host ''
Write-Info 'Volgende stap: registreer er precies EEN nieuwe met'
Write-Info '  cd ..\phase0'
Write-Info "  .\Invoke-Phase0Test.ps1 -CustomerTenantId $CustomerTenantId ``"
Write-Info "      -UserPrincipalName $UserPrincipalName -LocalKey ``"
if ($ClientId) { Write-Info "      -ClientId $ClientId" }
Write-Host ''
Write-Info 'Laat daarna Chrome er niet met de virtuele authenticator bij komen:'
Write-Info 'die hoogt de counter op en maakt het credential onbruikbaar. Test met'
Write-Info '  ..\phase0b\Invoke-PasskeySignIn.ps1     (houdt de counter op 0)'
