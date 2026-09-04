<#
.SYNOPSIS
    Draait Invoke-PasskeySignIn.ps1 met Chrome's Windows-SSO tijdelijk uit, en
    zet die daarna gegarandeerd terug.

.DESCRIPTION
    Op een Entra-joined machine levert Chrome de Primary Refresh Token van de
    ingelogde Windows-gebruiker rechtstreeks aan Entra. Heeft die gebruiker via
    GDAP toegang tot de doeltenant, dan meldt Entra hem gewoon aan — ook met
    prompt=login en een login_hint voor iemand anders. Er komt dan nooit een
    koude aanmeldpagina, en het testaccount komt niet aan bod.

    De Chrome-beleidsinstelling CloudAPAuthEnabled zet dat gedrag uit. Onder
    HKCU is daar geen verhoging voor nodig. Het raakt wel de gewone Chrome van
    deze gebruiker zolang het aanstaat, dus het wordt in een finally-blok
    teruggezet — ook als de test wordt afgebroken.

.PARAMETER UserPrincipalName
    Het testaccount waarvoor aangemeld wordt; wordt als login_hint meegegeven.

.PARAMETER CustomerTenantId
    Tenant van het testaccount.

.PARAMETER Port
    Poort voor Chrome's remote debugging.

.PARAMETER WaitSeconds
    Hoe lang de test op een assertion wacht.

.PARAMETER LogPath
    Waar de uitvoer van de onderliggende test heen gaat.

.NOTES
    Chrome moet volledig afgesloten zijn voordat de beleidswijziging aanslaat;
    het script controleert dat en waarschuwt als er nog vensters open staan.
#>
[CmdletBinding()]
param(
    [string] $UserPrincipalName = 'ChrisG@cwtesttentant.onmicrosoft.com',
    [string] $CustomerTenantId  = '0d89711e-71b0-4e19-893a-eba5dbcf7e16',
    [int]    $Port              = 9270,
    [int]    $WaitSeconds       = 600,
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$T) Write-Host "`n== $T" -ForegroundColor Cyan }
function Write-Info { param([string]$T) Write-Host "   $T" }
function Write-Ok   { param([string]$T) Write-Host "   $T" -ForegroundColor Green }
function Write-Warn { param([string]$T) Write-Host "   $T" -ForegroundColor Yellow }

$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $LogPath) { $LogPath = Join-Path $scriptDir "results\coldsignin-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" }
$policyKey  = 'HKCU:\Software\Policies\Google\Chrome'
$policyName = 'CloudAPAuthEnabled'

# --- Bestaande waarde onthouden ---------------------------------------------

Write-Step 'Windows-SSO in Chrome tijdelijk uitzetten'

$hadKey = Test-Path $policyKey
$oldValue = $null
if ($hadKey) {
    $prop = Get-ItemProperty -Path $policyKey -Name $policyName -ErrorAction SilentlyContinue
    if ($prop -and $prop.PSObject.Properties.Name -contains $policyName) { $oldValue = $prop.$policyName }
}
Write-Info "sleutel bestond : $hadKey"
Write-Info "oude waarde     : $(if ($null -eq $oldValue) { '(niet gezet)' } else { $oldValue })"

try {
    if (-not $hadKey) { New-Item -Path $policyKey -Force | Out-Null }
    New-ItemProperty -Path $policyKey -Name $policyName -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Ok "$policyName = 0 (Windows-SSO uit)"

    # Chrome leest beleid bij het starten van het browserproces. Draaien er nog
    # vensters van het gewone profiel, dan deelt de nieuwe instantie mogelijk
    # datzelfde proces en slaat de wijziging niet aan.
    $running = @(Get-Process chrome -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        Write-Warn "Er draaien nog $($running.Count) chrome-processen."
        Write-Warn 'Sluit Chrome helemaal af als de aanmelding straks alsnog automatisch gaat.'
    }

    # --- Test draaien --------------------------------------------------------

    Write-Step 'Aanmeldtest starten'

    # prompt=login dwingt herauthenticatie af; login_hint vult het testaccount in.
    # Zonder de PRT valt Entra terug op een echte aanmeldpagina, en daar is de
    # passkey te kiezen zonder dat het wachtwoord van het testaccount nodig is.
    $url = "https://login.microsoftonline.com/$CustomerTenantId/oauth2/v2.0/authorize" +
           '?client_id=4765445b-32c6-49b0-83e6-1d93765276ca' +
           '&response_type=code' +
           '&redirect_uri=' + [Uri]::EscapeDataString('https://www.office.com/landingv2') +
           '&response_mode=query' +
           '&scope=' + [Uri]::EscapeDataString('openid profile') +
           '&prompt=login' +
           '&login_hint=' + [Uri]::EscapeDataString($UserPrincipalName)

    Write-Info "account: $UserPrincipalName"
    Write-Info "log    : $LogPath"

    $inner = Join-Path $scriptDir 'Invoke-PasskeySignIn.ps1'
    & $inner -Port $Port -WaitSeconds $WaitSeconds -Url $url *>&1 | Tee-Object -FilePath $LogPath
}
finally {
    Write-Step 'Windows-SSO terugzetten'
    try {
        if ($null -ne $oldValue) {
            New-ItemProperty -Path $policyKey -Name $policyName -Value $oldValue -PropertyType DWord -Force | Out-Null
            Write-Ok "$policyName teruggezet op $oldValue"
        }
        else {
            Remove-ItemProperty -Path $policyKey -Name $policyName -ErrorAction SilentlyContinue
            if (-not $hadKey) {
                # Alleen opruimen als de sleutel verder leeg is; anders stond er al
                # ander Chrome-beleid dat we niet hebben gezet.
                $remaining = (Get-Item $policyKey -ErrorAction SilentlyContinue)
                if ($remaining -and $remaining.ValueCount -eq 0 -and $remaining.SubKeyCount -eq 0) {
                    Remove-Item $policyKey -Force -ErrorAction SilentlyContinue
                    Write-Ok 'beleidssleutel verwijderd (stond er niet voor de test)'
                } else {
                    Write-Ok 'waarde verwijderd; sleutel bevatte ander beleid en blijft staan'
                }
            } else {
                Write-Ok 'waarde verwijderd, sleutel blijft staan'
            }
        }
    }
    catch {
        Write-Warn "TERUGZETTEN MISLUKT: $($_.Exception.Message)"
        Write-Warn "Zet handmatig terug: $policyKey\$policyName"
    }
}
