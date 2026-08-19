<#
.SYNOPSIS
    Fase 0-test: accepteert Entra een volledig in software gegenereerde passkey,
    en lukt dat met uitsluitend GDAP-rechten?

.DESCRIPTION
    Twee vragen die los van elkaar staan (PRD §14.1) en die dit script allebei
    beantwoordt:

      1. Formaat  — slikt Entra een attestation-object met fmt "none" waarvan de
                    private key in Key Vault staat en nooit een authenticator is
                    geweest?
      2. Rechten  — kan een partner-engineer dit namens de gebruiker doen via
                    GDAP, of eist de provisioning-API dat de gebruiker het zelf
                    doet?

    Het script draait in stappen en schrijft na afloop een resultaatbestand met
    alles wat nodig is om de uitkomst te kunnen beoordelen: de ruwe
    creationOptions, de opgebouwde bytes en de Graph-response of -fout.

    Draai dit uitsluitend tegen een testtenant.

.PARAMETER CustomerTenantId
    Tenant-ID van de klanttenant waarin geregistreerd wordt. Bij de GDAP-test is
    dit de tenant waar je via GDAP toegang toe hebt; je logt in met je
    partner-account maar tegen deze tenant.

.PARAMETER UserPrincipalName
    Het account waarvoor de passkey geregistreerd wordt.

.PARAMETER KeyVaultName
    Key Vault waarin de non-exportable EC P-256 sleutel wordt aangemaakt.

.PARAMETER Aaguid
    Onze vaste AAGUID (PRD §13). Standaard een placeholder — vervang deze door de
    definitieve zodra die vastgesteld is.

.PARAMETER Origin
    Origin die in clientDataJSON komt. Standaard afgeleid van de RP ID uit
    creationOptions; alleen overschrijven als de test uitwijst dat Entra iets
    anders verwacht.

.PARAMETER GraphApiVersion
    beta of v1.0. De fido2-provisioning-endpoints zijn niet in elke versie
    aanwezig; welke werkt is onderdeel van wat fase 0 vaststelt.

.PARAMETER SkipRegistration
    Alles opbouwen en wegschrijven, maar niet daadwerkelijk POSTen. Handig om
    eerst te zien wat er verstuurd zou worden.

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@klant.onmicrosoft.com -KeyVaultName kv-passkeys-test -SkipRegistration

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@klant.onmicrosoft.com -KeyVaultName kv-passkeys-test
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$CustomerTenantId,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$KeyVaultName,

    [string]$KeyName,
    [string]$DisplayName = 'Passkey Manager fase 0-test',
    [guid]$Aaguid = '00000000-0000-0000-0000-000000000000',
    [string]$Origin,
    [ValidateSet('beta', 'v1.0')][string]$GraphApiVersion = 'beta',
    [string]$ResultPath,
    [switch]$SkipRegistration,
    [switch]$KeepKeyOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'PasskeyManager.Phase0.psm1') -Force

$result = [ordered]@{
    startedAt        = (Get-Date).ToString('o')
    customerTenantId = $CustomerTenantId.ToString()
    userPrincipalName = $UserPrincipalName
    keyVaultName     = $KeyVaultName
    graphApiVersion  = $GraphApiVersion
    steps            = [ordered]@{}
    verdict          = [ordered]@{
        formatAccepted     = $null
        gdapPathWorks      = $null
        notes              = @()
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "== $Message" -ForegroundColor Cyan
}

function Add-Note {
    param([string]$Text)
    $result.verdict.notes += $Text
    Write-Host "   ! $Text" -ForegroundColor Yellow
}

if (-not $KeyName) {
    $KeyName = 'phase0-{0}-{1}' -f ($UserPrincipalName -replace '[^a-zA-Z0-9]', '-'), (Get-Date -Format 'yyyyMMddHHmmss')
    if ($KeyName.Length -gt 127) { $KeyName = $KeyName.Substring(0, 127) }
}

if (-not $ResultPath) {
    $ResultPath = Join-Path $PSScriptRoot ('results/phase0-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$resultDir = Split-Path -Parent $ResultPath
if (-not (Test-Path $resultDir)) { New-Item -ItemType Directory -Path $resultDir | Out-Null }

if ($Aaguid -eq [guid]::Empty) {
    Add-Note 'AAGUID is de placeholder van louter nullen. Voor een formaattest prima, maar stel de definitieve AAGUID vast voordat er iets in productie geregistreerd wordt (PRD §13).'
}

try {

    # ------------------------------------------------------------------
    Write-Step 'Preflight'
    # ------------------------------------------------------------------
    # Alles controleren wat zonder neveneffecten te controleren is, voordat er
    # een challenge opgehaald wordt. De challenge verloopt en een halve run
    # laat een ongebruikte sleutel in de vault achter; beide zijn te vermijden
    # door hier te falen in plaats van halverwege.

    foreach ($module in 'Az.KeyVault', 'Microsoft.Graph.Authentication') {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Module $module ontbreekt. Installeer met: Install-Module $module -Scope CurrentUser"
        }
    }

    $azContext = Get-AzContext
    if (-not $azContext) {
        throw 'Geen Azure-context. Draai eerst Connect-AzAccount tegen de tenant waar de Key Vault staat (onze eigen tenant, niet de klanttenant).'
    }
    Write-Host "   Az        : $($azContext.Account.Id) / $($azContext.Subscription.Name)"

    # Leesbaarheid van de vault nu vaststellen, niet straks. Faalt dit op
    # rechten, dan ontbreekt Key Vault Crypto Officer.
    try {
        $vault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
        if (-not $vault) { throw "Key Vault $KeyVaultName niet gevonden." }
        Write-Host "   Key Vault : $($vault.VaultUri)"
    }
    catch {
        throw "Key Vault '$KeyVaultName' niet bereikbaar: $($_.Exception.Message)"
    }

    $result.steps.preflight = [ordered]@{
        azAccount    = $azContext.Account.Id
        subscription = $azContext.Subscription.Name
        vaultUri     = $vault.VaultUri
    }

    # ------------------------------------------------------------------
    Write-Step 'Verbinden met Graph tegen de klanttenant'
    # ------------------------------------------------------------------
    # Dit is de GDAP-vraag in de praktijk: inloggen met je partner-account, maar
    # met -TenantId van de klant. Lukt de connect maar faalt straks de POST met
    # 403, dan is dat het antwoord op vraag 2.

    Connect-MgGraph -TenantId $CustomerTenantId -Scopes 'UserAuthenticationMethod.ReadWrite.All', 'User.Read.All' -NoWelcome

    $context = Get-MgContext
    $result.steps.graphContext = [ordered]@{
        account  = $context.Account
        tenantId = $context.TenantId
        scopes   = @($context.Scopes)
        authType = $context.AuthType
    }
    Write-Host "   ingelogd als $($context.Account) tegen tenant $($context.TenantId)"

    if ($context.TenantId -ne $CustomerTenantId.ToString()) {
        Add-Note "Graph-context staat op tenant $($context.TenantId), niet op de opgegeven klanttenant. De rest van de test zegt dan niets over het GDAP-pad."
    }

    # ------------------------------------------------------------------
    Write-Step 'Doelaccount ophalen'
    # ------------------------------------------------------------------
    $user = Invoke-MgGraphRequest -Method GET -Uri "$GraphApiVersion/users/$UserPrincipalName" -OutputType PSObject
    $result.steps.user = [ordered]@{
        id                = $user.id
        userPrincipalName = $user.userPrincipalName
    }
    Write-Host "   $($user.userPrincipalName) ($($user.id))"

    # Heeft het doelaccount zelf een adminrol? Dat bepaalt welke rol je nodig
    # hebt: Authentication Administrator volstaat alleen voor niet-admins, voor
    # een admin-doelwit is Privileged Authentication Administrator vereist. In
    # productie mikken we op Global Admins, dus een test tegen een gewone
    # gebruiker bewijst minder dan hij lijkt te bewijzen (PRD §14.3).
    try {
        $roles = Invoke-MgGraphRequest -Method GET `
            -Uri "$GraphApiVersion/users/$($user.id)/transitiveMemberOf/microsoft.graph.directoryRole" `
            -OutputType PSObject
        $roleNames = @($roles.value | ForEach-Object { $_.displayName })
        $result.steps.user.directoryRoles = $roleNames

        if ($roleNames.Count -gt 0) {
            Write-Host "   adminrollen    : $($roleNames -join ', ')"
            Add-Note "Het doelaccount heeft adminrollen ($($roleNames -join ', ')). Er is dan Privileged Authentication Administrator nodig, niet Authentication Administrator. Dit is het scenario dat in productie geldt."
        }
        else {
            Write-Host '   adminrollen    : geen'
            Add-Note 'Het doelaccount heeft geen adminrollen. Slaagt de test, dan is daarmee nog niet bewezen dat het ook voor een Global Admin werkt — herhaal tegen een admin-doelwit voordat je fase 0 afvinkt.'
        }
    }
    catch {
        Add-Note "Kon de adminrollen van het doelaccount niet uitlezen: $($_.Exception.Message). Daarmee blijft onbekend welke rol er nodig is."
    }

    # ------------------------------------------------------------------
    Write-Step 'creationOptions opvragen'
    # ------------------------------------------------------------------
    # Levert challenge, RP ID en de door de tenant gevraagde parameters. De RP ID
    # nemen we hieruit over en nemen we niet aan (PRD §13).

    $optionsUri = "$GraphApiVersion/users/$UserPrincipalName/authentication/fido2Methods/creationOptions?challengeTimeoutInMinutes=5"
    $options = Invoke-MgGraphRequest -Method GET -Uri $optionsUri -OutputType PSObject
    $result.steps.creationOptions = $options

    $publicKeyOptions = $options.publicKey
    $rpId = $publicKeyOptions.rp.id
    $challenge = $publicKeyOptions.challenge

    Write-Host "   RP ID          : $rpId"
    Write-Host "   challenge      : $challenge"
    Write-Host "   attestation    : $($publicKeyOptions.attestation)"
    Write-Host "   pubKeyCredParams: $(($publicKeyOptions.pubKeyCredParams | ForEach-Object { $_.alg }) -join ', ')"

    if ($publicKeyOptions.attestation -and $publicKeyOptions.attestation -ne 'none') {
        Add-Note "De tenant vraagt attestation '$($publicKeyOptions.attestation)'. We leveren 'none'; dat is toegestaan omdat de RP niet mag afdwingen wat de authenticator teruggeeft, maar als de POST hierop faalt is dat de verklaring."
    }

    $algs = @($publicKeyOptions.pubKeyCredParams | ForEach-Object { $_.alg })
    if ($algs -notcontains -7) {
        Add-Note "ES256 (-7) staat niet in pubKeyCredParams: $($algs -join ', '). Dan klopt de aanname in PRD §13 niet."
    }

    if (-not $Origin) { $Origin = "https://$rpId" }
    Write-Host "   origin         : $Origin"

    # ------------------------------------------------------------------
    Write-Step 'Non-exportable EC P-256 sleutel aanmaken in Key Vault'
    # ------------------------------------------------------------------
    # Geen -Exportable en geen release policy: de sleutel kan hierna alleen nog
    # tekenen, niet verlaten. Dat is de kern van PRD §4.2.

    $kvKey = Add-AzKeyVaultKey `
        -VaultName $KeyVaultName `
        -Name $KeyName `
        -Destination Software `
        -KeyType EC `
        -CurveName P-256 `
        -KeyOps @('sign', 'verify')

    $result.steps.keyVaultKey = [ordered]@{
        keyId   = $kvKey.Id
        name    = $kvKey.Name
        version = $kvKey.Version
        keyType = $kvKey.Key.Kty
        curve   = $kvKey.Key.Crv
    }
    Write-Host "   $($kvKey.Id)"

    $x = [byte[]]$kvKey.Key.X
    $y = [byte[]]$kvKey.Key.Y

    # ------------------------------------------------------------------
    Write-Step 'Attestation-object opbouwen'
    # ------------------------------------------------------------------
    $credentialId = New-CredentialId -Length 32
    $coseKey = New-CoseEc2PublicKey -X $x -Y $y

    $authData = New-AuthenticatorData `
        -RpId $rpId `
        -Aaguid $Aaguid `
        -CredentialId $credentialId `
        -CosePublicKey $coseKey `
        -SignCount 0

    $attestationObject = New-AttestationObject -AuthenticatorData $authData
    $clientData = New-ClientDataJson -ChallengeBase64Url $challenge -Origin $Origin

    $result.steps.credential = [ordered]@{
        credentialId       = ConvertTo-Base64Url $credentialId
        aaguid             = $Aaguid.ToString()
        rpId               = $rpId
        origin             = $Origin
        clientDataJson     = $clientData.Json
        authDataLength     = $authData.Length
        authDataFlagsHex   = '0x{0:X2}' -f $authData[32]
        coseKeyHex         = ($coseKey | ForEach-Object { '{0:x2}' -f $_ }) -join ''
        attestationObjectB64Url = ConvertTo-Base64Url $attestationObject
    }

    Write-Host "   credentialId   : $($result.steps.credential.credentialId)"
    Write-Host "   authData       : $($authData.Length) bytes, flags $($result.steps.credential.authDataFlagsHex)"
    Write-Host "   attestationObj : $($attestationObject.Length) bytes"

    if ($SkipRegistration) {
        Write-Host ''
        Write-Host 'SkipRegistration staat aan; er wordt niets geregistreerd.' -ForegroundColor Yellow
        $result.verdict.notes += 'Niet geregistreerd (SkipRegistration).'
        return
    }

    # ------------------------------------------------------------------
    Write-Step 'Registreren bij Entra'
    # ------------------------------------------------------------------
    $body = @{
        displayName         = $DisplayName
        publicKeyCredential = @{
            id       = ConvertTo-Base64Url $credentialId
            response = @{
                clientDataJSON    = ConvertTo-Base64Url $clientData.Bytes
                attestationObject = ConvertTo-Base64Url $attestationObject
            }
        }
    }

    $result.steps.requestBody = $body

    try {
        $registration = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "$GraphApiVersion/users/$UserPrincipalName/authentication/fido2Methods" `
            -Body ($body | ConvertTo-Json -Depth 10) `
            -ContentType 'application/json' `
            -OutputType PSObject

        $result.steps.registration = $registration
        $result.verdict.formatAccepted = $true
        $result.verdict.gdapPathWorks = $true

        Write-Host ''
        Write-Host 'Geregistreerd.' -ForegroundColor Green
        Write-Host "   methode-id     : $($registration.id)"
        Write-Host "   displayName    : $($registration.displayName)"
        Write-Host "   AAGUID volgens Entra: $($registration.aaGuid)"
    }
    catch {
        $status = $null
        $graphError = $_.Exception.Message
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }

        $result.steps.registrationError = [ordered]@{
            statusCode = $status
            message    = $graphError
        }

        # De twee vragen uit elkaar trekken. Een 401/403 zegt iets over rechten,
        # een 400 over het formaat. Dat onderscheid is de hele opbrengst van deze
        # test, dus interpreteer het hier expliciet in plaats van de gebruiker
        # naar een stack trace te laten kijken.
        switch ($status) {
            { $_ -in 401, 403 } {
                $result.verdict.gdapPathWorks = $false
                Add-Note "HTTP $status : afgewezen op rechten, niet op formaat. Dit is PRD §14.1 vraag 2 en het betekent dat de registratieflow uit §7 herzien moet worden."
            }
            400 {
                $result.verdict.gdapPathWorks = $true
                $result.verdict.formatAccepted = $false
                Add-Note 'HTTP 400 : het verzoek kwam door de rechtencontrole heen maar het credential zelf werd geweigerd. Kijk in de foutmelding welk veld Entra afkeurt.'
            }
            default {
                Add-Note "HTTP $status : niet eenduidig toe te wijzen aan rechten of formaat. Zie het resultaatbestand."
            }
        }

        Write-Host ''
        Write-Host "Registratie mislukt: $graphError" -ForegroundColor Red

        # De sleutel is seconden oud, hoort bij een registratie die niet bestaat
        # en zou bij herhaald testen als ruis in de vault achterblijven. Opruimen
        # is veilig: Key Vault houdt hem soft-deleted, dus terughalen kan.
        if ($KeepKeyOnFailure) {
            Write-Host "Sleutel $KeyName blijft staan (KeepKeyOnFailure)." -ForegroundColor Yellow
        }
        else {
            try {
                Remove-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName -Force -Confirm:$false
                $result.steps.keyVaultKey.cleanedUp = $true
                Write-Host "Ongebruikte sleutel $KeyName opgeruimd (soft-deleted)."
            }
            catch {
                $result.steps.keyVaultKey.cleanedUp = $false
                Add-Note "Opruimen van sleutel $KeyName mislukt: $($_.Exception.Message). Verwijder hem handmatig."
            }
        }
    }
}
finally {
    $result.finishedAt = (Get-Date).ToString('o')
    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $ResultPath -Encoding utf8
    Write-Host ''
    Write-Host "Resultaat weggeschreven naar $ResultPath"
}
