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

.PARAMETER SubscriptionId
    De subscription waarin de Key Vault staat. Verplicht en wordt getoetst aan de
    actieve Az-context. Zonder deze controle pakt het script stilzwijgend welke
    context er toevallig actief is, en dat kan een klantomgeving zijn.

.PARAMETER SkipRegistration
    Alles opbouwen en wegschrijven, maar niet daadwerkelijk POSTen. Handig om
    eerst te zien wat er verstuurd zou worden.

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@testtenant.onmicrosoft.com -KeyVaultName kv-pkm-test -SubscriptionId <guid> -SkipRegistration

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@testtenant.onmicrosoft.com -KeyVaultName kv-pkm-test -SubscriptionId <guid>
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$CustomerTenantId,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][string]$SubscriptionId,

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

# Set-StrictMode laat een ontbrekende property een terminating error worden. Voor
# een response waarvan we de vorm juist nog niet kennen — dat is wat fase 0
# uitzoekt — is dat het verkeerde gedrag: dan klapt het script op een optioneel
# veld nadat de challenge al opgehaald is.
function Get-Prop {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    $prop.Value
}

# Scopes die de test nodig heeft. UserAuthenticationMethod.ReadWrite.All voor de
# registratie zelf, Directory.Read.All om de adminrollen van het doelaccount uit
# te lezen — zonder die laatste blijft onbekend welk van de twee rolscenario's
# we getest hebben, en dat is de eigenlijke opbrengst van de tweede run.
$requiredScopes = @(
    'UserAuthenticationMethod.ReadWrite.All'
    'User.Read.All'
    'Directory.Read.All'
)

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

    # Harde toets in plaats van pakken wat er toevallig actief is. Een sessie die
    # nog op een klantomgeving staat is een reeel scenario en het gevolg zou zijn
    # dat we daar een sleutel aanmaken.
    $activeSubId = Get-Prop (Get-Prop $azContext 'Subscription') 'Id'
    $activeSubName = Get-Prop (Get-Prop $azContext 'Subscription') 'Name' '<geen>'
    if ($activeSubId -ne $SubscriptionId) {
        throw @"
Actieve Az-context staat op een andere subscription dan opgegeven.
  actief    : $activeSubName ($activeSubId)
  verwacht  : $SubscriptionId
Wissel met: Set-AzContext -SubscriptionId $SubscriptionId
"@
    }
    Write-Host "   Az        : $($azContext.Account.Id)"
    Write-Host "   sub       : $activeSubName ($activeSubId)"

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
        subscription = $activeSubName
        subscriptionId = $activeSubId
        vaultUri     = $vault.VaultUri
    }

    # ------------------------------------------------------------------
    Write-Step 'Verbinden met Graph tegen de klanttenant'
    # ------------------------------------------------------------------
    # Dit is de GDAP-vraag in de praktijk: inloggen met je partner-account, maar
    # met -TenantId van de klant. Lukt de connect maar faalt straks de POST met
    # 403, dan is dat het antwoord op vraag 2.

    # Een bestaande sessie op dezelfde tenant hergebruiken scheelt een
    # browserprompt per run, en bij herhaald testen zijn dat er veel. Maar alleen
    # als die sessie ook alle scopes heeft: een sessie met te weinig scopes geeft
    # straks een 403 op de registratie, en dit script zou die 403 uitleggen als
    # "het GDAP-pad werkt niet" terwijl het aan de sessie ligt. Dat is precies de
    # verwarring die fase 0 moet uitsluiten, dus hier hard op toetsen.
    $context = Get-MgContext
    $reusable = $false
    if ($context -and $context.TenantId -eq $CustomerTenantId.ToString()) {
        $missing = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
        if ($missing.Count -eq 0) {
            $reusable = $true
            Write-Host '   bestaande Graph-sessie hergebruikt'
        }
        else {
            Write-Host "   bestaande sessie mist scopes ($($missing -join ', ')); opnieuw verbinden"
        }
    }

    if (-not $reusable) {
        Connect-MgGraph -TenantId $CustomerTenantId -Scopes $requiredScopes -NoWelcome
        $context = Get-MgContext
    }

    # Toestemming geven is niet hetzelfde als toestemming krijgen: bij een
    # consent-prompt kan de gebruiker een deel weigeren, en dan komt de sessie
    # met minder scopes terug dan gevraagd.
    $granted = @($context.Scopes)
    $stillMissing = @($requiredScopes | Where-Object { $_ -notin $granted })
    if ($stillMissing.Count -gt 0) {
        Add-Note "De Graph-sessie mist scopes: $($stillMissing -join ', '). Een 401/403 hierna zegt dan niets over het GDAP-pad, want de sessie zelf is al ontoereikend."
    }
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
        $roleNames = @(Get-Prop $roles 'value' @() | ForEach-Object { Get-Prop $_ 'displayName' })
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

    # De vorm van deze response is een van de dingen die fase 0 vaststelt, dus
    # hier niet aannemen dat velden bestaan.
    $publicKeyOptions = Get-Prop $options 'publicKey'
    if (-not $publicKeyOptions) {
        throw "creationOptions bevat geen 'publicKey'. Ontvangen velden: $(($options.PSObject.Properties.Name) -join ', '). Zie het resultaatbestand."
    }

    $rpId = Get-Prop (Get-Prop $publicKeyOptions 'rp') 'id'
    $challenge = Get-Prop $publicKeyOptions 'challenge'
    $attestation = Get-Prop $publicKeyOptions 'attestation'
    $credParams = @(Get-Prop $publicKeyOptions 'pubKeyCredParams' @())

    if (-not $rpId) { throw "creationOptions bevat geen rp.id; zonder RP ID is er geen geldige authenticatorData op te bouwen." }
    if (-not $challenge) { throw "creationOptions bevat geen challenge." }

    $algs = @($credParams | ForEach-Object { Get-Prop $_ 'alg' })

    Write-Host "   RP ID          : $rpId"
    Write-Host "   challenge      : $challenge"
    Write-Host "   attestation    : $attestation"
    Write-Host "   pubKeyCredParams: $($algs -join ', ')"

    if ($attestation -and $attestation -ne 'none') {
        Add-Note "De tenant vraagt attestation '$attestation'. We leveren 'none'; dat is toegestaan omdat de RP niet mag afdwingen wat de authenticator teruggeeft, maar als de POST hierop faalt is dat de verklaring."
    }

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
        $errorBody = $null
        $errorCode = $null

        $response = Get-Prop $_.Exception 'Response'
        if ($response) {
            $statusValue = Get-Prop $response 'StatusCode'
            if ($null -ne $statusValue) { $status = [int]$statusValue }
        }

        # Bij een 400 staat de reden in de body, niet in de message. Dat is de
        # onderbouwing van de fase 0-conclusie: welk veld keurt Entra af? Zonder
        # deze bytes is een 400 niet meer dan "iets klopte niet".
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorBody = $_.ErrorDetails.Message
        }
        elseif ($response) {
            try {
                $content = Get-Prop $response 'Content'
                if ($content) { $errorBody = $content.ReadAsStringAsync().GetAwaiter().GetResult() }
            }
            catch { $errorBody = "<body niet te lezen: $($_.Exception.Message)>" }
        }

        # Graph zet de machineleesbare reden in error.code; die is bruikbaarder
        # dan de prozatekst als we straks moeten uitzoeken wat er precies afkeurt.
        if ($errorBody) {
            try {
                $parsed = $errorBody | ConvertFrom-Json
                $errorCode = Get-Prop (Get-Prop $parsed 'error') 'code'
            }
            catch { }
        }

        $result.steps.registrationError = [ordered]@{
            statusCode   = $status
            errorCode    = $errorCode
            message      = $graphError
            responseBody = $errorBody
            exceptionType = $_.Exception.GetType().FullName
        }

        if ($errorBody) {
            Write-Host ''
            Write-Host 'Response body van Graph:' -ForegroundColor Yellow
            Write-Host $errorBody
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
                $shown = if ($null -ne $status) { "HTTP $status" } else { 'Geen HTTP-status uit de fout te halen' }
                Add-Note "$shown : niet eenduidig toe te wijzen aan rechten of formaat. Beoordeel handmatig aan de hand van responseBody in het resultaatbestand."
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
