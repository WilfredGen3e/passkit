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

.PARAMETER LocalKey
    Genereer de EC P-256 sleutel lokaal in plaats van in Key Vault, en raak
    Azure in deze run helemaal niet aan. Bedoeld om vraag 1 (formaat) los te
    kunnen stellen: een 403 op een Key Vault-rol in een subscription die niets
    met Entra te maken heeft, hoort deze test niet te kunnen blokkeren. Dezelfde
    scheiding die fase 0b maakt door naar een tekstbestand te schrijven in plaats
    van naar Key Vault (PRD §12.1).

    De sleutel is hierbij exporteerbaar en komt in leesbare vorm in het
    artefactbestand te staan. Dat is de omkering van het productieontwerp
    (PRD §4.2) en uitsluitend aanvaardbaar in een testtenant.

.PARAMETER ArtifactPath
    Waar het credential-artefact heen gaat. Dit is de overdracht naar fase 0b:
    het bevat de private key, het credential-ID, de RP ID, het user handle en na
    een geslaagde registratie het methode-ID van Entra. Standaard
    results/credential-<tijdstip>.json.

.PARAMETER Aaguid
    Onze vaste AAGUID (PRD §13). Standaard een placeholder — vervang deze door de
    definitieve zodra die vastgesteld is.

.PARAMETER Origin
    Origin die in clientDataJSON komt. Standaard afgeleid van de RP ID uit
    creationOptions; alleen overschrijven als de test uitwijst dat Entra iets
    anders verwacht.

.PARAMETER GraphApiVersion
    beta of v1.0. Standaard v1.0: die is inmiddels GA voor deze endpoints. Let
    op het verschil — v1.0 kent een vaste challenge-time-out van vijf minuten en
    accepteert challengeTimeoutInMinutes niet, beta wel. Het script stelt de URI
    daarop af.

.PARAMETER SubscriptionId
    De subscription waarin de Key Vault staat. Verplicht en wordt getoetst aan de
    actieve Az-context. Zonder deze controle pakt het script stilzwijgend welke
    context er toevallig actief is, en dat kan een klantomgeving zijn.

.PARAMETER ClientId
    App-ID van onze eigen multi-tenant app-registratie. Zonder deze parameter
    gebruikt Connect-MgGraph de Microsoft Graph Command Line Tools-app, en die
    moet per klanttenant apart ingericht worden — wat een GDAP-account niet mag.
    Onze eigen app is bedoeld om dat te omzeilen: eenmalig geconsent in de
    partnertenant, en via GDAP de klanttenants in.

.PARAMETER UseDeviceCode
    Aanmelden met een device code in plaats van een browservenster. Nodig zodra
    het script draait vanuit een sessie die geen venster naar de voorgrond kan
    halen; het WAM-dialoog verdwijnt daar achter de terminal en breekt na twee
    minuten af.

.PARAMETER SkipRegistration
    Alles opbouwen en wegschrijven, maar niet daadwerkelijk POSTen. Handig om
    eerst te zien wat er verstuurd zou worden.

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@testtenant.onmicrosoft.com -LocalKey -SkipRegistration

    Bouwt het credential op met een lokaal gegenereerde sleutel en schrijft het
    artefact weg zonder iets te registreren. Raakt Azure niet aan.

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@testtenant.onmicrosoft.com -LocalKey -ClientId <guid> -UseDeviceCode

    De eigenlijke fase 0a-test: registreert het lokaal gegenereerde credential
    bij Entra. Dit beantwoordt de formaatvraag zonder dat Key Vault een
    variabele is.

.EXAMPLE
    .\Invoke-Phase0Test.ps1 -CustomerTenantId <guid> -UserPrincipalName admin@testtenant.onmicrosoft.com -KeyVaultName kv-pkm-test -SubscriptionId <guid>

    Dezelfde test met de sleutel in Key Vault, zoals het productieontwerp het
    bedoelt. Pas zinvol als de lokale variant geslaagd is.
#>

[CmdletBinding(DefaultParameterSetName = 'KeyVault')]
param(
    [Parameter(Mandatory)][guid]$CustomerTenantId,
    [Parameter(Mandatory)][string]$UserPrincipalName,

    [Parameter(Mandatory, ParameterSetName = 'KeyVault')][string]$KeyVaultName,
    [Parameter(Mandatory, ParameterSetName = 'KeyVault')][string]$SubscriptionId,

    [Parameter(Mandatory, ParameterSetName = 'Local')][switch]$LocalKey,
    [Parameter(ParameterSetName = 'Local')][string]$ArtifactPath,

    [string]$ClientId,
    [switch]$UseDeviceCode,
    [string]$KeyName,
    [string]$DisplayName = 'PassKit fase 0-test',
    [guid]$Aaguid = '00000000-0000-0000-0000-000000000000',
    [string]$Origin,
    [ValidateSet('beta', 'v1.0')][string]$GraphApiVersion = 'v1.0',
    [string]$ResultPath,
    [switch]$SkipRegistration,
    [switch]$KeepKeyOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'PasskeyManager.Phase0.psm1') -Force

# Twee manieren om aan een sleutel te komen, met precies dezelfde opbouw van
# credential en attestation-object erna. Dat is het punt: de lokale modus is
# geen apart script en geen aparte codepad-vertakking na dit punt, dus wat hier
# bewezen wordt over het formaat geldt ook voor de Key Vault-variant.
$useKeyVault = $PSCmdlet.ParameterSetName -eq 'KeyVault'

$result = [ordered]@{
    startedAt        = (Get-Date).ToString('o')
    customerTenantId = $CustomerTenantId.ToString()
    userPrincipalName = $UserPrincipalName
    keySource        = if ($useKeyVault) { 'keyvault' } else { 'local' }
    keyVaultName     = if ($useKeyVault) { $KeyVaultName } else { $null }
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

# Sinds de v1.0-GA van deze API kent Graph een fijnmazige scope die precies dit
# doet, met UserAuthenticationMethod.ReadWrite.All als bredere variant. Beide
# volstaan, dus toets op "een van beide" en niet op de brede: een sessie met
# alleen de smalle is toereikend en mag hier niet als tekort gemeld worden.
# Voor de onboardingflow over 300 tenants (open vraag 2) is de smalle bovendien
# de makkelijkere consent-vraag.
$passkeyScopes = @(
    'UserAuthMethod-Passkey.ReadWrite.All'
    'UserAuthenticationMethod.ReadWrite.All'
)

# Zonder deze valt er niets te testen.
$requiredScopes = @(
    'User.Read.All'
)

# Wat we bij het aanmelden vragen. De brede scope staat waarschijnlijk al op de
# app-registratie; de smalle wordt meegevraagd zodat een tenant die alleen die
# consent geeft ook werkt.
$scopesToRequest = $passkeyScopes + $requiredScopes

# Levert de scopes op die de sessie mist, met de twee passkey-scopes als
# alternatieven van elkaar. Geeft een lege verzameling terug als de sessie
# bruikbaar is.
function Get-MissingScopes {
    param([string[]]$Granted)

    $lacking = @()
    if (-not ($passkeyScopes | Where-Object { $_ -in $Granted })) {
        $lacking += ($passkeyScopes -join ' of ')
    }
    foreach ($scope in $requiredScopes) {
        if ($scope -notin $Granted) { $lacking += $scope }
    }
    # Geen komma-operator hier. Die zou de lege lijst als één element teruggeven,
    # waardoor een volledig toereikende sessie als "mist scopes: System.Object[]"
    # gemeld werd — een waarschuwing die nergens op sloeg, in een script waarvan
    # de hele waarde is dat je de notities kunt vertrouwen.
    $lacking
}

# Het artefact is de overdracht van 0a naar 0b. Het resultaatbestand is een
# verslag van een run en mag van vorm veranderen; dit bestand is een contract en
# bevat precies wat er nodig is om later een assertion te tekenen, niet meer.
# Vandaar het aparte bestand en het schemaversienummer.
function Write-CredentialArtifact {
    param([Parameter(Mandatory)][hashtable]$Artifact, [Parameter(Mandatory)][string]$Path)

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    ([pscustomobject]$Artifact) | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding utf8
}

# Directory.Read.All is voor het uitlezen van de adminrollen van het doelaccount,
# waarmee het resultaatbestand kan noteren welk van de twee rolscenario's er
# getest is. Nuttig, maar geen onderdeel van de test zelf — en we benaderen de
# tenant via GDAP, waar niet gezegd is dat de rollen in de relatie directory-
# lezen toestaan. Dus wel vragen, niet op afdwingen: een bijzaak hoort de run
# niet te blokkeren.
$optionalScopes = @(
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

if (-not $useKeyVault -and -not $ArtifactPath) {
    $ArtifactPath = Join-Path $PSScriptRoot ('results/credential-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

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

    $neededModules = @('Microsoft.Graph.Authentication')
    if ($useKeyVault) { $neededModules += 'Az.KeyVault' }
    foreach ($module in $neededModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Module $module ontbreekt. Installeer met: Install-Module $module -Scope CurrentUser"
        }
    }

    if (-not $useKeyVault) {
        # De hele Azure-kant slaan we hier over. Dat is het doel van deze modus:
        # 0a stelt een vraag over Entra, en die vraag hoort niet te kunnen
        # stranden op een RBAC-rol in een subscription die er niets mee te maken
        # heeft. Precies dezelfde scheiding die 0b maakt door naar een
        # tekstbestand te schrijven in plaats van naar Key Vault (PRD §12.1).
        Write-Host '   sleutel   : lokaal gegenereerd, geen Azure in deze run'
        Write-Host '   Az-context: niet gebruikt'
        $result.steps.preflight = [ordered]@{
            keySource = 'local'
            azUsed    = $false
        }
    }
    else {

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

    try {
        $vault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
        if (-not $vault) { throw "Key Vault $KeyVaultName niet gevonden." }
        Write-Host "   Key Vault : $($vault.VaultUri)"
    }
    catch {
        throw "Key Vault '$KeyVaultName' niet bereikbaar: $($_.Exception.Message)"
    }

    # Bovenstaande is een management-call en zegt niets over het recht dat we
    # straks nodig hebben: sleutels aanmaken is een data plane-actie, en die
    # rollen erven niet uit Owner of Contributor. Een vault in RBAC-modus laat
    # een Owner dus wel de vault zien maar geen sleutel aanmaken. Zonder deze
    # tweede controle slaagt de preflight en faalt de run pas nadat de challenge
    # is opgehaald.
    try {
        Get-AzKeyVaultKey -VaultName $KeyVaultName -ErrorAction Stop | Out-Null
        Write-Host '   data plane: lezen bevestigd'
    }
    catch {
        $rbacHint = if ($vault.EnableRbacAuthorization) {
            "De vault staat in RBAC-modus. Ken 'Key Vault Crypto Officer' toe op de vault zelf; Owner op de subscription volstaat niet voor data plane-acties."
        }
        else {
            'De vault gebruikt access policies. Zorg voor Create- en Get-rechten op sleutels.'
        }
        throw "Geen data plane-toegang tot '$KeyVaultName': $($_.Exception.Message)`n$rbacHint"
    }

    $result.steps.preflight = [ordered]@{
        keySource      = 'keyvault'
        azUsed         = $true
        azAccount      = $azContext.Account.Id
        subscription   = $activeSubName
        subscriptionId = $activeSubId
        vaultUri       = $vault.VaultUri
    }

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
        $missing = @(Get-MissingScopes -Granted @($context.Scopes))
        if ($missing.Count -eq 0) {
            $reusable = $true
            Write-Host '   bestaande Graph-sessie hergebruikt'
        }
        else {
            Write-Host "   bestaande sessie mist scopes ($($missing -join ', ')); opnieuw verbinden"
        }
    }

    if (-not $reusable) {
        $connectArgs = @{
            TenantId  = $CustomerTenantId
            NoWelcome = $true
        }
        if ($ClientId) {
            $connectArgs.ClientId = $ClientId
            Write-Host "   app-registratie: $ClientId"
        }
        # Het interactieve aanmeldvenster van WAM opent achter de terminal en
        # wordt dan na twee minuten afgebroken zonder dat iemand het gezien
        # heeft. Device code heeft geen venster nodig en werkt dus ook vanuit
        # een sessie zonder eigen desktop.
        if ($UseDeviceCode) {
            $connectArgs.UseDeviceAuthentication = $true
        }

        # Deze notitie hing eerder aan de else-tak van $UseDeviceCode en sloeg dus
        # aan op de verkeerde voorwaarde: hij verscheen bij een interactieve
        # aanmelding mét -ClientId, waar hij niets betekende.
        if (-not $ClientId) {
            Add-Note 'Geen -ClientId opgegeven, dus Connect-MgGraph gebruikt de Microsoft Graph Command Line Tools-app. Die moet per klanttenant apart ingericht worden en een GDAP-account mag dat niet; verwacht hier een autorisatiefout die niets over passkeys zegt.'
        }

        try {
            Connect-MgGraph @connectArgs -Scopes ($scopesToRequest + $optionalScopes)
        }
        catch {
            # Struikelt de consent over Directory.Read.All, dan is dat geen reden
            # om de test niet te doen. Opnieuw proberen met alleen het nodige.
            Add-Note "Verbinden met alle scopes mislukte ($($_.Exception.Message)). Opnieuw geprobeerd zonder de optionele scopes; de rollen van het doelaccount blijven dan onbekend."
            Connect-MgGraph @connectArgs -Scopes $scopesToRequest
        }
        $context = Get-MgContext
    }

    # Toestemming vragen is niet hetzelfde als toestemming krijgen: bij een
    # consent-prompt kan een deel geweigerd worden, en dan komt de sessie met
    # minder scopes terug dan gevraagd.
    $granted = @($context.Scopes)
    $stillMissing = @(Get-MissingScopes -Granted $granted)
    if ($stillMissing.Count -gt 0) {
        Add-Note "De Graph-sessie mist scopes die de test nodig heeft: $($stillMissing -join ', '). Een 401/403 hierna zegt dan niets over het GDAP-pad, want de sessie zelf is al ontoereikend."
    }
    if ('Directory.Read.All' -notin $granted) {
        Add-Note 'Geen Directory.Read.All in de sessie. De adminrollen van het doelaccount zijn dan niet uit te lezen; noteer handmatig of het doelwit een adminrol heeft, want dat bepaalt wat de run bewijst.'
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

    # challengeTimeoutInMinutes bestaat alleen in beta. In v1.0 hanteert Graph een
    # vaste time-out van vijf minuten en levert de parameter meesturen een fout
    # op — een fout die niets met het credentialformaat te maken heeft en de
    # uitkomst van fase 0 dus zou vertroebelen.
    $optionsUri = if ($GraphApiVersion -eq 'beta') {
        "beta/users/$UserPrincipalName/authentication/fido2Methods/creationOptions?challengeTimeoutInMinutes=5"
    }
    else {
        "v1.0/users/$UserPrincipalName/authentication/fido2Methods/creationOptions"
    }
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

    # Het user handle hoort bij het credential, niet bij deze run: een
    # authenticator geeft het bij een assertion terug zodat de RP weet wie er
    # tekent. Fase 0b heeft het dus nodig en het is hierna niet meer op te
    # vragen — daarom hier vastleggen.
    $userHandle = Get-Prop (Get-Prop $publicKeyOptions 'user') 'id'

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
    # De sleutel. Twee bronnen, één uitkomst: X en Y van een EC P-256 sleutel.
    # Alles daarna is identiek, zodat de lokale run hetzelfde formaat aan Entra
    # aanbiedt als de Key Vault-run.
    # ------------------------------------------------------------------
    $privateKeyPkcs8 = $null

    if ($useKeyVault) {
        Write-Step 'Non-exportable EC P-256 sleutel aanmaken in Key Vault'
        # Geen -Exportable en geen release policy: de sleutel kan hierna alleen
        # nog tekenen, niet verlaten. Dat is de kern van PRD §4.2.

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
    }
    else {
        Write-Step 'EC P-256 sleutel lokaal genereren'
        # Bewust exporteerbaar, want fase 0b moet er straks mee kunnen tekenen
        # zonder Azure. Dat is de omkering van PRD §4.2 en uitsluitend
        # aanvaardbaar omdat dit een testtenant is; zie de waarschuwing bij het
        # wegschrijven van het artefact.
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create(
            [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        try {
            $ecParams = $ecdsa.ExportParameters($true)
            $x = [byte[]]$ecParams.Q.X
            $y = [byte[]]$ecParams.Q.Y
            $privateKeyPkcs8 = $ecdsa.ExportPkcs8PrivateKey()
        }
        finally {
            $ecdsa.Dispose()
        }

        $result.steps.localKey = [ordered]@{
            curve   = 'nistP256'
            source  = 'System.Security.Cryptography.ECDsa'
            xLength = $x.Length
            yLength = $y.Length
        }
        Write-Host "   P-256 sleutel gegenereerd (X $($x.Length) bytes, Y $($y.Length) bytes)"
    }

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

    # ------------------------------------------------------------------
    # Het artefact voor fase 0b
    # ------------------------------------------------------------------
    # Alleen in de lokale modus, want alleen dan is er een private key om weg te
    # schrijven. Nu al schrijven en niet pas na een geslaagde registratie: als de
    # POST faalt is dit bestand nog steeds bruikbaar om offline mee te werken, en
    # het is de enige plek waar de sleutel bestaat.
    if (-not $useKeyVault) {
        Write-Step 'Credential-artefact wegschrijven'

        $artifact = @{
            schemaVersion     = 1
            createdAt         = (Get-Date).ToString('o')
            keySource         = 'local'
            tenantId          = $CustomerTenantId.ToString()
            userPrincipalName = $UserPrincipalName
            userHandle        = $userHandle
            rpId              = $rpId
            origin            = $Origin
            credentialId      = ConvertTo-Base64Url $credentialId
            aaguid            = $Aaguid.ToString()
            algorithm         = [ordered]@{ name = 'ES256'; coseAlg = -7; curve = 'P-256' }
            publicKey         = [ordered]@{
                x          = ConvertTo-Base64Url (Expand-ToFixedLength -Bytes $x -Length 32)
                y          = ConvertTo-Base64Url (Expand-ToFixedLength -Bytes $y -Length 32)
                coseKeyHex = ($coseKey | ForEach-Object { '{0:x2}' -f $_ }) -join ''
            }
            privateKeyPkcs8   = [Convert]::ToBase64String($privateKeyPkcs8)
            signCount         = 0
            entra             = [ordered]@{ registered = $false; methodId = $null; registeredAt = $null }
            warning           = 'Bevat een private key in leesbare vorm. Uitsluitend voor de testtenant; niet in git, niet naar een productieaccount.'
        }

        Write-CredentialArtifact -Artifact $artifact -Path $ArtifactPath
        Write-Host "   $ArtifactPath"
        Write-Host '   LET OP: dit bestand bevat de private key in leesbare vorm.' -ForegroundColor Yellow
    }

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
                # clientDataJson, niet clientDataJSON. Zo staat het in het
                # Graph-contract en zo doet DSInternals.Passkeys het, waarvan
                # bekend is dat het werkt. Graph is hier vermoedelijk
                # hoofdletterongevoelig, maar "vermoedelijk" is precies wat we
                # bij een 400 niet willen hoeven uitsluiten.
                clientDataJson    = ConvertTo-Base64Url $clientData.Bytes
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

        # Een geslaagde POST bewijst het formaat, maar niet automatisch het
        # GDAP-pad: meld je aan met een account uit de klanttenant zelf, dan is
        # er geen delegatie in het spel en zegt deze run daar niets over. Eerder
        # zette dit script gdapPathWorks onvoorwaardelijk op true, waarmee een
        # latere lezer zou concluderen dat de delegatie bewezen was terwijl die
        # niet getest is.
        $signInDomain = ($context.Account -split '@')[-1]
        $targetDomain = ($UserPrincipalName -split '@')[-1]
        if ($signInDomain -eq $targetDomain) {
            $result.verdict.gdapPathWorks = $null
            Add-Note "Aangemeld als $($context.Account), een account uit de klanttenant zelf. Het formaat is hiermee bewezen, het GDAP-pad niet — daarvoor is een run met het partner-account nodig."
        }
        else {
            $result.verdict.gdapPathWorks = $true
        }

        Write-Host ''
        Write-Host 'Geregistreerd.' -ForegroundColor Green
        Write-Host "   methode-id     : $($registration.id)"
        Write-Host "   displayName    : $($registration.displayName)"
        Write-Host "   AAGUID volgens Entra: $($registration.aaGuid)"

        # Het methode-id is nodig om de registratie later weer op te ruimen, en
        # het is het bewijs dat dit credential aan Entra bekend is. Zonder deze
        # tweede schrijfactie zou het artefact een geregistreerd credential niet
        # van een niet-geregistreerd kunnen onderscheiden.
        if (-not $useKeyVault) {
            $artifact.entra = [ordered]@{
                registered   = $true
                methodId     = $registration.id
                registeredAt = (Get-Date).ToString('o')
            }
            Write-CredentialArtifact -Artifact $artifact -Path $ArtifactPath
            Write-Host "   artefact bijgewerkt: $ArtifactPath"
        }
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
        #
        # Twee complicaties, allebei in de praktijk tegengekomen:
        #   1. De body begint met de request-regel en de responseheaders; pas
        #      daarna komt de JSON. Rechtstreeks parsen faalt dus altijd, en dan
        #      bleef errorCode leeg terwijl de reden gewoon in de body stond.
        #      Zoeken op de eerste { werkt niet: de header x-ms-ags-diagnostic
        #      bevat er zelf een. Vandaar de eis dat het blok aan het begin van
        #      een regel opent.
        #   2. De echte reden zit een niveau dieper: error.message is zélf een
        #      JSON-tekst met daarin een odata.error met een subCode. Die subCode
        #      is het enige veld dat eenduidig zegt wát er misging — de rest is
        #      proza waar we niet op willen hoeven matchen.
        $errorSubCode = $null
        $errorText = $null
        if ($errorBody) {
            if ($errorBody -match '(?ms)^(\{.*\})\s*$') {
                $jsonText = $Matches[1]
                try {
                    $parsed = ($jsonText | ConvertFrom-Json)
                    $outerError = Get-Prop $parsed 'error'
                    $errorCode = Get-Prop $outerError 'code'

                    $innerRaw = Get-Prop $outerError 'message'
                    if ($innerRaw -and $innerRaw.TrimStart().StartsWith('{')) {
                        $inner = Get-Prop ($innerRaw | ConvertFrom-Json) 'odata.error'
                        $errorText = Get-Prop (Get-Prop $inner 'message') 'value'
                        $errorSubCode = @(Get-Prop $inner 'values' @()) |
                            Where-Object { (Get-Prop $_ 'item') -eq 'subCode' } |
                            ForEach-Object { Get-Prop $_ 'value' } |
                            Select-Object -First 1
                    }
                    else {
                        $errorText = $innerRaw
                    }
                }
                catch { }
            }
        }

        $result.steps.registrationError = [ordered]@{
            statusCode   = $status
            errorCode    = $errorCode
            errorSubCode = $errorSubCode
            errorText    = $errorText
            message      = $graphError
            responseBody = $errorBody
            exceptionType = $_.Exception.GetType().FullName
        }

        if ($errorSubCode) { Write-Host "   subCode        : $errorSubCode" -ForegroundColor Yellow }
        if ($errorText)    { Write-Host "   reden          : $errorText" -ForegroundColor Yellow }

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

                # Niet elke 400 gaat over het formaat. Beleidsfouten zouden ten
                # onrechte als "Entra weigert ons credential" gelezen worden — de
                # conclusie waar het hele project op hangt. Toets daarom op de
                # subCode en niet op de prozatekst: die is eenduidig en verandert
                # niet mee met een herformulering aan Microsofts kant.
                switch ($errorSubCode) {
                    'error_user_group_restriction_policy_failure' {
                        $result.verdict.formatAccepted = $null
                        Add-Note 'Beleid, geen formaat: het doelaccount valt niet in de doelgroep van het passkey-beleid. Entra is niet aan het credential toegekomen, dus deze run zegt niets over het formaat. Zet het account in de doelgroep en draai opnieuw.'
                    }
                    default {
                        # Voor de zelfbedieningsfout is de subCode nog niet
                        # waargenomen; tot die er is blijft dit op de tekst
                        # matchen. Vervang zodra we hem een keer zien.
                        if ($errorBody -match 'self-service|selfservice') {
                            $result.verdict.formatAccepted = $null
                            Add-Note "Beleid, geen formaat: 'Allow self-service setup' staat uit. Microsoft voert dat als known issue van deze API. Zet het aan en draai opnieuw."
                        }
                        else {
                            Add-Note 'Geen bekende beleidsoorzaak herkend in de response. Als dit standhoudt, is dit een echte formaatafwijzing — kijk in errorText welk veld Entra afkeurt.'
                        }
                    }
                }
            }
            default {
                $shown = if ($null -ne $status) { "HTTP $status" } else { 'Geen HTTP-status uit de fout te halen' }
                Add-Note "$shown : niet eenduidig toe te wijzen aan rechten of formaat. Beoordeel handmatig aan de hand van responseBody in het resultaatbestand."
            }
        }

        Write-Host ''
        Write-Host "Registratie mislukt: $graphError" -ForegroundColor Red

        # In de lokale modus valt er niets op te ruimen: de sleutel staat alleen
        # in het artefactbestand en dat blijft juist bruikbaar, ook na een
        # mislukte POST. Bij een 400 op het formaat is dat zelfs het interessante
        # geval — dan kan 0b er alsnog offline mee verder.
        if (-not $useKeyVault) {
            Write-Host "Artefact blijft staan: $ArtifactPath" -ForegroundColor Yellow
        }
        # De sleutel is seconden oud, hoort bij een registratie die niet bestaat
        # en zou bij herhaald testen als ruis in de vault achterblijven. Opruimen
        # is veilig: Key Vault houdt hem soft-deleted, dus terughalen kan.
        elseif ($KeepKeyOnFailure) {
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
