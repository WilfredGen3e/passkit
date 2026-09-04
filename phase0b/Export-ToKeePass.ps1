<#
.SYNOPSIS
    Zet een fase 0-credential-artefact om in een KeePass-entry, zodat de in
    fase 0a geregistreerde passkey via KeePassPasskey daadwerkelijk gebruikt
    kan worden om aan te melden.

.DESCRIPTION
    Fase 0b vraagt: roept Windows 11 een eigen plugin-authenticator
    daadwerkelijk aan bij een passkey-aanmelding? Deze route beantwoordt die
    vraag zonder eerst zelf een provider te bouwen, door een bestaande,
    bewezen provider te gebruiken (KeePassPasskey) en daar ons eigen credential
    in te stoppen.

    Dat bewijst in één keer twee dingen die we nu allebei nog niet weten:

      1. Windows dispatcht een passkey-ceremonie naar een third-party
         plugin-authenticator (de 0b-vraag, PRD §12.1).
      2. Het in fase 0a geregistreerde credential is ook echt bruikbaar om mee
         in te loggen. Tot nu toe weten we alleen dat Entra het bij registratie
         accepteerde — niet dat er een geldige assertion mee te maken is.

    Wat dit NIET bewijst: remote signing. KeePassPasskey tekent lokaal met de
    private key uit de database. PassKit tekent in Key Vault, over het netwerk,
    binnen de ceremonie. Dat blijft de openstaande, projectspecifieke vraag.

    Het script raakt geen enkele online omgeving aan — het leest een artefact en
    schrijft een importbestand.

.PARAMETER CredentialPath
    Het credential-artefact uit fase 0a. Standaard het nieuwste bestand in
    ../phase0/results/ waarvan entra.registered waar is: alleen een credential
    dat Entra kent, kan een aanmelding opleveren.

.PARAMETER OutputPath
    Waar het KeePass-importbestand heen gaat. Standaard
    results/keepass-import-<tijdstip>.xml.

.PARAMETER Title
    Titel van de KeePass-entry. Standaard afgeleid van de UPN.

.PARAMETER NoFieldList
    Sla het leesbare veldoverzicht over. Standaard wordt dat er naast gezet, als
    terugval voor het geval de XML-import tegenvalt: de zeven velden zijn dan met
    de hand in KeePass te plakken.

.NOTES
    OPENSTAANDE AANNAMES — nog niet bewezen, net als de aannames in fase 0a:

      - Dat KeePassPasskey een credential accepteert dat het niet zelf heeft
        aangemaakt. De velden komen uit de broncode (PasskeyEntryStorage.cs),
        maar een geïmporteerd credential is een pad dat wij als eerste lopen.
      - Dat Entra bij aanmelding een assertion accepteert van een credential met
        signCount 0 dat als "synced" geregistreerd staat.
      - Dat de KeePass 2.x XML-import de custom velden overneemt zoals bedoeld.

    Het artefact bevat een private key in leesbare vorm; het importbestand dus
    ook. Uitsluitend testtenant. results/ staat in .gitignore.
#>
[CmdletBinding()]
param(
    [string] $CredentialPath,
    [string] $OutputPath,
    [string] $Title,
    [switch] $NoFieldList
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Text) Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "   $Text" -ForegroundColor Green }
function Write-Info { param([string]$Text) Write-Host "   $Text" }
function Write-Warn { param([string]$Text) Write-Host "   $Text" -ForegroundColor Yellow }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- 1. Artefact kiezen ------------------------------------------------------

Write-Step 'Credential-artefact kiezen'

if (-not $CredentialPath) {
    $resultsDir = Join-Path (Split-Path -Parent $scriptDir) 'phase0\results'
    if (-not (Test-Path $resultsDir)) {
        throw "Geen -CredentialPath opgegeven en $resultsDir bestaat niet. Draai eerst fase 0a."
    }

    $candidates = Get-ChildItem $resultsDir -Filter 'credential-*.json' |
        Sort-Object LastWriteTime -Descending |
        Where-Object {
            $c = Get-Content $_.FullName -Raw | ConvertFrom-Json
            $c.PSObject.Properties.Name -contains 'entra' -and $c.entra.registered -eq $true
        }

    if (-not $candidates) {
        throw "Geen artefact met entra.registered = true gevonden in $resultsDir. Een niet-geregistreerd credential kent Entra niet, dus daar valt niet mee aan te melden."
    }

    $CredentialPath = $candidates[0].FullName
    Write-Info "automatisch gekozen: het nieuwste geregistreerde artefact"
}

if (-not (Test-Path $CredentialPath)) { throw "Artefact niet gevonden: $CredentialPath" }
$cred = Get-Content $CredentialPath -Raw | ConvertFrom-Json
Write-Ok "$(Split-Path -Leaf $CredentialPath)"

# --- 2. Artefact controleren -------------------------------------------------

Write-Step 'Artefact controleren'

foreach ($required in 'credentialId','privateKeyPkcs8','rpId','userHandle','userPrincipalName','origin') {
    if (-not ($cred.PSObject.Properties.Name -contains $required) -or -not $cred.$required) {
        throw "Artefact mist het verplichte veld '$required'. Is dit een fase 0a-artefact (schemaVersion 1)?"
    }
}

if ($cred.entra.registered -ne $true) {
    Write-Warn 'entra.registered is niet waar — dit credential is bij Entra niet bekend.'
    Write-Warn 'Een aanmeldpoging hiermee kan per definitie niet slagen.'
}

Write-Info "account      : $($cred.userPrincipalName)"
Write-Info "RP ID        : $($cred.rpId)"
Write-Info "tenant       : $($cred.tenantId)"
Write-Info "methode-ID   : $($cred.entra.methodId)"
Write-Info "algoritme    : $($cred.algorithm.name) (COSE $($cred.algorithm.coseAlg))"
Write-Info "signCount    : $($cred.signCount)"

# --- 3. Sleutel valideren ----------------------------------------------------
# Als het publieke punt uit de private key niet gelijk is aan wat in het artefact
# staat, dan hoort daar een andere sleutel bij dan Entra kent en is elke
# aanmelding kansloos. Dat wil je hier weten, niet pas bij het inlogscherm.

Write-Step 'Sleutel valideren tegen het artefact'

$der = [Convert]::FromBase64String($cred.privateKeyPkcs8)
$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
try {
    $ecdsa.ImportPkcs8PrivateKey($der, [ref]$null)
} catch {
    throw "De private key uit het artefact is geen geldige PKCS#8 EC-sleutel: $($_.Exception.Message)"
}

$pub = $ecdsa.ExportParameters($false)
function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$xFromKey = ConvertTo-Base64Url $pub.Q.X
$yFromKey = ConvertTo-Base64Url $pub.Q.Y

if ($xFromKey -ne $cred.publicKey.x -or $yFromKey -ne $cred.publicKey.y) {
    throw "Het publieke punt uit de private key komt niet overeen met publicKey in het artefact. Het artefact is inconsistent; aanmelden zou hoe dan ook mislukken."
}
Write-Ok "curve $($pub.Curve.Oid.FriendlyName), publiek punt komt overeen met het artefact"

# Een echte ondertekening zetten en verifiëren. Dit is precies de operatie die
# KeePassPasskey straks per aanmelding doet.
$probe = [Text.Encoding]::UTF8.GetBytes('passkit-phase0b-probe')
$sig = $ecdsa.SignData($probe, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
if (-not $ecdsa.VerifyData($probe, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) {
    throw 'De sleutel kan geen verifieerbare ES256-handtekening zetten.'
}
Write-Ok 'ES256-proefondertekening gezet en geverifieerd'

# --- 4. PEM opbouwen ---------------------------------------------------------
# KeePassPasskey leest KPEX_PASSKEY_PRIVATE_KEY_PEM als PKCS#8 ("BEGIN PRIVATE
# KEY"), zie PasskeyKeyHelper.cs. Het artefact bevat de DER al in die vorm.

Write-Step 'PEM opbouwen'

$b64 = [Convert]::ToBase64String($der)
$lines = for ($i = 0; $i -lt $b64.Length; $i += 64) {
    $b64.Substring($i, [Math]::Min(64, $b64.Length - $i))
}
$pem = "-----BEGIN PRIVATE KEY-----`n" + ($lines -join "`n") + "`n-----END PRIVATE KEY-----"
Write-Ok "PKCS#8 PEM, $($der.Length) bytes DER"

# --- 5. Velden samenstellen --------------------------------------------------
# Veldnamen en semantiek uit KeePassPasskey (PasskeyEntryStorage.cs). Het is
# het KeePassXC-compatibele KPEX_PASSKEY_*-formaat.
#
# BE/BS: fase 0a heeft geregistreerd met flags 0x5D, dus met BE en BS gezet, en
# Entra classificeerde het credential als "synced" (PRD §13). Bij de assertion
# moeten die vlaggen consistent blijven, dus hier allebei aan.

Write-Step 'Velden samenstellen'

if (-not $Title) {
    $Title = "PassKit fase 0b — $($cred.userPrincipalName)"
}

$fields = [ordered]@{
    'Title'                        = $Title
    'UserName'                     = $cred.userPrincipalName
    'URL'                          = $cred.origin
    'KPEX_PASSKEY_CREDENTIAL_ID'   = $cred.credentialId
    'KPEX_PASSKEY_PRIVATE_KEY_PEM' = $pem
    'KPEX_PASSKEY_RELYING_PARTY'   = $cred.rpId
    'KPEX_PASSKEY_USER_HANDLE'     = $cred.userHandle
    'KPEX_PASSKEY_USERNAME'        = $cred.userPrincipalName
    'KPEX_PASSKEY_FLAG_BE'         = '1'
    'KPEX_PASSKEY_FLAG_BS'         = '1'
}

# Deze vier worden door KeePassPasskey beschermd opgeslagen; de rest niet.
$protectedFields = @(
    'KPEX_PASSKEY_CREDENTIAL_ID',
    'KPEX_PASSKEY_PRIVATE_KEY_PEM',
    'KPEX_PASSKEY_USER_HANDLE',
    'Password'
)

foreach ($k in $fields.Keys) {
    $v = $fields[$k]
    $shown = if ($k -eq 'KPEX_PASSKEY_PRIVATE_KEY_PEM') { '<PKCS#8 PEM, niet getoond>' }
             elseif ($v.Length -gt 50) { $v.Substring(0, 50) + '...' }
             else { $v }
    Write-Info ("{0,-30} {1}" -f $k, $shown)
}

# --- 6. KeePass 2.x XML schrijven --------------------------------------------
# Onbeschermde KeePass-XML: waarden staan als platte tekst in het bestand en
# ProtectInMemory markeert wat KeePass na import in het geheugen moet beschermen.
# Bewust géén Protected="True": dat verwacht de inner random stream van een
# echte kdbx en is voor een importbestand niet te produceren.

Write-Step 'KeePass-importbestand schrijven'

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputPath = Join-Path $scriptDir "results\keepass-import-$stamp.xml"
}
$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function New-KpUuid { [Convert]::ToBase64String([Guid]::NewGuid().ToByteArray()) }

$sb = [Text.StringBuilder]::new()
[void]$sb.AppendLine('<?xml version="1.0" encoding="utf-8" standalone="yes"?>')
[void]$sb.AppendLine('<KeePassFile>')
[void]$sb.AppendLine('  <Meta>')
[void]$sb.AppendLine('    <Generator>PassKit phase0b</Generator>')
[void]$sb.AppendLine('    <DatabaseName>PassKit fase 0b</DatabaseName>')
[void]$sb.AppendLine('    <MemoryProtection>')
[void]$sb.AppendLine('      <ProtectTitle>False</ProtectTitle>')
[void]$sb.AppendLine('      <ProtectUserName>False</ProtectUserName>')
[void]$sb.AppendLine('      <ProtectPassword>True</ProtectPassword>')
[void]$sb.AppendLine('      <ProtectURL>False</ProtectURL>')
[void]$sb.AppendLine('      <ProtectNotes>False</ProtectNotes>')
[void]$sb.AppendLine('    </MemoryProtection>')
[void]$sb.AppendLine('  </Meta>')
[void]$sb.AppendLine('  <Root>')
[void]$sb.AppendLine('    <Group>')
[void]$sb.AppendLine("      <UUID>$(New-KpUuid)</UUID>")
[void]$sb.AppendLine('      <Name>Passkeys</Name>')
[void]$sb.AppendLine('      <IsExpanded>True</IsExpanded>')
[void]$sb.AppendLine('      <Entry>')
[void]$sb.AppendLine("        <UUID>$(New-KpUuid)</UUID>")
[void]$sb.AppendLine('        <IconID>0</IconID>')

foreach ($k in $fields.Keys) {
    $protect = if ($protectedFields -contains $k) { ' ProtectInMemory="True"' } else { '' }
    $val = [Security.SecurityElement]::Escape($fields[$k])
    [void]$sb.AppendLine('        <String>')
    [void]$sb.AppendLine("          <Key>$k</Key>")
    [void]$sb.AppendLine("          <Value$protect>$val</Value>")
    [void]$sb.AppendLine('        </String>')
}

# KeePass verwacht een Password-veld; leeg is prima, de passkey is de credential.
[void]$sb.AppendLine('        <String>')
[void]$sb.AppendLine('          <Key>Password</Key>')
[void]$sb.AppendLine('          <Value ProtectInMemory="True"></Value>')
[void]$sb.AppendLine('        </String>')

[void]$sb.AppendLine('      </Entry>')
[void]$sb.AppendLine('    </Group>')
[void]$sb.AppendLine('  </Root>')
[void]$sb.AppendLine('</KeePassFile>')

# UTF-8 zonder BOM: KeePass' XML-lezer struikelt over een BOM voor de declaratie.
[IO.File]::WriteAllText($OutputPath, $sb.ToString(), [Text.UTF8Encoding]::new($false))
Write-Ok $OutputPath

# --- 7. Veldoverzicht als terugval -------------------------------------------

if (-not $NoFieldList) {
    $listPath = [IO.Path]::ChangeExtension($OutputPath, '.velden.txt')
    $lines = @(
        "PassKit fase 0b — velden voor een KeePass-entry",
        "Bron: $(Split-Path -Leaf $CredentialPath)",
        "Account: $($cred.userPrincipalName)",
        "",
        "Als de XML-import tegenvalt: maak in KeePass met de hand een entry aan en",
        "zet onderstaande velden onder Advanced -> Add. Titel, UserName en URL zijn",
        "de standaardvelden; de KPEX_-velden zijn custom string fields.",
        "",
        "LET OP: hieronder staat een private key in leesbare vorm. Testtenant.",
        ("-" * 70),
        ""
    )
    foreach ($k in $fields.Keys) {
        $lines += "[$k]"
        $lines += $fields[$k]
        $lines += ""
    }
    [IO.File]::WriteAllLines($listPath, $lines, [Text.UTF8Encoding]::new($false))
    Write-Ok $listPath
}

# --- 8. Wat nu ---------------------------------------------------------------

Write-Step 'Volgende stappen (handmatig, buiten dit script)'
@"
   1. Installeer KeePass 2.54+ en de KeePassPasskey-provider.
   2. Maak een KeePass-database aan en importeer het XML-bestand hierboven:
      File -> Import -> KeePass XML (2.x).
   3. Controleer dat de entry de KPEX_PASSKEY_*-velden heeft (tab Advanced).
   4. Zet de provider aan: Instellingen -> Accounts -> Passkeys ->
      Geavanceerde passkey-opties -> KeePassPasskey.
   5. Meld aan als $($cred.userPrincipalName) en kies bij de passkey-stap
      KeePassPasskey als provider. KeePass moet open zijn met de database erin.

   Wat je meet:
     - Komt de Windows-providerkiezer op?      -> Windows dispatcht naar de plugin
     - Komt de KeePassPasskey-prompt op?       -> de plugin wordt echt aangeroepen (0b)
     - Accepteert Entra de aanmelding?         -> het 0a-credential is bruikbaar

   Een fout bij stap 5 duidt niet automatisch op een formaatprobleem: net als in
   0a kan het ook beleid zijn (Conditional Access, authentication methods policy).
   Noteer welke van de drie hierboven wel en niet gebeurde — dat bepaalt de duiding.
"@ | Write-Host
