<#
.SYNOPSIS
    Meld aan bij Entra met het credential uit een fase 0a-artefact.

.DESCRIPTION
    De vraag: is de passkey die fase 0a bij Entra registreerde ook echt bruikbaar
    om mee in te loggen? Tot nu toe wisten we alleen dat Entra hem bij registratie
    accepteerde.

    Een WebAuthn-assertion is niet meer dan: challenge ophalen, authenticatorData
    plus SHA256(clientDataJSON) ondertekenen met de private key, terugsturen.
    Daar is geen Windows-plugin, geen MSIX en geen passkey-provider voor nodig.

    Twee manieren, allebei via Chrome's DevTools-protocol:

    SelfSign (standaard)
        navigator.credentials.get() wordt in de pagina vervangen door onze eigen
        implementatie, die authenticatorData opbouwt en met WebCrypto tekent met
        de sleutel uit het artefact. Wij bepalen dus elke byte — inclusief de
        signature counter.

        Dit is nodig: Entra weigert een opgehoogde counter op een credential dat
        als "synced" geregistreerd staat, met AADSTS135017 ("Unexpected Signature
        Counter"). Dat is conform de FIDO-richtlijn voor multi-device credentials
        — een teller is over gesynchroniseerde kopieen niet coherent bij te
        houden, dus hoort hij 0 te blijven. Het raakt ook het productieontwerp:
        de PassKit-provider moet voor deze credentials altijd 0 sturen.

    VirtualAuthenticator (-UseVirtualAuthenticator)
        Chrome's ingebouwde virtuele authenticator, met het credential erin
        geladen. Werkt technisch, maar hoogt de counter altijd op en loopt dus
        tegen AADSTS135017 aan. Bewaard omdat het die bevinding reproduceert.

    Wat dit NIET is: het productiepad. In productie tekent Key Vault en levert de
    Windows-provider de ceremonie. Dit script bewijst dat het credential deugt —
    los van de vraag hoe we er later bij komen.

.PARAMETER CredentialPath
    Het fase 0a-artefact. Standaard het nieuwste bestand in ../phase0/results/
    waarvan entra.registered waar is.

.PARAMETER Url
    Waar naartoe genavigeerd wordt. Standaard myaccount.microsoft.com, dat
    uitkomt op login.microsoftonline.com.

    Dat is de juiste origin: RP ID login.microsoft.com publiceert een
    .well-known/webauthn die login.microsoftonline.com en login.live.com als
    toegestane origins noemt (WebAuthn Related Origin Requests). Op
    login.microsoft.com zelf werkt het niet — dat adres redirect.

.PARAMETER SignCount
    De counter die in authenticatorData gezet wordt. Standaard 0; zie hierboven
    waarom dat de enige waarde is die Entra hier accepteert.

.PARAMETER WaitSeconds
    Hoe lang gewacht wordt voordat het script opgeeft. Standaard 300.

.NOTES
    Chrome start met een apart, tijdelijk profiel, zodat je gewone profiel en je
    bestaande aanmeldingen niet geraakt worden.
#>
[CmdletBinding()]
param(
    [string] $CredentialPath,
    [string] $Url = 'https://myaccount.microsoft.com',
    [int]    $Port = 9222,
    [string] $ChromePath,
    [int]    $SignCount = 0,
    [int]    $WaitSeconds = 300,
    [switch] $UseVirtualAuthenticator
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$T) Write-Host "`n== $T" -ForegroundColor Cyan }
function Write-Info { param([string]$T) Write-Host "   $T" }
function Write-Ok   { param([string]$T) Write-Host "   $T" -ForegroundColor Green }
function Write-Warn { param([string]$T) Write-Host "   $T" -ForegroundColor Yellow }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Artefact ----------------------------------------------------------------

Write-Step 'Credential-artefact'

if (-not $CredentialPath) {
    $resultsDir = Join-Path (Split-Path -Parent $scriptDir) 'phase0\results'
    $candidates = Get-ChildItem $resultsDir -Filter 'credential-*.json' -EA Stop |
        Sort-Object LastWriteTime -Descending |
        Where-Object {
            $c = Get-Content $_.FullName -Raw | ConvertFrom-Json
            $c.PSObject.Properties.Name -contains 'entra' -and $c.entra.registered -eq $true
        }
    if (-not $candidates) { throw "Geen artefact met entra.registered = true in $resultsDir." }
    $CredentialPath = $candidates[0].FullName
}

$cred = Get-Content $CredentialPath -Raw | ConvertFrom-Json
Write-Ok (Split-Path -Leaf $CredentialPath)
Write-Info "account   : $($cred.userPrincipalName)"
Write-Info "RP ID     : $($cred.rpId)"
Write-Info "methode-ID: $($cred.entra.methodId)"

function ConvertTo-StdBase64([string]$B64Url) {
    $s = $B64Url.Replace('-', '+').Replace('_', '/')
    $s + ('=' * ((4 - $s.Length % 4) % 4))
}

# Klopt de sleutel bij het credential? Zo niet, dan is elke poging kansloos.
$ec = [System.Security.Cryptography.ECDsa]::Create()
$ec.ImportPkcs8PrivateKey([Convert]::FromBase64String($cred.privateKeyPkcs8), [ref]$null)
$xCheck = [Convert]::ToBase64String($ec.ExportParameters($false).Q.X).TrimEnd('=').Replace('+','-').Replace('/','_')
if ($xCheck -ne $cred.publicKey.x) { throw 'De private key hoort niet bij publicKey in het artefact.' }
Write-Ok 'private key hoort bij het geregistreerde publieke punt'

# --- Chrome ------------------------------------------------------------------

Write-Step 'Chrome starten'

if (-not $ChromePath) {
    $ChromePath = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $ChromePath -or -not (Test-Path $ChromePath)) { throw 'chrome.exe niet gevonden. Geef -ChromePath op.' }

$profileDir = Join-Path ([IO.Path]::GetTempPath()) "passkit-cdp-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
$chrome = Start-Process -FilePath $ChromePath -PassThru -ArgumentList @(
    "--remote-debugging-port=$Port", "--user-data-dir=`"$profileDir`"",
    '--no-first-run', '--no-default-browser-check', 'about:blank')
Write-Ok "gestart (pid $($chrome.Id)), poort $Port"

# --- CDP ---------------------------------------------------------------------

Write-Step 'Verbinden met het DevTools-protocol'

$targetWs = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 250
    try {
        $t = Invoke-RestMethod "http://127.0.0.1:$Port/json/list" -TimeoutSec 2
        $p = $t | Where-Object { $_.type -eq 'page' } | Select-Object -First 1
        if ($p) { $targetWs = $p.webSocketDebuggerUrl; break }
    } catch { }
}
if (-not $targetWs) { throw "Geen DevTools-doel op poort $Port." }

$ws = [System.Net.WebSockets.ClientWebSocket]::new()
[void]$ws.ConnectAsync([Uri]$targetWs, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
Write-Ok 'verbonden'

# Console-meldingen van de shim worden hier verzameld. Een vlag op het window
# overleeft geen paginawisseling — en Entra klikt na de assertion meteen door —
# dus dat is als meting onbruikbaar gebleken. Console-events komen over de
# CDP-verbinding binnen en blijven staan, ook als het document allang weg is.
$script:passkitEvents = [System.Collections.Generic.List[string]]::new()

$script:cdpId = 0
function Invoke-Cdp {
    param([string]$Method, [hashtable]$Params = @{})
    $script:cdpId++
    $msg = @{ id = $script:cdpId; method = $Method; params = $Params } | ConvertTo-Json -Depth 12 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($msg)
    # [void]: GetResult() op een void-Task levert anders een VoidTaskResult op die
    # in de pipeline belandt, waardoor de functie een array teruggeeft.
    [void]$ws.SendAsync([ArraySegment[byte]]::new($bytes),
        [System.Net.WebSockets.WebSocketMessageType]::Text, $true,
        [Threading.CancellationToken]::None).GetAwaiter().GetResult()

    $buffer = [byte[]]::new(131072)
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        $sb = [Text.StringBuilder]::new()
        do {
            $res = $ws.ReceiveAsync([ArraySegment[byte]]::new($buffer), [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            [void]$sb.Append([Text.Encoding]::UTF8.GetString($buffer, 0, $res.Count))
        } while (-not $res.EndOfMessage)
        $obj = $sb.ToString() | ConvertFrom-Json

        # Events die langskomen terwijl we op een antwoord wachten niet weggooien:
        # de meldingen van de shim zitten hierin.
        if ($obj.PSObject.Properties.Name -contains 'method' -and
            $obj.method -eq 'Runtime.consoleAPICalled') {
            try {
                $text = ($obj.params.args | ForEach-Object {
                    if ($_.PSObject.Properties.Name -contains 'value') { [string]$_.value } else { $_.description }
                }) -join ' '
                if ($text -like '*[passkit]*') { $script:passkitEvents.Add($text.Trim()) }
            } catch { }
        }

        if ($obj.PSObject.Properties.Name -contains 'id' -and $obj.id -eq $script:cdpId) {
            if ($obj.PSObject.Properties.Name -contains 'error') { throw "CDP $Method faalde: $($obj.error.message)" }
            return $obj.result
        }
    }
    throw "Geen antwoord op $Method binnen 20 seconden."
}

# --- Assertion-bron ----------------------------------------------------------

if ($UseVirtualAuthenticator) {
    Write-Step 'Virtuele authenticator (reproduceert de counter-bevinding)'
    [void](Invoke-Cdp 'WebAuthn.enable' @{ enableUI = $false })
    $auth = Invoke-Cdp 'WebAuthn.addVirtualAuthenticator' @{ options = @{
        protocol = 'ctap2'; ctap2Version = 'ctap2_1'; transport = 'internal'
        hasResidentKey = $true; hasUserVerification = $true
        automaticPresenceSimulation = $true; isUserVerified = $true
        defaultBackupEligibility = $true; defaultBackupState = $true } }
    $authId = $auth.authenticatorId
    [void](Invoke-Cdp 'WebAuthn.addCredential' @{
        authenticatorId = $authId
        credential = @{
            credentialId = (ConvertTo-StdBase64 $cred.credentialId)
            isResidentCredential = $true
            rpId = $cred.rpId
            privateKey = $cred.privateKeyPkcs8
            userHandle = (ConvertTo-StdBase64 $cred.userHandle)
            signCount = [int]$cred.signCount } })
    Write-Ok 'credential geladen'
    Write-Warn 'Chrome hoogt de counter altijd op; verwacht AADSTS135017.'
}
else {
    Write-Step 'Eigen assertion-implementatie injecteren'

    # navigator.credentials.get wordt vervangen. De shim bouwt authenticatorData
    # met flags 0x1D (UP|UV|BE|BS, conform PRD §13 en de vlaggen waarmee 0a
    # registreerde) en een vaste signature counter, en tekent met WebCrypto.
    $js = @'
(() => {
  if (window.__passkitShim) return;
  window.__passkitShim = true;
  window.__passkitLog = [];
  const log = (...a) => { window.__passkitLog.push(a.join(' ')); console.log('[passkit]', ...a); };

  const CRED_ID   = '__CREDID__';
  const RP_ID     = '__RPID__';
  const USER_H    = '__USERHANDLE__';
  const PKCS8     = '__PKCS8__';
  const SIGNCOUNT = __SIGNCOUNT__;

  const b64uToBytes = s => {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const b64ToBytes = s => {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const bytesToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // WebCrypto levert ECDSA als r||s (64 bytes); WebAuthn verwacht een DER-SEQUENCE.
  const rawSigToDer = raw => {
    const trim = v => {
      let i = 0;
      while (i < v.length - 1 && v[i] === 0) i++;
      v = v.slice(i);
      return (v[0] & 0x80) ? Uint8Array.from([0, ...v]) : v;
    };
    const r = trim(raw.slice(0, 32));
    const s = trim(raw.slice(32, 64));
    const body = [0x02, r.length, ...r, 0x02, s.length, ...s];
    return Uint8Array.from([0x30, body.length, ...body]);
  };

  const original = navigator.credentials.get.bind(navigator.credentials);

  navigator.credentials.get = async function (options) {
    // Elke aanroep loggen, ook de doorgelaten: zonder dit is niet te zien of
    // Entra uberhaupt om een passkey vraagt.
    log('GET AANGEROEPEN, mediation=' + (options.mediation || 'default') +
        ', rpId=' + ((options.publicKey && options.publicKey.rpId) || location.hostname));

    if (!options || !options.publicKey) return original(options);
    const pk = options.publicKey;

    const rpId = pk.rpId || location.hostname;
    if (rpId !== RP_ID) {
      log('andere rpId dan het artefact (' + RP_ID + '), doorgegeven aan de browser');
      return original(options);
    }

    const enc = new TextEncoder();
    const clientData = {
      type: 'webauthn.get',
      challenge: bytesToB64u(new Uint8Array(pk.challenge)),
      origin: location.origin,
      crossOrigin: false
    };
    const clientDataJSON = enc.encode(JSON.stringify(clientData));

    const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(rpId)));
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x1D;                     // UP | UV | BE | BS
    new DataView(authData.buffer).setUint32(33, SIGNCOUNT, false);

    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
    const signedData = new Uint8Array(authData.length + clientDataHash.length);
    signedData.set(authData, 0);
    signedData.set(clientDataHash, authData.length);

    const key = await crypto.subtle.importKey(
      'pkcs8', b64ToBytes(PKCS8), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const rawSig = new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, key, signedData));
    const derSig = rawSigToDer(rawSig);

    log('ASSERTION GEZET, signCount=' + SIGNCOUNT + ', sig ' + derSig.length + ' bytes');
    window.__passkitSigned = true;

    const rawId = b64uToBytes(CRED_ID);
    const result = {
      id: CRED_ID,
      rawId: rawId.buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: clientDataJSON.buffer,
        authenticatorData: authData.buffer,
        signature: derSig.buffer,
        userHandle: b64uToBytes(USER_H).buffer
      },
      getClientExtensionResults: () => ({})
    };
    // Entra's JS leest deze velden; een echt PublicKeyCredential-prototype is
    // niet te maken zonder de constructor, dus dit is een gewoon object.
    Object.setPrototypeOf(result, Object.prototype);
    return result;
  };

  log('shim geinstalleerd');
})();
'@
    $js = $js.Replace('__CREDID__',     $cred.credentialId).
              Replace('__RPID__',       $cred.rpId).
              Replace('__USERHANDLE__', $cred.userHandle).
              Replace('__PKCS8__',      $cred.privateKeyPkcs8).
              Replace('__SIGNCOUNT__',  "$SignCount")

    [void](Invoke-Cdp 'Page.enable')
    # Runtime.enable laat de console-meldingen van de shim als CDP-events
    # binnenkomen; die overleven paginawisselingen, een window-vlag niet.
    [void](Invoke-Cdp 'Runtime.enable')
    [void](Invoke-Cdp 'Page.addScriptToEvaluateOnNewDocument' @{ source = $js })
    Write-Ok "shim geinstalleerd, signCount vast op $SignCount, flags 0x1D"
}

# --- Navigeren ---------------------------------------------------------------

Write-Step 'Navigeren'
[void](Invoke-Cdp 'Page.enable')
[void](Invoke-Cdp 'Page.navigate' @{ url = $Url })
Write-Ok $Url

Write-Host @"

   Meld nu in het Chrome-venster aan als:
       $($cred.userPrincipalName)

   Kies bij de tweede stap de passkey-optie. Er komt geen Windows Hello-prompt:
   de assertion wordt in de pagina zelf gezet met de sleutel uit het artefact.

"@ -ForegroundColor White

# --- Wachten -----------------------------------------------------------------

Write-Step 'Wachten'

$deadline       = (Get-Date).AddSeconds($WaitSeconds)
$signed         = $false
$announced      = $false
$succeeded      = $false
$lastUrl        = ''
$reportedEvents = 0

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3

    if ($UseVirtualAuthenticator) {
        try {
            $creds = Invoke-Cdp 'WebAuthn.getCredentials' @{ authenticatorId = $authId }
            foreach ($c in $creds.credentials) {
                if ($c.signCount -gt [int]$cred.signCount) { $signed = $true }
            }
        } catch { }
    }
    else {
        # Deze aanroep pompt tegelijk de socket leeg, waardoor de console-events
        # van de shim binnenkomen en in $script:passkitEvents belanden.
        try { [void](Invoke-Cdp 'Runtime.evaluate' @{ expression = '1'; returnByValue = $true }) } catch { }

        foreach ($e in $script:passkitEvents) {
            if ($e -match 'ASSERTION GEZET') { $signed = $true }
        }
        while ($script:passkitEvents.Count -gt $reportedEvents) {
            Write-Info "  shim: $($script:passkitEvents[$reportedEvents])"
            $reportedEvents++
        }
    }

    try {
        $u = Invoke-Cdp 'Runtime.evaluate' @{ expression = 'location.href'; returnByValue = $true }
        $cur = $u.result.value
        if ($cur -and $cur -ne $lastUrl) {
            $lastUrl = $cur
            Write-Info "pagina: $($cur.Split('#')[0].Split('?')[0])"
            if ($cur -match 'error=|AADSTS') {
                Write-Warn 'foutmelding in de URL:'
                $dec = [Uri]::UnescapeDataString($cur)
                if ($dec -match 'AADSTS\d+[^&]*') { Write-Warn "  $($Matches[0])" }
            }
        }
    } catch { }

    # Bewust NIET afbreken zodra er getekend is. De CDP-sessie houdt de
    # geinjecteerde shim in leven; sluit je hem, dan is de shim weg en strandt de
    # aanmelding halverwege de redirects. Doorlopen tot de flow ergens uitkomt.
    if ($signed -and -not $announced) {
        Write-Ok 'Er is een assertion gezet met het credential uit het artefact.'
        $announced = $true
    }

    # Aangemeld: we zijn van de aanmeldhost af en er staat geen fout in de URL.
    # Bewust niet vergelijken met $Url: de startpagina kan een authorize-endpoint
    # zijn, en dan zegt "terug op $Url" niets.
    if ($signed -and $lastUrl -notmatch 'error=' -and
        $lastUrl -notmatch '^https://login\.(microsoftonline|live|microsoft)\.com/') {
        $succeeded = $true
        break
    }
}

Write-Step 'Uitkomst'
if ($succeeded) {
    Write-Ok 'AANGEMELD. Entra accepteerde de assertion van het 0a-credential.'
    Write-Info "eind-URL: $($lastUrl.Split('?')[0])"
} elseif ($signed) {
    Write-Warn 'Er is getekend, maar de flow kwam niet uit op de doelapplicatie.'
    Write-Info "laatste URL: $($lastUrl.Split('?')[0])"
    $dec = [Uri]::UnescapeDataString($lastUrl)
    if ($dec -match 'AADSTS\d+[^&]*') { Write-Warn "Entra wees af: $($Matches[0])" }
} else {
    Write-Warn "Binnen $WaitSeconds seconden geen assertion gezien."
    Write-Info 'Werd de passkey-optie wel aangeboden? Zo niet, dan kwam het niet tot een'
    Write-Info 'ceremonie en zegt dit niets over het credential zelf.'
}

Write-Info 'Chrome blijft open; sluit het venster zelf.'
try { $ws.Dispose() } catch { }
Write-Info "tijdelijk profiel: $profileDir"
