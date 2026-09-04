<#
.SYNOPSIS
    Fase 0b-proef: eist Windows MSIX-package-identity om een plugin-authenticator
    te registreren, of niet?

.DESCRIPTION
    Dit is de goedkoopste meting die veel bouwwerk kan schelen. De aanname was:
    "MSIX is verplicht", gebaseerd op het feit dat KeePassPasskey zijn COM-klasse
    registreert via <com:Extension Category="windows.comServer"> in het
    appxmanifest en zelfs voor Debug een getekende MSIX installeert. Dat is sterk
    bewijs, maar geen bewijs — de header van Microsoft zegt er niets over.

    De proef roept WebAuthNPluginAddAuthenticator aan vanuit PowerShell. Dat is
    een onverpakt proces zonder package identity en zonder geregistreerde
    COM-klasse. De HRESULT onderscheidt drie uitkomsten die elk iets anders
    betekenen voor de bouw:

      S_OK                      registratie lukt onverpakt, en de CLSID hoeft op
                                dat moment niet eens activeerbaar te zijn. MSIX
                                is dan geen voorwaarde om te beginnen.
      APPMODEL_ERROR_NO_PACKAGE Windows eist package identity. MSIX-verpakking
      (0x80073D54)              is dan de eerste bouwstap, niet de laatste.
      REGDB_E_CLASSNOTREG       identity is niet het probleem, maar de CLSID moet
      (0x80040154)              wel activeerbaar zijn. Dan is de vraag of dat ook
                                via een klassieke LocalServer32-registratie kan.

    Er wordt niets blijvends geregistreerd: slaagt de aanroep, dan draait de
    proef hem meteen terug met WebAuthNPluginRemoveAuthenticator.

.PARAMETER Clsid
    De CLSID die geprobeerd wordt. Standaard een willekeurige, zodat de proef
    nooit een bestaande registratie raakt.

.PARAMETER KeepRegistration
    Draai een geslaagde registratie niet terug. Alleen zinvol als je daarna
    handmatig wilt kijken of de authenticator in Windows opduikt.

.NOTES
    Verandert niets aan de machine tenzij -KeepRegistration is opgegeven, en ook
    dan alleen een authenticator-registratie die met dit script weer weg te halen
    is.
#>
[CmdletBinding()]
param(
    [guid]   $Clsid = [guid]::NewGuid(),
    [switch] $KeepRegistration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$T) Write-Host "`n== $T" -ForegroundColor Cyan }
function Write-Info { param([string]$T) Write-Host "   $T" }
function Write-Ok   { param([string]$T) Write-Host "   $T" -ForegroundColor Green }
function Write-Warn { param([string]$T) Write-Host "   $T" -ForegroundColor Yellow }

# --- CTAP2 authenticatorGetInfo ---------------------------------------------
# Met de hand gecodeerd. De encoder in phase0/ mist nog een array- en een
# boolean-tak (majortype 4 en de simple values 20/21), en Tier-0-code uitbreiden
# vóór deze proef iets heeft opgeleverd is de verkeerde volgorde. Zodra de
# richting vaststaat horen die takken in de module thuis, mét tests.
#
# {1: ["FIDO_2_0","FIDO_2_1"], 3: h'<16 nulbytes>',
#  4: {"rk":true,"up":true,"uv":true}, 9: ["internal"],
#  10: [{"alg":-7,"type":"public-key"}]}
# Sleutelvolgorde volgens CTAP2 canonical.

function New-AuthenticatorGetInfoCbor {
    $bytes = [System.Collections.Generic.List[byte]]::new()
    function Add-Text([string]$s) {
        $b = [Text.Encoding]::UTF8.GetBytes($s)
        if ($b.Length -ge 24) { throw "tekst te lang voor de korte vorm: $s" }
        $bytes.Add([byte](0x60 -bor $b.Length)); $bytes.AddRange($b)
    }

    $bytes.Add(0xA5)                       # map(5)

    $bytes.Add(0x01)                       # 1: versions
    $bytes.Add(0x82)                       #    array(2)
    Add-Text 'FIDO_2_0'
    Add-Text 'FIDO_2_1'

    $bytes.Add(0x03)                       # 3: aaguid
    $bytes.Add(0x50)                       #    bytes(16)
    $bytes.AddRange([byte[]]::new(16))     #    PassKit-AAGUID is nog een placeholder (PRD §13)

    $bytes.Add(0x04)                       # 4: options
    $bytes.Add(0xA3)                       #    map(3)
    Add-Text 'rk'; $bytes.Add(0xF5)        #    true
    Add-Text 'up'; $bytes.Add(0xF5)
    Add-Text 'uv'; $bytes.Add(0xF5)

    $bytes.Add(0x09)                       # 9: transports
    $bytes.Add(0x81)                       #    array(1)
    Add-Text 'internal'

    $bytes.Add(0x0A)                       # 10: algorithms
    $bytes.Add(0x81)                       #     array(1)
    $bytes.Add(0xA2)                       #     map(2)
    Add-Text 'alg';  $bytes.Add(0x26)      #     -7 (ES256)
    Add-Text 'type'; Add-Text 'public-key'

    , $bytes.ToArray()
}

# --- P/Invoke ----------------------------------------------------------------
# WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS uit webauthnplugin.h. x64-indeling:
# 5 pointers (0..39), DWORD+padding (40), pointer (48), DWORD+padding (56),
# pointer (64) = 72 bytes. Sequential layout met standaard packing geeft dat.

$cs = @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct AddAuthenticatorOptions
{
    public IntPtr pwszAuthenticatorName;
    public IntPtr rclsid;                  // REFCLSID: pointer naar de CLSID
    public IntPtr pwszPluginRpId;
    public IntPtr pwszLightThemeLogoSvg;
    public IntPtr pwszDarkThemeLogoSvg;
    public uint   cbAuthenticatorInfo;
    public IntPtr pbAuthenticatorInfo;
    public uint   cSupportedRpIds;
    public IntPtr ppwszSupportedRpIds;
}

public static class PluginApi
{
    [DllImport("webauthn.dll")]
    public static extern int WebAuthNPluginAddAuthenticator(
        ref AddAuthenticatorOptions options, out IntPtr response);

    [DllImport("webauthn.dll")]
    public static extern void WebAuthNPluginFreeAddAuthenticatorResponse(IntPtr response);

    [DllImport("webauthn.dll")]
    public static extern int WebAuthNPluginRemoveAuthenticator(
        [MarshalAs(UnmanagedType.LPStruct)] Guid rclsid);

    [DllImport("webauthn.dll")]
    public static extern int WebAuthNPluginGetAuthenticatorState(
        [MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, out int state);
}
'@

if (-not ([Management.Automation.PSTypeName]'PluginApi').Type) {
    Add-Type -TypeDefinition $cs -ErrorAction Stop
}

function Resolve-Hresult([int]$Hr) {
    $known = @{
        0          = 'S_OK'
        -2147024891 = 'E_ACCESSDENIED (0x80070005)'
        -2147221164 = 'REGDB_E_CLASSNOTREG (0x80040154) - CLSID niet geregistreerd'
        -2147217151 = 'NTE_NOT_FOUND (0x80090011) - onbekende authenticator'
        -2147009196 = 'APPMODEL_ERROR_NO_PACKAGE (0x80073D54) - proces heeft geen package identity'
        -2147024809 = 'E_INVALIDARG (0x80070057)'
        -2147467259 = 'E_FAIL (0x80004005)'
        -2147024882 = 'E_OUTOFMEMORY (0x8007000E)'
    }
    if ($known.ContainsKey($Hr)) { return $known[$Hr] }
    try { return [ComponentModel.Win32Exception]::new($Hr).Message } catch { return '(onbekend)' }
}

# --- Uitvoeren ---------------------------------------------------------------

Write-Step 'Omgeving'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
Write-Info "proces      : PowerShell $($PSVersionTable.PSVersion) (onverpakt, geen package identity)"
Write-Info "gebruiker   : $($id.Name)"
Write-Info "OS build    : $([Environment]::OSVersion.Version)"
Write-Info "webauthn.dll: $((Get-Item "$env:windir\System32\webauthn.dll").VersionInfo.FileVersion)"

Write-Step 'authenticatorGetInfo opbouwen'
$info = New-AuthenticatorGetInfoCbor
Write-Info "CBOR: $($info.Length) bytes"
Write-Info (($info | ForEach-Object { $_.ToString('x2') }) -join '')

Write-Step 'Registratie proberen'
Write-Info "CLSID: $Clsid"

$allocated = [System.Collections.Generic.List[IntPtr]]::new()
function New-Utf16([string]$s) {
    $p = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($s)
    $allocated.Add($p); $p
}

$hr = 0
$resp = [IntPtr]::Zero
try {
    $clsidPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    $allocated.Add($clsidPtr)
    [Runtime.InteropServices.Marshal]::Copy($Clsid.ToByteArray(), 0, $clsidPtr, 16)

    $infoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($info.Length)
    $allocated.Add($infoPtr)
    [Runtime.InteropServices.Marshal]::Copy($info, 0, $infoPtr, $info.Length)

    $opts = New-Object AddAuthenticatorOptions
    $opts.pwszAuthenticatorName   = New-Utf16 'PassKit fase 0b-proef'
    $opts.rclsid                  = $clsidPtr
    $opts.pwszPluginRpId          = New-Utf16 'passkit.invalid'
    $opts.pwszLightThemeLogoSvg   = [IntPtr]::Zero
    $opts.pwszDarkThemeLogoSvg    = [IntPtr]::Zero
    $opts.cbAuthenticatorInfo     = [uint32]$info.Length
    $opts.pbAuthenticatorInfo     = $infoPtr
    $opts.cSupportedRpIds         = 0
    $opts.ppwszSupportedRpIds     = [IntPtr]::Zero

    $hr = [PluginApi]::WebAuthNPluginAddAuthenticator([ref]$opts, [ref]$resp)
}
catch {
    Write-Warn "aanroep gooide een uitzondering: $($_.Exception.Message)"
    $hr = -1
}

Write-Info ("HRESULT: 0x{0:X8}  {1}" -f $hr, (Resolve-Hresult $hr))

# --- Duiding -----------------------------------------------------------------

Write-Step 'Wat dit betekent'
switch ($hr) {
    0 {
        Write-Ok 'Registratie geslaagd vanuit een ONVERPAKT proces.'
        Write-Info 'MSIX-package-identity is dus geen voorwaarde om te registreren, en de'
        Write-Info 'CLSID hoefde op dit moment niet activeerbaar te zijn. De 0b-POC kan'
        Write-Info 'beginnen met een gewone COM-server; verpakken kan later.'
        if ($resp -ne [IntPtr]::Zero) {
            $cb = [Runtime.InteropServices.Marshal]::ReadInt32($resp, 0)
            Write-Info "platform op-signing publieke sleutel: $cb bytes"
            Write-Info '(Windows tekent hiermee elk verzoek dat het aan de plugin geeft — TPM-backed.)'
        }
    }
    -2147009196 {
        Write-Warn 'Windows eist package identity.'
        Write-Info 'MSIX-verpakking is dan de eerste bouwstap van de POC, niet de laatste.'
    }
    -2147221164 {
        Write-Warn 'Identity is niet het struikelblok, maar de CLSID moet activeerbaar zijn.'
        Write-Info 'Vervolgvraag: volstaat een klassieke LocalServer32-registratie, of moet'
        Write-Info 'het via de com:ComServer-extensie van een MSIX?'
    }
    default {
        Write-Warn 'Andere fout dan de drie verwachte uitkomsten.'
        Write-Info 'Noteer de HRESULT; hij zegt iets anders dan iets over MSIX.'
    }
}

# --- Opruimen ----------------------------------------------------------------

if ($hr -eq 0 -and -not $KeepRegistration) {
    Write-Step 'Terugdraaien'
    if ($resp -ne [IntPtr]::Zero) { [PluginApi]::WebAuthNPluginFreeAddAuthenticatorResponse($resp) }
    $rm = [PluginApi]::WebAuthNPluginRemoveAuthenticator($Clsid)
    Write-Info ("WebAuthNPluginRemoveAuthenticator: 0x{0:X8}  {1}" -f $rm, (Resolve-Hresult $rm))
    if ($rm -eq 0) { Write-Ok 'registratie verwijderd, machine terug in de oude staat' }
    else { Write-Warn "verwijderen mislukte — CLSID $Clsid staat mogelijk nog geregistreerd" }
}
elseif ($hr -eq 0) {
    Write-Warn "Registratie blijft staan (-KeepRegistration). Verwijderen kan met:"
    Write-Info "  .\Test-PluginRegistration.ps1 -Clsid $Clsid   # of handmatig via RemoveAuthenticator"
}

foreach ($p in $allocated) { [Runtime.InteropServices.Marshal]::FreeHGlobal($p) }
