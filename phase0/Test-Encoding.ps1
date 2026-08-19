<#
.SYNOPSIS
    Offline controle van de CBOR/COSE-encoder. Geen Azure of Graph nodig.

.DESCRIPTION
    De encoder in PasskeyManager.Phase0.psm1 is met de hand geschreven en een
    fout daarin komt bij de echte test terug als een nietszeggende HTTP 400. Deze
    test vergelijkt de opgebouwde bytes met wat de specificatie voorschrijft,
    zodat een 400 tijdens fase 0 betekenisvol is: dan ligt het niet aan ons.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'PasskeyManager.Phase0.psm1') -Force

$script:failures = 0

function Assert-Equal {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()]$Expected,
        [Parameter(Mandatory)][AllowEmptyString()]$Actual
    )

    if ("$Expected" -eq "$Actual") {
        Write-Host "  ok    $Name" -ForegroundColor Green
    }
    else {
        Write-Host "  FOUT  $Name" -ForegroundColor Red
        Write-Host "        verwacht : $Expected"
        Write-Host "        gekregen : $Actual"
        $script:failures++
    }
}

function ConvertTo-Hex {
    param([AllowEmptyCollection()][byte[]]$Bytes)
    ($Bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ''
}

Write-Host ''
Write-Host 'CBOR primitieven (RFC 8949 appendix A)' -ForegroundColor Cyan

Assert-Equal 'unsigned 0' '00' (ConvertTo-Hex (ConvertTo-CborInt 0))
Assert-Equal 'unsigned 23' '17' (ConvertTo-Hex (ConvertTo-CborInt 23))
Assert-Equal 'unsigned 24' '1818' (ConvertTo-Hex (ConvertTo-CborInt 24))
Assert-Equal 'unsigned 255' '18ff' (ConvertTo-Hex (ConvertTo-CborInt 255))
Assert-Equal 'unsigned 256' '190100' (ConvertTo-Hex (ConvertTo-CborInt 256))
Assert-Equal 'unsigned 65536' '1a00010000' (ConvertTo-Hex (ConvertTo-CborInt 65536))
Assert-Equal 'negatief -1' '20' (ConvertTo-Hex (ConvertTo-CborInt -1))
Assert-Equal 'negatief -7 (ES256)' '26' (ConvertTo-Hex (ConvertTo-CborInt -7))
Assert-Equal 'negatief -3' '22' (ConvertTo-Hex (ConvertTo-CborInt -3))
Assert-Equal 'lege bytestring' '40' (ConvertTo-Hex (ConvertTo-CborByteString ([byte[]]@())))
Assert-Equal 'bytestring 4' '4401020304' (ConvertTo-Hex (ConvertTo-CborByteString ([byte[]]@(1, 2, 3, 4))))
Assert-Equal 'text "fmt"' '63666d74' (ConvertTo-Hex (ConvertTo-CborTextString 'fmt'))
Assert-Equal 'text "none"' '646e6f6e65' (ConvertTo-Hex (ConvertTo-CborTextString 'none'))
Assert-Equal 'lege map' 'a0' (ConvertTo-Hex (ConvertTo-CborMap -Pairs @()))

Write-Host ''
Write-Host 'AAGUID byte-volgorde' -ForegroundColor Cyan

# .NET geeft Guid.ToByteArray() mixed-endian terug; WebAuthn wil de bytes zoals
# de GUID geschreven staat. Deze GUID maakt een verwisseling meteen zichtbaar.
$guid = [guid]'00112233-4455-6677-8899-aabbccddeeff'
Assert-Equal 'AAGUID big-endian' '00112233445566778899aabbccddeeff' (ConvertTo-Hex (ConvertTo-AaguidBytes -Aaguid $guid))

Write-Host ''
Write-Host 'Coordinaat-normalisatie' -ForegroundColor Cyan

$short = [byte[]]@(0xAB, 0xCD)
Assert-Equal 'links opvullen tot 32' ('abcd'.PadLeft(64, '0')) (ConvertTo-Hex (Expand-ToFixedLength -Bytes $short -Length 32))

Write-Host ''
Write-Host 'COSE_Key EC2 / ES256' -ForegroundColor Cyan

$x = [byte[]](1..32)
$y = [byte[]](33..64)
$cose = New-CoseEc2PublicKey -X $x -Y $y

# a5                map van 5
#   01 02           kty = EC2
#   03 26           alg = -7
#   20 01           crv = P-256
#   21 5820 <x>     x
#   22 5820 <y>     y
$expectedCose = 'a5' + '0102' + '0326' + '2001' +
                '215820' + (ConvertTo-Hex $x) +
                '225820' + (ConvertTo-Hex $y)

Assert-Equal 'COSE_Key bytes' $expectedCose (ConvertTo-Hex $cose)
Assert-Equal 'COSE_Key lengte' 77 $cose.Length

Write-Host ''
Write-Host 'authenticatorData' -ForegroundColor Cyan

$credentialId = [byte[]](1..32)
$authData = New-AuthenticatorData `
    -RpId 'login.microsoft.com' `
    -Aaguid $guid `
    -CredentialId $credentialId `
    -CosePublicKey $cose `
    -SignCount 0

# 32 rpIdHash + 1 flags + 4 signCount + 16 aaguid + 2 lengte + 32 credId + 77 cose
Assert-Equal 'authData lengte' 164 $authData.Length

$sha = [System.Security.Cryptography.SHA256]::Create()
$expectedHash = ConvertTo-Hex ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('login.microsoft.com')))
$sha.Dispose()
Assert-Equal 'rpIdHash' $expectedHash (ConvertTo-Hex $authData[0..31])

# UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) | AT(0x40) = 0x5D, conform PRD §13
Assert-Equal 'flags' '5d' ('{0:x2}' -f $authData[32])
Assert-Equal 'signCount' '00000000' (ConvertTo-Hex $authData[33..36])
Assert-Equal 'aaguid in authData' '00112233445566778899aabbccddeeff' (ConvertTo-Hex $authData[37..52])
Assert-Equal 'credentialId lengte' '0020' (ConvertTo-Hex $authData[53..54])

$flagsNoBackup = New-AuthenticatorData -RpId 'login.microsoft.com' -Aaguid $guid `
    -CredentialId $credentialId -CosePublicKey $cose `
    -BackupEligible $false -BackupState $false
Assert-Equal 'flags zonder BE/BS' '45' ('{0:x2}' -f $flagsNoBackup[32])

Write-Host ''
Write-Host 'attestationObject' -ForegroundColor Cyan

$att = New-AttestationObject -AuthenticatorData $authData

# a3                       map van 3
#   63 666d74               "fmt"
#   64 6e6f6e65             "none"
#   67 61747453746d74       "attStmt"
#   a0                      {}
#   68 6175746844617461     "authData"
#   58 a4 <164 bytes>       bytestring
$expectedAtt = 'a3' +
               '63666d74' + '646e6f6e65' +
               '6761747453746d74' + 'a0' +
               '686175746844617461' + '58a4' + (ConvertTo-Hex $authData)

Assert-Equal 'attestationObject lengte' 194 $att.Length
Assert-Equal 'attestationObject bytes' $expectedAtt (ConvertTo-Hex $att)

Write-Host ''
Write-Host 'clientDataJSON' -ForegroundColor Cyan

$cd = New-ClientDataJson -ChallengeBase64Url 'abc-_123' -Origin 'https://login.microsoft.com'
Assert-Equal 'json' '{"type":"webauthn.create","challenge":"abc-_123","origin":"https://login.microsoft.com","crossOrigin":false}' $cd.Json

Write-Host ''
Write-Host 'base64url' -ForegroundColor Cyan

$roundtrip = ConvertFrom-Base64Url (ConvertTo-Base64Url ([byte[]]@(0xFB, 0xFF, 0x00, 0x3E)))
Assert-Equal 'roundtrip' 'fbff003e' (ConvertTo-Hex $roundtrip)
Assert-Equal 'geen padding, url-safe alfabet' 'Pj8-Pw' (ConvertTo-Base64Url ([byte[]]@(0x3E, 0x3F, 0x3E, 0x3F)))

Write-Host ''
if ($script:failures -eq 0) {
    Write-Host 'Alle controles geslaagd.' -ForegroundColor Green
    exit 0
}
else {
    Write-Host "$($script:failures) controle(s) mislukt." -ForegroundColor Red
    exit 1
}
