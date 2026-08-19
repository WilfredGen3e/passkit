# PasskeyManager.Phase0
#
# Helpers om een WebAuthn attestation-object in software te bouwen, zodat fase 0
# kan vaststellen of Entra zo'n credential accepteert via de provisioning-API.
#
# Bewust geen externe dependencies voor de CBOR/COSE-kant: het formaat is klein
# genoeg om met de hand te schrijven en dat maakt precies zichtbaar wat we
# aanleveren. Dat is voor een fase 0-test belangrijker dan elegantie.

Set-StrictMode -Version Latest

#region base64url

function ConvertTo-Base64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) {
        2 { $s += '==' }
        3 { $s += '=' }
    }
    [Convert]::FromBase64String($s)
}

#endregion

#region bytes

function Join-Bytes {
    <#
    .SYNOPSIS
        Plakt byte-arrays achter elkaar. Neemt ze als losse argumenten of via de pipeline.
    #>
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments)][object[]]$Parts)

    $list = [System.Collections.Generic.List[byte]]::new()
    foreach ($p in $Parts) {
        if ($null -eq $p) { continue }
        $list.AddRange([byte[]]$p)
    }
    , $list.ToArray()
}

function Get-BigEndianBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint64]$Value,
        [Parameter(Mandatory)][int]$Length
    )

    $b = [byte[]]::new($Length)
    for ($i = $Length - 1; $i -ge 0; $i--) {
        $b[$i] = [byte]($Value -band 0xFF)
        $Value = $Value -shr 8
    }
    , $b
}

function Expand-ToFixedLength {
    <#
    .SYNOPSIS
        Links met nullen opvullen tot de gevraagde lengte.
    .DESCRIPTION
        Key Vault levert EC-coordinaten normaal al als 32 bytes, maar een
        coordinaat die toevallig met een nulbyte begint kan ingekort terugkomen.
        Een COSE-sleutel met een 31-byte X wordt door de relying party afgekeurd,
        en dat is een lastig te vinden fout die pas bij ~1 op de 256 sleutels
        optreedt. Daarom onvoorwaardelijk normaliseren.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Length
    )

    if ($Bytes.Length -eq $Length) { return , $Bytes }
    if ($Bytes.Length -gt $Length) {
        throw "Waarde is $($Bytes.Length) bytes en past niet in $Length bytes."
    }

    $out = [byte[]]::new($Length)
    [Array]::Copy($Bytes, 0, $out, $Length - $Bytes.Length, $Bytes.Length)
    , $out
}

#endregion

#region CBOR

# Alleen de subset die een attestation-object nodig heeft: unsigned ints,
# negatieve ints, byte strings, text strings en maps. Geen decoder — die hebben
# we niet nodig en ongebruikte parser-code is alleen maar aanvalsoppervlak.

function New-CborHead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(0, 7)][int]$MajorType,
        [Parameter(Mandatory)][uint64]$Value
    )

    $mt = [byte]($MajorType -shl 5)

    # Grenswaarden expliciet als uint64. PowerShell parseert 0xFFFFFFFF als Int32
    # en dus als -1, waardoor de 4-byte-tak stilzwijgend nooit gekozen zou worden.
    if ($Value -lt 24) { return , [byte[]]@([byte]($mt -bor [byte]$Value)) }
    if ($Value -le [uint64]0xFF) { return , (Join-Bytes ([byte[]]@([byte]($mt -bor 24))) (Get-BigEndianBytes $Value 1)) }
    if ($Value -le [uint64]0xFFFF) { return , (Join-Bytes ([byte[]]@([byte]($mt -bor 25))) (Get-BigEndianBytes $Value 2)) }
    if ($Value -le [uint64]4294967295) { return , (Join-Bytes ([byte[]]@([byte]($mt -bor 26))) (Get-BigEndianBytes $Value 4)) }
    , (Join-Bytes ([byte[]]@([byte]($mt -bor 27))) (Get-BigEndianBytes $Value 8))
}

function ConvertTo-CborInt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$Value)

    if ($Value -ge 0) {
        New-CborHead -MajorType 0 -Value ([uint64]$Value)
    }
    else {
        New-CborHead -MajorType 1 -Value ([uint64](-1 - $Value))
    }
}

function ConvertTo-CborByteString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    Join-Bytes (New-CborHead -MajorType 2 -Value ([uint64]$Bytes.Length)) $Bytes
}

function ConvertTo-CborTextString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $b = [System.Text.Encoding]::UTF8.GetBytes($Text)
    Join-Bytes (New-CborHead -MajorType 3 -Value ([uint64]$b.Length)) $b
}

function ConvertTo-CborMap {
    <#
    .SYNOPSIS
        Bouwt een CBOR-map uit al gecodeerde sleutel/waarde-paren.
    .DESCRIPTION
        Neemt bewust vooraf gecodeerde bytes in plaats van een hashtable: de
        volgorde van de sleutels is in COSE en CTAP2 betekenisvol en moet in de
        aanroepende code zichtbaar zijn, niet afhangen van hoe PowerShell een
        hashtable toevallig enumereert.
    .PARAMETER Pairs
        Array van paren, elk een array van twee byte-arrays: @(sleutel, waarde).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Pairs)

    $parts = [System.Collections.Generic.List[object]]::new()
    $parts.Add((New-CborHead -MajorType 5 -Value ([uint64]$Pairs.Count)))
    foreach ($pair in $Pairs) {
        $parts.Add([byte[]]$pair[0])
        $parts.Add([byte[]]$pair[1])
    }
    Join-Bytes @($parts)
}

#endregion

#region COSE / WebAuthn

function New-CoseEc2PublicKey {
    <#
    .SYNOPSIS
        COSE_Key voor een EC P-256 publieke sleutel, ES256.
    .DESCRIPTION
        Sleutelvolgorde volgens RFC 8152 canonical: 1, 3, -1, -2, -3.
            1  kty = 2   (EC2)
            3  alg = -7  (ES256)
           -1  crv = 1   (P-256)
           -2  x   = 32 bytes
           -3  y   = 32 bytes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$X,
        [Parameter(Mandatory)][byte[]]$Y
    )

    ConvertTo-CborMap -Pairs @(
        , @((ConvertTo-CborInt 1), (ConvertTo-CborInt 2))
        , @((ConvertTo-CborInt 3), (ConvertTo-CborInt -7))
        , @((ConvertTo-CborInt -1), (ConvertTo-CborInt 1))
        , @((ConvertTo-CborInt -2), (ConvertTo-CborByteString (Expand-ToFixedLength -Bytes $X -Length 32)))
        , @((ConvertTo-CborInt -3), (ConvertTo-CborByteString (Expand-ToFixedLength -Bytes $Y -Length 32)))
    )
}

function New-AuthenticatorData {
    <#
    .SYNOPSIS
        Bouwt authenticatorData inclusief attestedCredentialData.
    .DESCRIPTION
        Layout:
            rpIdHash          32 bytes  SHA-256 over de RP ID
            flags              1 byte
            signCount          4 bytes  big-endian
            aaguid            16 bytes
            credentialIdLen    2 bytes  big-endian
            credentialId       n bytes
            credentialPubKey   COSE_Key

        Flags conform PRD §13: UP=1, UV=1, BE=1, BS=1, AT=1 -> 0x5D.
        signCount blijft 0; meerdere engineers delen dezelfde credential, dus een
        oplopende teller zou als clone-detectie false positives opleveren.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RpId,
        [Parameter(Mandatory)][guid]$Aaguid,
        [Parameter(Mandatory)][byte[]]$CredentialId,
        [Parameter(Mandatory)][byte[]]$CosePublicKey,
        [uint32]$SignCount = 0,
        [bool]$UserPresent = $true,
        [bool]$UserVerified = $true,
        [bool]$BackupEligible = $true,
        [bool]$BackupState = $true
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $rpIdHash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($RpId))
    }
    finally {
        $sha.Dispose()
    }

    $flags = 0
    if ($UserPresent) { $flags = $flags -bor 0x01 }   # UP
    if ($UserVerified) { $flags = $flags -bor 0x04 }   # UV
    if ($BackupEligible) { $flags = $flags -bor 0x08 }   # BE
    if ($BackupState) { $flags = $flags -bor 0x10 }   # BS
    $flags = $flags -bor 0x40                            # AT, altijd bij registratie

    Join-Bytes `
        $rpIdHash `
    ([byte[]]@([byte]$flags)) `
    (Get-BigEndianBytes ([uint64]$SignCount) 4) `
    (ConvertTo-AaguidBytes -Aaguid $Aaguid) `
    (Get-BigEndianBytes ([uint64]$CredentialId.Length) 2) `
        $CredentialId `
        $CosePublicKey
}

function ConvertTo-AaguidBytes {
    <#
    .SYNOPSIS
        AAGUID als 16 bytes in big-endian volgorde.
    .DESCRIPTION
        .NET geeft Guid.ToByteArray() in mixed-endian (eerste drie velden
        little-endian). WebAuthn wil de bytes zoals de GUID geschreven wordt.
        Zonder deze omkering staat er een andere AAGUID in het credential dan op
        de allowlist, wat pas bij rapportage opvalt.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$Aaguid)

    $b = $Aaguid.ToByteArray()
    , [byte[]]@(
        $b[3], $b[2], $b[1], $b[0],
        $b[5], $b[4],
        $b[7], $b[6],
        $b[8], $b[9], $b[10], $b[11], $b[12], $b[13], $b[14], $b[15]
    )
}

function New-AttestationObject {
    <#
    .SYNOPSIS
        CBOR attestation-object met fmt "none".
    .DESCRIPTION
        Map-volgorde fmt, attStmt, authData volgens CTAP2 canonical (kortere
        sleutel eerst). attStmt is leeg: we leveren geen attestation, zie PRD §4.3.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$AuthenticatorData)

    ConvertTo-CborMap -Pairs @(
        , @((ConvertTo-CborTextString 'fmt'), (ConvertTo-CborTextString 'none'))
        , @((ConvertTo-CborTextString 'attStmt'), (ConvertTo-CborMap -Pairs @()))
        , @((ConvertTo-CborTextString 'authData'), (ConvertTo-CborByteString $AuthenticatorData))
    )
}

function New-ClientDataJson {
    <#
    .SYNOPSIS
        clientDataJSON voor een create-ceremonie.
    .DESCRIPTION
        Met de hand opgebouwd in plaats van via ConvertTo-Json: de relying party
        hasht deze bytes letterlijk, dus witruimte en sleutelvolgorde moeten
        voorspelbaar zijn. De challenge komt al base64url gecodeerd uit
        creationOptions en gaat er ongewijzigd in.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ChallengeBase64Url,
        [Parameter(Mandatory)][string]$Origin,
        [string]$Type = 'webauthn.create'
    )

    $json = '{"type":"' + $Type + '","challenge":"' + $ChallengeBase64Url + '","origin":"' + $Origin + '","crossOrigin":false}'
    [PSCustomObject]@{
        Json  = $json
        Bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    }
}

function New-CredentialId {
    [CmdletBinding()]
    param([int]$Length = 32)

    $b = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    , $b
}

#endregion

Export-ModuleMember -Function @(
    'ConvertTo-Base64Url'
    'ConvertFrom-Base64Url'
    'Join-Bytes'
    'Get-BigEndianBytes'
    'Expand-ToFixedLength'
    'New-CborHead'
    'ConvertTo-CborInt'
    'ConvertTo-CborByteString'
    'ConvertTo-CborTextString'
    'ConvertTo-CborMap'
    'New-CoseEc2PublicKey'
    'New-AuthenticatorData'
    'ConvertTo-AaguidBytes'
    'New-AttestationObject'
    'New-ClientDataJson'
    'New-CredentialId'
)
