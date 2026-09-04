# Fase 0 — accepteert Entra een software-gegenereerde passkey?

Deze map beantwoordt de twee vragen uit [PRD §14.1](../docs/PRD.md#14-openstaande-punten). Zolang die niet beantwoord zijn is de rest van de bouw hypothetisch.

| Vraag | Wat het is | Hoe je het antwoord herkent |
|---|---|---|
| **Formaat** | Slikt Entra een attestation-object met `fmt: none` waarvan de private key in Key Vault staat en nooit een authenticator is geweest? | HTTP 400 op de registratie-POST |
| **Rechten** | Kan een partner-engineer dit namens de gebruiker via GDAP, of eist de provisioning-API dat de gebruiker het zelf doet? | HTTP 401/403 op dezelfde POST |

Het script trekt die twee expliciet uit elkaar en zet de conclusie in het resultaatbestand. Dat onderscheid is de hele opbrengst van fase 0: bij een 403 hoeft de registratieflow uit §7 herzien te worden, bij een 400 het credentialformaat.

## Inhoud

| Bestand | Doel |
|---|---|
| `PasskeyManager.Phase0.psm1` | CBOR/COSE-encoder en de WebAuthn-structuren. Handgeschreven, geen dependencies. |
| `Test-Encoding.ps1` | Offline controle van die encoder. Geen Azure nodig. |
| `Invoke-Phase0Test.ps1` | De echte test tegen Key Vault en Graph. |
| `results/` | Resultaatbestanden per run (niet in git). |

## Eerst: de encoder controleren

```powershell
pwsh -NoProfile -File .\Test-Encoding.ps1
```

Draai dit voordat je de echte test doet. Een fout in de handgeschreven CBOR komt bij Entra terug als een nietszeggende HTTP 400, en dan weet je niet of het aan ons ligt of aan Entra. Deze test vergelijkt de bytes met wat RFC 8949, RFC 8152 en de WebAuthn-spec voorschrijven, zodat een 400 tijdens de echte test betekenisvol is.

## Voorbereiding

### Op je werkplek

- PowerShell 7
- Modules `Az.KeyVault` en `Microsoft.Graph.Authentication`
- `Connect-AzAccount` naar **onze eigen** tenant, waar de Key Vault staat

Let op dat dit twee verschillende tenants zijn: Az wijst naar onze tenant, Graph naar de klant. Het script controleert dat vooraf.

### In de testtenant — authenticatiemethoden, Passkey (FIDO2)

| Instelling | Waarde | Waarom |
|---|---|---|
| Inschakelen | Ja | |
| Doelgroep | het testaccount, of Alle gebruikers | de methode aan zetten is niet genoeg, het account moet ook in de doelgroep vallen |
| Attestatie afdwingen | **Nee** | Entra kan op synced passkeys toch niets verifiëren (PRD §4.3) |
| Sleutelbeperkingen afdwingen | **Nee** | anders geldt er een AAGUID-allowlist en wordt onze placeholder geweigerd — je krijgt dan een 400 die op een formaatfout lijkt maar beleid is |
| Self-service setup toestaan | **Ja** | de provisioning-API is op zelfregistratie geënt |

Die laatste twee zijn de makkelijkst te vergeten voorwaarden en allebei kunnen ze de uitkomst van fase 0 verkeerd doen lijken.

### GDAP-rol — bepaalt wat de test bewijst

Voor het beheren van authenticatiemethoden bestaan twee rollen, en het verschil is hier wezenlijk:

| Rol | Mag auth-methoden beheren van |
|---|---|
| Authentication Administrator | niet-admin gebruikers |
| **Privileged Authentication Administrator** | ook accounts die zelf een adminrol hebben |

In productie mikken we op **Global Admins** in klanttenants. Slaagt de test tegen een gewone gebruiker met Authentication Administrator, dan is daarmee dus niets bewezen over het echte scenario.

**Draai de test daarom twee keer:** eerst tegen een gewone testgebruiker, daarna tegen een testgebruiker die je Global Admin hebt gemaakt. Het verschil tussen die runs is de eigenlijke opbrengst. Het script leest de adminrollen van het doelaccount uit en zet in het resultaatbestand welk van de twee scenario's je getest hebt.

Structureel Privileged Authentication Administrator houden over 300 tenants is een zware keuze. Dat is openstaand punt PRD §14.3, en fase 0 levert de feiten om die keuze te maken.

Verder: je partner-account moet lid zijn van de security group die aan de GDAP-rol hangt, en roltoewijzingen hebben even nodig om door te werken.

### Key Vault — alleen in de Key Vault-modus

- Rol *Key Vault Crypto Officer* op de vault (of Create/Get bij access policies)
- Geen firewall of private endpoint die je machine buitensluit

Mislukt de registratie, dan ruimt het script de zojuist aangemaakte sleutel weer op — hij is soft-deleted en dus terug te halen. Met `-KeepKeyOnFailure` blijft hij staan.

## Twee modi, en waarom

Het script kan de sleutel op twee manieren krijgen. De opbouw van het credential daarna is identiek — dezelfde COSE-sleutel, dezelfde authenticatorData, hetzelfde attestation-object — dus wat de ene modus over het formaat bewijst, geldt ook voor de andere.

| Modus | Sleutel | Azure nodig | Waarvoor |
|---|---|---|---|
| `-LocalKey` | lokaal gegenereerd, exporteerbaar | nee | de formaatvraag stellen zonder dat Key Vault-rechten een variabele zijn |
| `-KeyVaultName` + `-SubscriptionId` | non-exportable in Key Vault | ja | het productieontwerp (PRD §4.2) |

**Begin met `-LocalKey`.** De reden is dezelfde als waarom fase 0b naar een tekstbestand schrijft in plaats van naar Key Vault (PRD §12.1): twee onafhankelijke faalpunten in één run maken een fout onduidbaar. Een ontbrekende RBAC-rol in een MSDN-subscription hoort een vraag over Entra niet te kunnen blokkeren — en in de praktijk deed hij dat ook.

De prijs is dat de private key exporteerbaar is en in leesbare vorm in het artefactbestand komt. Dat is de omkering van het hele beveiligingsontwerp en uitsluitend aanvaardbaar in een testtenant. Zet er niets mee op een account dat ertoe doet.

### Het artefact

`-LocalKey` schrijft `results/credential-<timestamp>.json`. Dat is de overdracht naar fase 0b — het bevat precies wat er nodig is om later een assertion te tekenen:

| Veld | Waarvoor |
|---|---|
| `privateKeyPkcs8` | tekenen (base64, PKCS#8) |
| `credentialId`, `rpId`, `userHandle` | wat een authenticator bij een assertion teruggeeft |
| `publicKey.x/y`, `coseKeyHex` | controleren dat de sleutel bij het credential hoort |
| `aaguid`, `signCount` | authenticatorData opnieuw opbouwen |
| `entra.methodId` | de registratie later weer opruimen |

Het wordt weggeschreven vóór de registratie-POST en na een geslaagde registratie nog een keer bijgewerkt. Bij een mislukte POST blijft het dus staan — juist dan is het bruikbaar om offline mee verder te werken.

## Draaien

Eerst droog, om te zien wat er verstuurd zou worden. Raakt Azure niet aan:

```powershell
.\Invoke-Phase0Test.ps1 `
    -CustomerTenantId <guid> `
    -UserPrincipalName admin@testtenant.onmicrosoft.com `
    -LocalKey `
    -ClientId <guid> `
    -SkipRegistration
```

Dan echt:

```powershell
.\Invoke-Phase0Test.ps1 `
    -CustomerTenantId <guid> `
    -UserPrincipalName admin@testtenant.onmicrosoft.com `
    -LocalKey `
    -ClientId <guid>
```

En pas als dat geslaagd is, dezelfde test met de sleutel in Key Vault:

```powershell
.\Invoke-Phase0Test.ps1 `
    -CustomerTenantId <guid> `
    -UserPrincipalName admin@testtenant.onmicrosoft.com `
    -KeyVaultName kv-passkeys-test `
    -SubscriptionId <guid>
```

Elke run schrijft `results/phase0-<timestamp>.json` met de ruwe creationOptions, de opgebouwde bytes, de verstuurde body en de response of fout. Bewaar dat bestand — het is de onderbouwing van de fase 0-conclusie.

## Wat de API van ons verlangt

Vastgesteld aan de hand van de Graph-documentatie en van [`DSInternals.Passkeys`](https://github.com/MichaelGrafnetter/webauthn-interop), een module die dit aantoonbaar werkend doet. Dat haalt een reeks variabelen weg die anders bij een 400 stuk voor stuk uitgesloten hadden moeten worden.

| | |
|---|---|
| API-versie | `v1.0` is GA voor deze endpoints. Let op: v1.0 hanteert een vaste challenge-time-out van vijf minuten en accepteert `challengeTimeoutInMinutes` niet — dat is beta-only. Het script stelt de URI daarop af. |
| Scope | `UserAuthMethod-Passkey.ReadWrite.All` is de fijnmazige, `UserAuthenticationMethod.ReadWrite.All` de bredere. Beide volstaan. De smalle is voor de onboardingflow over 300 tenants de makkelijkere consent-vraag. |
| Rollen | Global Reader, Authentication Administrator of Privileged Authentication Administrator — bevestigd in de Graph-documentatie, en in lijn met het onderscheid hierboven. |
| Body | `publicKeyCredential.response.{clientDataJson,attestationObject}`, base64url zonder padding. Let op de schrijfwijze `clientDataJson`, niet `clientDataJSON`. |

Twee dingen die Microsoft expliciet documenteert en die allebei een 400 opleveren die op een formaatfout lijkt:

- **"Allow self-service setup" moet aan staan.** Microsoft voert dit als *known issue* van de provisioning-API. Staat het uit, dan faalt de POST om een reden die niets met het credential te maken heeft.
- **Zelfregistratie wordt niet ondersteund.** Deze API werkt alleen namens een ander. Test dus niet tegen je eigen account.

Het script herkent beide gevallen in de response en zet de formaatconclusie dan expliciet op *onbekend* in plaats van op *afgekeurd*.

Een derde, uit de praktijk: **"User or group restriction policy failed"** betekent dat het doelaccount niet in de doelgroep van het FIDO2-beleid valt. Ook beleid, ook een 400.

## Wat nog niet vaststaat

Bewust niet aangenomen, omdat fase 0 er juist voor is om het uit te zoeken:

- **RP ID.** Wordt uit `creationOptions` overgenomen, niet hardgecodeerd (PRD §13). De `origin` in `clientDataJSON` wordt daarvan afgeleid als `https://<rpId>`; als de test uitwijst dat Entra iets anders verwacht, overschrijf met `-Origin`.
- **AAGUID.** Standaard alleen nullen. Prima voor een formaattest, maar stel de definitieve vast voordat er iets in productie geregistreerd wordt.
- **De kernvraag zelf.** `DSInternals.Passkeys` bewijst dat het *pad* werkt, maar gebruikt de Windows WebAuthn-API en dus een echte authenticator of Windows Hello. Of Entra een credential accepteert dat nooit in een authenticator heeft gezeten, is daarmee nog steeds onbeantwoord. Dat is precies wat dit script uitzoekt.

## Aantekening voor fase 5

Key Vault levert een ES256-handtekening als raw `r || s` (64 bytes). WebAuthn wil in een assertion een ASN.1 DER-gecodeerde ECDSA-Sig-Value. Het `/sign`-endpoint moet dus converteren; dat is geen bug maar wel iets waar je een middag op zoekt als je het niet weet.

Dit geldt onverkort voor het lokale artefact: .NET geeft met `ECDsa.SignData(...)` standaard óók raw `r || s`. Wil je DER, geef dan expliciet `DSASignatureFormat.Rfc3279DerSequence` mee. Het lokale pad reproduceert deze valkuil dus in plaats van hem te verbergen — dat is de bedoeling.
