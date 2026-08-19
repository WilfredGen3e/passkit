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

### Key Vault

- Rol *Key Vault Crypto Officer* op de vault (of Create/Get bij access policies)
- Geen firewall of private endpoint die je machine buitensluit

Mislukt de registratie, dan ruimt het script de zojuist aangemaakte sleutel weer op — hij is soft-deleted en dus terug te halen. Met `-KeepKeyOnFailure` blijft hij staan.

## Draaien

Eerst droog, om te zien wat er verstuurd zou worden:

```powershell
.\Invoke-Phase0Test.ps1 `
    -CustomerTenantId <guid> `
    -UserPrincipalName admin@testtenant.onmicrosoft.com `
    -KeyVaultName kv-passkeys-test `
    -SkipRegistration
```

Dan echt:

```powershell
.\Invoke-Phase0Test.ps1 `
    -CustomerTenantId <guid> `
    -UserPrincipalName admin@testtenant.onmicrosoft.com `
    -KeyVaultName kv-passkeys-test
```

Elke run schrijft `results/phase0-<timestamp>.json` met de ruwe creationOptions, de opgebouwde bytes, de verstuurde body en de response of fout. Bewaar dat bestand — het is de onderbouwing van de fase 0-conclusie.

## Wat nog niet vaststaat

Bewust niet aangenomen, omdat fase 0 er juist voor is om het uit te zoeken:

- **RP ID.** Wordt uit `creationOptions` overgenomen, niet hardgecodeerd (PRD §13). De `origin` in `clientDataJSON` wordt daarvan afgeleid als `https://<rpId>`; als de test uitwijst dat Entra iets anders verwacht, overschrijf met `-Origin`.
- **API-versie.** Standaard `beta`. Of de fido2-provisioning-endpoints ook op `v1.0` staan is niet geverifieerd; te wisselen met `-GraphApiVersion`.
- **Vorm van de request body.** `publicKeyCredential.response.{clientDataJSON,attestationObject}`, base64url. Als dit de reden van een 400 blijkt, staat de volledige response in het resultaatbestand.
- **AAGUID.** Standaard alleen nullen. Prima voor een formaattest, maar stel de definitieve vast voordat er iets in productie geregistreerd wordt.

## Aantekening voor fase 5

Key Vault levert een ES256-handtekening als raw `r || s` (64 bytes). WebAuthn wil in een assertion een ASN.1 DER-gecodeerde ECDSA-Sig-Value. Het `/sign`-endpoint moet dus converteren; dat is geen bug maar wel iets waar je een middag op zoekt als je het niet weet.
