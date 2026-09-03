# PRD — Centraal passkey-beheer voor MSP-beheerde admin-accounts

**Versie:** 1.1
**Datum:** 3 september 2026
**Status:** Ter besluitvorming / gereed voor uitwerking
**Vervangt:** alle eerdere concepten
**Wijziging t.o.v. 1.0:** de Windows-provider-haalbaarheid is geen fase-6 "later" meer, maar een blokkerende validatie naast de Entra/GDAP-vraag (§11, §12, §14) — zonder werkende Windows-provider heeft dit ontwerp geen gebruiksmechanisme, en er is bewust geen browserextensie-alternatief.

---

## 1. Aanleiding

Microsoft faseert SMS- en voice-MFA uit in Entra ID. Vanaf 1 september 2026 worden gebruikers die op SMS of voice staan automatisch voor passkeys ingeschakeld en gaat de Registration Campaign naar "Microsoft managed" om ze te nudgen; vanaf 1 februari 2027 wordt de door Microsoft geleverde telecomlevering voor SMS en voice ingetrokken, waarna gebruikers met uitsluitend die methodes een blokkerende registratieprompt krijgen zonder opt-out.

Los daarvan geldt: passkeys zijn de richting waar Microsoft heen gaat, en voor privileged accounts is phishing-resistente authenticatie sowieso de juiste keuze.

**Ons probleem:** wij beheren in elke klanttenant een Global Admin-account. Dat account bestaat noodzakelijkerwijs — er zijn handelingen die niet via GDAP kunnen. Vandaag staat de TOTP-seed daarvan in IT Glue. IT Glue kent geen passkey-object, dus er is geen bestaande plek om dit te beleggen.

**Schaal:** ~300 klanten, één GA-account elk, plus break-glass en incidentele overige accounts. Met ruimte voor groei rekenen we op 1000–2000 credentials.

---

## 2. Wat we bouwen

Een webinterface met per-klant structuur waarin we passkeys voor die accounts kunnen registreren, inzien, gebruiken en intrekken. De sleutels leven centraal in Azure Key Vault. Later komt daar een Windows-component bij zodat de passkeys ook daadwerkelijk bruikbaar zijn bij het inloggen.

**Buiten scope:** migratie van bestaande TOTP-seeds, eindgebruiker-MFA bij klanten, IT Glue vervangen, macOS/Linux/mobiel als beheerclient, wachtwoordbeheer.

---

## 3. Context: waar dit systeem in past

Dit is bewust géén primaire toegangsroute. De inrichting eromheen:

- **Reguliere toegang** tot klanttenants loopt via Lighthouse/GDAP, uitsluitend vanaf managed devices
- **Toegang tot dit portaal** vereist PIM-activering op een Entra-groep; standaard heeft niemand toegang
- **Tweede route** blijft bestaan: TOTP via IT Glue. Dit systeem is dus geen single point of failure voor klanttoegang
- **Break-glass op onze eigen tenant** met FIDO buiten CA is al ingericht als algemene praktijk

Dat maakt het risicoprofiel wezenlijk anders dan bij een systeem dat dagelijks gebruikt wordt: activeringen zijn zeldzaam en daarmee individueel opvallend, wat anomaliedetectie eenvoudig maakt.

---

## 4. Vastgelegde ontwerpbeslissingen

### 4.1 Passkeys zijn niet opslaanbaar als geheim
Een passkey is geen TOTP-seed. De private key hoort de authenticator niet te verlaten en er is geen exportformaat. Wil je hem centraal beheren, dan moet je zelf de authenticator zijn. Dat is de reden dat er een clientcomponent nodig is en dat dit meer werk is dan "een kluisje bouwen".

### 4.2 Remote signing, geen sleuteldistributie
De private key wordt aangemaakt als non-exportable EC P-256 key in Key Vault en verlaat die nooit. De client bouwt `authenticatorData || SHA256(clientDataJSON)`, de backend laat Key Vault tekenen, de handtekening gaat terug.

Gevolgen:
- er staat nooit sleutelmateriaal op een endpoint, in geen enkele vorm
- een gestolen of gecompromitteerde laptop levert niets op — de clientcomponent is een lege huls
- een engineer intrekken is één RBAC-wijziging, geen sleutelrotatie
- elke handtekening is een auditregel

### 4.3 Attestation staat uit — bewust geaccepteerd
Deze passkeys zijn synced, en Entra ondersteunt geen attestation op synced passkeys: staat attestation op "yes", dan zijn alleen device-bound passkeys toegestaan, en zonder attestation kan Entra geen enkel attribuut verifiëren, ook AAGUID-lijsten niet.

Dit is het MSP-compromis. Het alternatief is per tenant fysieke keys uitgeven (logistiek onwerkbaar bij groei) of alles op één sleutel zetten (fysiek single point of failure). Onze AAGUID komt wel op de allowlist — advisory, voor schone rapportage.

*Vastgelegd zodat hier over drie jaar niet opnieuw over gediscussieerd hoeft te worden.*

### 4.4 Onderscheid beheer- versus noodaccounts
| | beheer | noodtoegang |
|---|---|---|
| Gebruik | regelmatig | zeldzaam |
| Alert bij gebruik | nee | ja, direct |
| Reden | ticketnummer | vrije tekst + ticketnummer |
| Rapportage | maandoverzicht | elk gebruik apart |

---

## 5. Beveiliging

Twee eisen die het verschil maken en die **server-side** afgedwongen worden, niet in de UI:

**User verification per tekenoperatie.** Niet één keer per sessie. De backend accepteert alleen een tekenverzoek met een verse Windows Hello-bevestiging. PIM is de poort, UV is de check per handeling. Zonder dit is een geactiveerde sessie urenlang een blanco cheque op een machine die besmet kan zijn — dit is de belangrijkste maatregel in het hele ontwerp.

**Scope per aanvraag.** Elke tekenoperatie toetst: welke engineer, welke klant, is die klant nu actief in zijn sessie, heeft hij Operator op precies deze klant. Een misbruikte sessie raakt daarmee één klant, niet de hele portefeuille.

**PIM-inrichting.** Activeringsduur krap houden — één uur is voor dit gebruikspatroon ruim. Reden en ticketnummer verplicht. Auto-approval is verdedigbaar mits er een alert op staat die iemand daadwerkelijk leest; auto-approval is logging, geen goedkeuring.

**Wat overblijft aan risico.** Dit systeem kan namens 300 tenants tekenen. Dat is inherent aan het doel en wordt gedempt door bovenstaande maatregelen plus het feit dat het geen dagelijkse route is. Externe pentest vóór productiegebruik.

---

## 6. Architectuur

```
Engineer (PIM-geactiveerd, managed device)
      │  Entra-login + CA-policy
      ▼
Static Web App ──(managed backend)──► Azure Functions
  geen secrets client-side                │ Managed Identity
                                          ├─► Key Vault (EC P-256, alleen sign)
                                          ├─► Table/Cosmos (klantfolders, metadata)
                                          ├─► Graph (per klanttenant, via GDAP)
                                          └─► Log Analytics (audit)
```

Later erbij: Windows passkey provider (MSIX, plugin authenticator API) op engineer-workstations, die via `/sign` bij de backend aanklopt. Alleen op onze eigen ~20–80 machines, niet bij klanten.

### Datamodel
```
Klant (tenant-ID, naam, primair domein, status, PSA-referentie)
  └── Account (UPN, type: beheer|noodtoegang, doel)
        └── Credential (credentialId, keyVaultKeyId, aaguid,
                        displayName, aangemaakt, door wie, status)
```

---

## 7. Registratieflow

Volledig server-side. Geen browserceremonie, geen lokale software, geen hardware:

1. Engineer kiest klant en account in het portaal
2. `GET /users/{upn}/authentication/fido2Methods/creationOptions` via Graph
3. Backend maakt non-exportable EC P-256 key in Key Vault
4. Backend bouwt het attestation-object (`none`) met onze AAGUID
5. `POST /users/{upn}/authentication/fido2Methods` registreert in Entra
6. Metadata vastgelegd onder de klantfolder

Vereist GDAP naar de klanttenant en "Allow self-service setup" aan in hun FIDO2-beleid.

**Let op:** de provisioning-API is doorgaans bedoeld voor een gebruiker die zijn eigen methode registreert. Wij doen dit namens de gebruiker, met alleen gedelegeerde rechten via GDAP. Of dat pad werkt is een aparte vraag van of Entra de credential inhoudelijk accepteert — beide moeten in fase 0 bewezen worden, en in de praktijk is het rechtenpad vaker het struikelblok dan het credentialformaat. Zie §14.1.

---

## 8. Rollen

Per klant toe te kennen — een engineer kan Operator zijn op zijn eigen portefeuille en Reader op de rest.

| Rol | Rechten |
|---|---|
| Reader | Klantfolders en metadata zien |
| Operator | + registreren en gebruiken |
| Revoker | + intrekken en verwijderen |
| Tenant Admin | Klantfolders aanmaken, rollen toekennen |

---

## 9. API

```
POST   /customers                    klantfolder aanmaken (idempotent op tenant-ID)
GET    /customers/{id}
POST   /customers/{id}/accounts
GET    /customers/{id}/credentials
POST   /customers/{id}/credentials   registreren via Graph
DELETE /credentials/{id}             vereist Revoker
POST   /sign                         intern, alleen voor de provider
```

OAuth2 client credentials met Entra app-rollen. `POST /customers` maakt folder én rolgroepen in één handeling.

**Driftdetectie:** periodieke sync die per klanttenant `fido2Methods` uitleest en meldt wat afwijkt van onze administratie, beide kanten op.

---

## 10. Audit

Append-only naar een Log Analytics workspace waar de portaal-identiteit geen schrijfrechten op heeft.

Per regel: engineer-UPN, klant, account, credential-ID, actie, PIM-activering, ticketnummer, tijdstip, bron-IP, device-ID, resultaat.

Alerts op: gebruik van een noodtoegang-account, revoke, rolwijziging, registratie buiten kantooruren.

---

## 11. Fasering

| Fase | Resultaat |
|---|---|
| **0a** | Testtenant: bevestig dat Entra een software-gegenereerde credential accepteert via de provisioning-API, én dat dat lukt met alleen GDAP-rechten |
| **0b** | Windows-provider-haalbaarheid: bevestig dat een eigen `IPluginAuthenticator` daadwerkelijk door Windows 11 wordt aangeroepen bij een passkey-aanmelding — minimale POC, geen productieflow (zie §12.1) |
| **1** | Datamodel, klantfolders, Entra-login, PIM-koppeling, RBAC |
| **2** | Registratieflow via Graph, één klant end-to-end |
| **3** | Auditlog, alerts, driftdetectie |
| **4** | Onboarding-API, bulkuitrol over de klantenbase |
| **5** | Sign-endpoint gereed maken voor de provider |
| **6** | Windows passkey provider, productierijp op basis van 0b (zie §12.2) |

**0a en 0b zijn beide blokkerend, en gelijkwaardig belangrijk.** Zonder 0a heeft het opslagmodel geen zin; zonder 0b heeft het hele project geen gebruiksmechanisme, want er is bewust geen browserextensie-alternatief. Dat de Windows-provider in een eerdere versie van dit document als "apart traject" bij fase 6 stond, was een verkeerde inschatting van het risico: het is geen uitbreiding die later kan volgen, het is de vraag die bepaalt of dit project een manier heeft om passkeys daadwerkelijk te gebruiken.

---

## 12. Windows provider

De clientcomponent die de passkeys bruikbaar maakt bij het inloggen. Dit is niet een detail dat later uitgewerkt kan worden: zonder een werkende Windows-provider heeft de rest van dit ontwerp geen manier om passkeys daadwerkelijk te gebruiken, en er is bewust geen browserextensie-alternatief. Vandaar fase 0b (§11): de haalbaarheid hiervan wordt naast de Entra/GDAP-vraag als eerste getoetst, vóór er in fase 1–5 geïnvesteerd wordt.

### 12.1 Fase 0b — minimale haalbaarheids-POC

Doel is uitsluitend aantonen **dát** Windows 11 een eigen `IPluginAuthenticator` daadwerkelijk aanroept bij een passkey-aanmelding — niet een werkende registratie- of tekenflow bouwen. Concreet: een geregistreerde plugin die bij aanroep een "rondje" maakt naar het bestaande `phase0`-PowerShell-script (dat al iets naar Key Vault wegschrijft), puur om te bewijzen dat de aanroep vanuit Windows daadwerkelijk bij onze eigen code aankomt. Geen productieflow, geen echte signing, geen credential-scoping — dat is §12.2 / fase 6.

Slaagt dit niet — Windows roept de plugin niet aan, registratie lukt niet, of het OS behandelt third-party plugin-authenticators anders dan gedocumenteerd — dan is dat een showstopper voor het hele project, niet alleen voor fase 6.

### 12.2 Productie-uitwerking (fase 6, na geslaagde 0b)

Windows 11 kent hiervoor een COM-interface `IPluginAuthenticator`: een vendor levert een verpakte app die een COM-object registreert, een AAGUID en naam meelevert, waarna het OS WebAuthn-ceremonies naar die app dispatcht. Registratie loopt via `WebAuthNPluginAddAuthenticator`, credential-metadata via `WebAuthNPluginAuthenticatorAddCredentials` en `RemoveCredentials`, user verification via `WebAuthNPluginPerformUserVerification` met Windows Hello.

Referentie: het Contoso Passkey Manager-sample in `microsoft/Windows-classic-samples`, headers in `microsoft/webauthn`.

**Te ontwerpen: het credential-pickerprobleem.** Alle Entra-passkeys van alle klanten delen dezelfde RP ID. Publiceer je ze allemaal aan Windows, dan krijgt de engineer bij elke login honderden opties. Oplossing: de provider publiceert alleen de credentials van de klant die op dat moment actief is, vervallend na inactiviteit of bij lock. Levert meteen veiligheidswinst — nooit meer dan één klant tegelijk scherp.

**Benodigde competenties:** C++/COM/WinUI 3, CBOR en COSE, ECDSA P-256 en WebAuthn op detailniveau, MSIX-packaging en signing. Inschatting 6–9 maanden voor de productierijpe versie. Als die kennis niet in huis is: inkopen, niet leren op een Tier-0-systeem.

---

## 13. Vaste technische instellingen

| Item | Waarde |
|---|---|
| AAGUID | Eén vaste, willekeurig gegenereerde GUID voor al onze builds |
| Attestation | `none` |
| Algoritme | ES256 (EC P-256) |
| `signCount` | 0 — meerdere engineers delen de credential; een teller geeft false-positive clone-detectie |
| `UV` flag | 1, via Windows Hello |
| `BE` / `BS` | 1 / 1 — zie toelichting hieronder |
| Credential-type | Discoverable (resident), vereist voor Entra passwordless |
| RP ID | Verifiëren in fase 0, niet aannemen |

**Toelichting `BE` / `BS`.** Deze credential is niet gesynced in de gebruikelijke zin van het woord — er is geen cloudprovider die hem repliceert, hij staat in Key Vault. We zetten beide flags op 1 omdat meerdere engineers dezelfde credential moeten kunnen gebruiken, en de credential dus niet als device-gebonden mag ogen. Zou `BE` op 0 staan, dan presenteren we een device-bound credential die feitelijk vanaf elk engineer-workstation gebruikt wordt — dat wringt met wat de relying party mag aannemen. Het is dus een bewuste keuze die volgt uit §4.2, niet een beschrijving van waar de sleutel fysiek leeft.

---

## 14. Openstaande punten

1. **Fase 0a-test (Entra/GDAP)** — twee vragen die los van elkaar staan en allebei beantwoord moeten worden:
   - accepteert Entra een volledig in software gegenereerde credential? Volgt logisch uit het ontbreken van attestation-handhaving, maar de hele bouw hangt eraan.
   - werkt de registratieflow met uitsluitend GDAP-rechten, dus namens de gebruiker in plaats van als de gebruiker? De provisioning-API is primair op self-service geënt; dit is het waarschijnlijkste faalpunt van de twee.

   Valt de tweede vraag negatief uit, dan is er nog een uitweg via een tijdelijke sessie als het GA-account zelf, maar dat verandert de registratieflow wezenlijk en hoort dan opnieuw ontworpen te worden.
2. **Fase 0b-test (Windows-provider)** — roept Windows 11 een eigen `IPluginAuthenticator` daadwerkelijk aan bij een passkey-aanmelding? Zie §12.1. Gelijkwaardig blokkerend aan 0a: zonder positief antwoord hier is er geen browserextensie-alternatief, en heeft de rest van het ontwerp geen gebruiksmechanisme.
3. **Key Vault-tier** — Premium rekent per sleutel per maand, wat bij 2000 sleutels aantikt; Managed HSM heeft een vaste prijs die op dit volume gunstiger kan uitvallen. Ook throttling- en sleutelaantallimieten per vault checken, zo nodig sharden.
4. **GDAP-rolkeuze** per klanttenant voor de registratieflow.
5. **C++/COM-capaciteit** in huis of inkopen, voor fase 6.
6. **Klantcommunicatie** — vastleggen in de dienstverleningsovereenkomst dat wij deze credentials houden.
7. **Break-glass buiten dit systeem** — bevestigen dat de bestaande procedure per klanttenant dekkend blijft.
