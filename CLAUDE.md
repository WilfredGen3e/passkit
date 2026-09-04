# PassKit

## Doel

Centraal beheer van passkeys voor **MSP-beheerde Global Admin-accounts in klanttenants**. In elke klanttenant beheren we noodzakelijkerwijs een GA-account (er zijn handelingen die niet via GDAP kunnen). De TOTP-seed daarvan staat nu in IT Glue; IT Glue kent geen passkey-object. PassKit geeft die credentials een plek: registreren, inzien, gebruiken en intrekken, per klant gescheiden.

Aanleiding: Microsoft faseert SMS-/voice-MFA uit (blokkerende registratieprompt vanaf 1 februari 2027) en passkeys zijn sowieso de juiste keuze voor privileged accounts.

Volledige requirements en architectuur: zie [`docs/PRD.md`](./docs/PRD.md) (v1.0, 19 augustus 2026 — **vervangt alle eerdere concepten**). Actuele voortgang en eerstvolgende stap: zie [`docs/VOORTGANG.md`](./docs/VOORTGANG.md) — **lees dat bestand eerst** bij het hervatten van werk.

**Buiten scope:** migratie van bestaande TOTP-seeds, eindgebruiker-MFA bij klanten, IT Glue vervangen, macOS/Linux/mobiel als beheerclient, wachtwoordbeheer.

## Kernontwerp

Dit wijkt op een fundamenteel punt af van een eerder verkend model: **geen envelope encryption, geen decrypt-in-memory.**

- **Remote signing, geen sleuteldistributie.** De private key wordt aangemaakt als non-exportable EC P-256 key in Azure Key Vault en verlaat die nooit. De client bouwt `authenticatorData || SHA256(clientDataJSON)`, de backend laat Key Vault zelf tekenen. Er staat dus nooit sleutelmateriaal op een endpoint — een gecompromitteerde laptop levert niets op, intrekken is één RBAC-wijziging.
- **Attestation staat bewust uit.** Entra ondersteunt geen attestation op synced passkeys; het alternatief (fysieke keys per tenant, of één gedeelde sleutel) is logistiek onwerkbaar op deze schaal. Eigen AAGUID komt wel op de allowlist, advisory.
- **Registratie is volledig server-side via Graph** (`POST /users/{upn}/authentication/fido2Methods`), geen browserceremonie — dit is een bewust andere aanpak dan "klant-site + interactieve WebAuthn `create()`". Vereist GDAP naar de klanttenant + "Allow self-service setup" in hun FIDO2-beleid. Of dat werkt met alleen gedelegeerde (GDAP-)rechten is nog niet bewezen (zie Status).
- **UV per handeling, niet per sessie.** De backend accepteert alleen een tekenverzoek met een verse Windows Hello-bevestiging — PIM is de poort, user verification is de check per handeling. Dit is de belangrijkste beveiligingsmaatregel in het ontwerp.
- **Scope per aanvraag**, niet per sessie: elke tekenoperatie toetst engineer + klant + actieve klant-context + rol op precies die klant.
- **Windows passkey provider is géén "later" traject.** `IPluginAuthenticator`-COM-interface, alleen op eigen ~20–80 workstations, niet bij klanten. Er is bewust geen browserextensie-alternatief, dus de haalbaarheid hiervan is (sinds 3 september 2026) fase 0b — even blokkerend als de Entra/GDAP-vraag (0a), vóór er in fase 1+ geïnvesteerd wordt. Pas de productierijpe versie (fase 6, ná geslaagde 0b) is ingeschat op 6–9 maanden en vereist C++/COM/WinUI 3/CBOR/COSE-kennis.
- **Rollen per klant:** Reader / Operator / Revoker / Tenant Admin.
- **Onderscheid beheer- vs. noodtoegangsaccounts**: verschillend alert- en rapportagebeleid (zie PRD §4.4).

## Architectuur (doel-architectuur, fase 1+)

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

Datamodel: `Klant → Account (beheer|noodtoegang) → Credential (Key Vault key-ID, aaguid, status)`.

## Structuur

```
/README.md          — korte projectintroductie
/docs/PRD.md         — product requirements document v1.0 (bron van waarheid)
/docs/VOORTGANG.md   — werkdocument tussen sessies: waar staan we, wat is de volgende stap, log
/phase0/             — fase 0-spike: bewijst of Entra een software-gegenereerde passkey accepteert
  README.md          — uitleg, voorwaarden, hoe te draaien
  PasskeyManager.Phase0.psm1 — handgeschreven CBOR/COSE-encoder + WebAuthn-structuren, geen dependencies
  Test-Encoding.ps1  — offline encodertest (30 controles), geen Azure nodig
  Invoke-Phase0Test.ps1 — echte test tegen Key Vault + Graph in een testtenant
/phase0b/            — fase 0b: is het credential bruikbaar, en kan Windows onze provider aanroepen?
  Invoke-PasskeySignIn.ps1 — meldt aan bij Entra met de sleutel uit een 0a-artefact
  Invoke-ColdSignIn.ps1    — zet Chrome's Windows-SSO tijdelijk uit en draait de aanmeldtest
  Reset-Passkeys.ps1       — verwijdert alle FIDO2-methoden van een testaccount
  Test-PluginRegistration.ps1 — meet of Windows MSIX-identity eist voor een plugin-authenticator
/CLAUDE.md           — dit bestand
```

## Status

**Fase 0 loopt, nog niet afgerond — en is sinds 3 september 2026 in twee gelijkwaardig blokkerende sporen gesplitst (PRD v1.1 §11):**

- **0a — Entra/GDAP.** Twee deelvragen, los van elkaar te beantwoorden:
  1. **Formaat** — slikt Entra een `fmt: none`-attestation-object met een sleutel die nooit een authenticator is geweest? **Ja, bewezen op 4 september 2026.** Geregistreerd als `notAttested` / `synced`, en op dezelfde dag is er ook daadwerkelijk mee aangemeld (authorization code van Entra). Het credential deugt dus, en is bruikbaar.
  2. **Rechten** — kan dit via GDAP namens de gebruiker, of eist de provisioning-API dat de gebruiker het zelf doet? **Nog onbeantwoord**: de geslaagde runs gebruikten een account uit de klanttenant zelf, dus er was geen delegatie in het spel. Ook nog niet getest tegen een Global Admin, en niet met de sleutel in Key Vault.
- **0b — Windows-provider-haalbaarheid (PRD §12.1).** Roept Windows 11 een eigen `IPluginAuthenticator` daadwerkelijk aan bij een passkey-aanmelding? **Nog niet getest, maar de onbekenden zijn weg**: de interface is vier methoden met CTAP2-CBOR als wire-formaat, .NET volstaat (geen C++ nodig), en MSIX-package-identity is verplicht — dat laatste is gemeten (`APPMODEL_ERROR_NO_PACKAGE`), niet aangenomen. Wat nog gebouwd moet worden is de COM-server plus een CTAP2-CBOR-**decoder**, die er nog niet is. Er is bewust geen browserextensie-fallback — faalt dit, dan stopt het project.

**Vaste ontwerpregel, gevonden op 4 september:** de signature counter is **altijd 0**. Entra registreert deze credentials als `synced` en weigert elke andere waarde met `AADSTS135017`. Geldt ook voor de Windows-provider straks. Test daarom nooit met Chrome's virtuele authenticator — die hoogt de counter op en maakt een credential onbruikbaar.

**Geplande volgorde:** de 0b-POC (COM-server die in de Windows-providerkiezer verschijnt), daarna de resterende 0a-vragen: GDAP, Global Admin, en de Key Vault-schrijftest.

Belangrijkste tussentijdse bevinding (raakt het ontwerp): **multi-tenant + GDAP neemt de per-tenant inrichting niet weg.** Elke klanttenant heeft een eenmalige onboarding nodig (consent + service principal) voordat er iets kan via Graph — dat moet bij schaal (~300 klanten) een geautomatiseerde flow worden, geen handwerk. Zie `docs/VOORTGANG.md` §"Open vragen" punt 2 voor het beoogde onboarding-vs-steady-state-model.

Blokkerend op dit moment (geen van drie meet iets over passkeys, het is tenant-inrichting):
1. Admin consent voor de eigen app-registratie in de testtenant.
2. `Key Vault Crypto Officer`-rol op de vault (Owner op de subscription geeft geen data plane-rechten).
3. GDAP-rolset van de relatie vaststellen (Privileged Authentication Administrator nodig voor admin-doelwitten, niet Authentication Administrator).

**Afspraak: nooit vooruitbouwen op een onbeantwoorde fase.** Fase 1+ is hypothetisch totdat fase 0 rond is. Zie `docs/VOORTGANG.md` voor de volledige, actuele stand, omgevingdetails (tenant/subscription-ID's, app-registratie) en het log per sessie — dat bestand is leidend boven dit overzicht bij twijfel.

## Werkwijze

Conform de standaard MSP-werkwijze (`~/git`-CLAUDE.md): stap voor stap bouwen, na elke stap terugkoppelen en op akkoord wachten voordat verder gegaan wordt. Aanvullende, project-specifieke afspraken (vastgelegd in `docs/VOORTGANG.md`):
- Nooit tegen een omgeving uitvoeren zonder dat expliciet vaststaat welke tenant én welke subscription actief zijn — ook niet bij read-only verkenning.
- Testtenant, niet klanttenant, tot fase 0 rond is.
- Aannames (RP ID, Graph API-versie, body-vorm) expliciet als openstaand markeren in code én docs, niet hardcoderen, tot ze in fase 0 bewezen zijn.
- De handgeschreven CBOR/COSE-encoder blijft handgeschreven en getest — Tier-0-code die een auditor moet kunnen lezen, geen dependency erbij.
