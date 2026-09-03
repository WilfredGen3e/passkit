# Voortgang

Werkdocument om het project tussen sessies over te kunnen dragen. Wie hier koud instapt leest dit bestand en daarna de [PRD](PRD.md), en kan dan verder.

**Bijwerken bij elke betekenisvolle stap.** Niet als changelog van commits — die staan in git — maar als antwoord op "waar staan we en waarom".

---

## Waar we nu staan

**Fase 0, nog niet uitgevoerd.** De code om de test te doen ligt er, is nagelopen en offline gevalideerd, maar er is nog niet één keer echt tegen een tenant aan gedraaid. Daarmee is de kernvraag van het hele project onbeantwoord: accepteert Entra een passkey die nooit in een authenticator heeft gezeten?

Zolang dat zo is, is alles vanaf fase 1 hypothetisch. Niet vooruitbouwen.

De omgeving staat klaar, de parameters zijn bekend en het script heeft echt gedraaid — maar het is nog niet tot de registratie-POST gekomen. Alle tijd ging op aan toegang krijgen tot de testtenant, niet aan passkeys. Dat is geen verloren tijd: het heeft de vraag beantwoord met welke app-identiteit we een klanttenant binnenkomen, en dat antwoord raakt het ontwerp harder dan verwacht.

Hoever we kwamen: preflight geslaagd, Graph-login geslaagd met een eigen app-registratie, en toen `Request_BadRequest: Unsupported token. Unable to initialize the authorization context.` op het ophalen van het doelaccount. Vrijwel zeker omdat de app nog geen service principal in de testtenant heeft.

## De volgende stap

**Herprioritering (3 september 2026): twee losse toetsen, beide blokkerend, in deze volgorde.** Zie PRD v1.1 §11/§12/§14 voor de onderbouwing.

1. **Morgen: Key Vault-schrijftest** in de testtenant — kunnen we er een sleutel naartoe schrijven? Dit is de eenvoudigste van de twee: het opslagmodel zelf wordt niet gewantrouwd ("dat beunen we wel in elkaar"), dit ruimt vooral de bekende blokkade op (Key Vault Crypto Officer-rol ontbreekt nog, zie stap 2 hieronder).
2. **Direct daarna: minimale POC van de Windows-provider (fase 0b, PRD §12.1).** Dit was tot nu toe geformuleerd als fase 6 — een "later" traject — en dat was een verkeerde risico-inschatting. Zonder werkende `IPluginAuthenticator` heeft de rest van dit ontwerp geen gebruiksmechanisme, en er is bewust **geen browserextensie-alternatief**. De eerste versie hoeft niets van de echte flow te doen: puur bewijzen dat Windows de plugin daadwerkelijk aanroept bij een passkey-aanmelding, door een rondje te maken naar het bestaande `phase0`-PowerShell-script dat al iets naar Key Vault wegschrijft. Geen echte signing, geen credential-scoping, geen productieflow. Slaagt dit niet, dan stopt het project hier — dat weegt zwaarder dan doorwerken aan de Entra/GDAP-registratieflow (0a).

De uitgewerkte inrichtingsstappen hieronder zijn voor de volledige Entra/GDAP-registratietest (0a) en blijven nodig, maar zijn dus niet meer per se de eerstvolgende actie. Drie inrichtingsstappen, dan pas die test. Geen daarvan meet iets over passkeys.

**1. Consent voor onze eigen app in de testtenant.** Vereist Global Admin daar; via het access package is dat tijdelijk te krijgen. Een GDAP-account alleen kan het niet — dat is geprobeerd en het gaf 403.

```
https://login.microsoftonline.com/0d89711e-71b0-4e19-893a-eba5dbcf7e16/adminconsent?client_id=e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a
```

**2. Key Vault Crypto Officer** op de vault. Staat er nu niet; er is alleen Owner op de subscription en dat geeft geen data plane-rechten.

```powershell
New-AzRoleAssignment -ObjectId 9e3d0083-8ef0-40c9-82e8-f64467e96340 `
  -RoleDefinitionName 'Key Vault Crypto Officer' `
  -Scope '/subscriptions/bb23ea30-0ac7-4feb-b329-bb311d2322da/resourcegroups/rg_ssi_passkeymanager/providers/microsoft.keyvault/vaults/testpasskey'
```

**3. Stel de GDAP-rolset van de relatie vast** (Partner Center → Customers → Admin relationships). Zonder dat is een 403 straks niet te duiden.

Dan de run, in een eigen PowerShell-venster — niet vanuit de agent, want het aanmeldvenster van WAM komt daar niet naar de voorgrond:

```powershell
cd D:\Git\claudeprojects\passkeymanager\phase0
.\Invoke-Phase0Test.ps1 `
  -CustomerTenantId 0d89711e-71b0-4e19-893a-eba5dbcf7e16 `
  -UserPrincipalName ChrisG@cwtesttentant.onmicrosoft.com `
  -KeyVaultName testpasskey `
  -SubscriptionId bb23ea30-0ac7-4feb-b329-bb311d2322da `
  -ClientId e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a `
  -SkipRegistration
```

**Twee runs, niet één.** Eerst tegen een gewone testgebruiker, daarna tegen een testgebruiker met Global Admin. Voor auth-methoden van een admin-account is Privileged Authentication Administrator nodig in plaats van Authentication Administrator, en dat is het scenario dat in productie geldt. Een geslaagde run tegen een gewone gebruiker bewijst dus minder dan hij lijkt te bewijzen.

**Overweeg de formaatvraag los te trekken met tijdelijk GA.** Ben je toch al GA via het access package, draai de echte registratie dan één keer in die hoedanigheid. Dan is de rechtenvraag geen variabele meer en meet je puur of Entra het credentialformaat slikt — de vraag waar het hele project op staat of valt. Elke 403 daarna is dan gegarandeerd een rollenprobleem en geen formaatprobleem.

### Omgeving

| | |
|---|---|
| Testtenant | `0d89711e-71b0-4e19-893a-eba5dbcf7e16`, benaderd via GDAP |
| Testgebruiker | `ChrisG@cwtesttentant.onmicrosoft.com` (nog zonder adminrol) |
| App-registratie | `e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a`, multi-tenant, public client, delegated |
| Key Vault | `testpasskey`, RG `rg_ssi_passkeymanager`, subscription `bb23ea30-0ac7-4feb-b329-bb311d2322da` (MSDN), RBAC-modus |
| Az-account | `s.siemerink@connectworks.nl`, objectId `9e3d0083-8ef0-40c9-82e8-f64467e96340` |

Twee losse logins met twee verschillende accounts: Az met het MSDN-account naar de subscription, Graph met het partner-account naar de testtenant. Tenant en subscription hangen hier niet aan elkaar; het script koppelt ze ook nergens en toetst alleen de subscription.

Dat de vault in een MSDN-subscription staat is voor fase 0 niet bezwaarlijk: Entra ziet alleen de publieke sleutel, dus de tier van de vault raakt de uitkomst niet. De tierkeuze zelf is PRD §14.2.

De app-registratie heeft deze redirect URI's nodig, alle drie, onder *Mobile and desktop applications*, en public client flows aan:

```
http://localhost
https://login.microsoftonline.com/common/oauth2/nativeclient
ms-appx-web://Microsoft.AAD.BrokerPlugin/e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a
```

Die laatste is hoofdlettergevoelig.

## Wat er ligt

| Onderdeel | Staat | Opmerking |
|---|---|---|
| PRD | vastgesteld | v1.0, [docs/PRD.md](PRD.md) |
| CBOR/COSE-encoder | werkt | `phase0/PasskeyManager.Phase0.psm1`, handgeschreven, geen dependencies |
| Encodertest | slaagt | `phase0/Test-Encoding.ps1`, 30 controles, draait offline |
| Fase 0-testscript | draait tot Graph | `phase0/Invoke-Phase0Test.ps1` — preflight en login werken; strandt op het ophalen van het doelaccount |
| App-registratie | aangemaakt | `e3fb0cfc-…` in de partnertenant, multi-tenant, delegated, drie redirect URI's |
| Consent in de testtenant | ontbreekt | de app heeft daar nog geen service principal — dit blokkeert nu alles |
| Key Vault-rechten | ontbreken | Crypto Officer nog niet toegekend |
| Alles vanaf fase 1 | niets | wacht op de uitkomst van fase 0 |

## Wat we onderweg zijn tegengekomen

Dingen die geld of tijd kosten als iemand ze opnieuw moet ontdekken.

- **PowerShell parseert `0xFFFFFFFF` als Int32 `-1`.** Kostte de CBOR-encoder stilzwijgend de 4-byte-tak: alles boven 65535 werd als 8 bytes gecodeerd. Opgelost door grenswaarden expliciet als `[uint64]` te schrijven. Precies het soort fout dat bij Entra terugkomt als een nietszeggende HTTP 400 — vandaar dat de encodertest bestaat.
- **`Guid.ToByteArray()` is mixed-endian.** WebAuthn wil de AAGUID zoals de GUID geschreven staat. Zonder omkering staat er een andere AAGUID in het credential dan op de allowlist, en dat valt pas bij rapportage op. Afgevangen in `ConvertTo-AaguidBytes`, met een test erop.
- **EC-coördinaten kunnen korter dan 32 bytes terugkomen** uit Key Vault als ze toevallig met een nulbyte beginnen. Een COSE-sleutel met een 31-byte X wordt afgekeurd. Treedt bij ongeveer 1 op de 256 sleutels op, dus zonder onvoorwaardelijke normalisatie is dit een fout die pas in productie opduikt.
- **Key Vault tekent ES256 als raw `r || s`,** WebAuthn wil ASN.1 DER in een assertion. Raakt fase 5, staat genoteerd in de fase 0-leesmij.
- **Sleutelbeperkingen in het FIDO2-beleid vervuilen de fase 0-uitkomst.** Staan ze aan, dan geldt er een AAGUID-allowlist en wordt onze placeholder geweigerd met een 400 die op een formaatfout lijkt. Uit laten tijdens de test.
- **Twee rollen voor auth-methoden, niet één.** Authentication Administrator werkt alleen voor niet-admins; voor een admin-doelwit is Privileged Authentication Administrator vereist. Omdat we in productie op Global Admins mikken, is dat de rol die telt — en een zware om over 300 tenants te houden.
- **Graph PowerShell komt een klanttenant niet zomaar in.** `Connect-MgGraph -TenantId <klant>` geeft *not authorized in the tenant*: het service principal van Microsoft Graph Command Line Tools (`14d82eec-204b-4c2f-b7e8-296a70dab67e`) bestaat daar niet. Dat is app-inrichting en staat los van de GDAP-rechtenvraag van fase 0 — makkelijk te verwarren, want beide melden zich als een autorisatiefout.
- **En met een GDAP-account krijg je dat niet opgelost.** De consent-URL werkte niet, en het service principal aanmaken via `Invoke-AzRestMethod` op `/servicePrincipals` gaf 403: de GDAP-relatie bevat geen rol die apps mag beheren. Dit is geen randgeval maar een structureel gegeven, en het maakt de eigen multi-tenant app-registratie (zie open vraag 2) de enige werkbare route in plaats van alleen de nettere.
- **Multi-tenant zijn neemt de per-tenant inrichting níet weg.** Met een eigen multi-tenant app kwamen we wel door de aanmelding, maar Graph gaf daarna `Request_BadRequest: Unsupported token. Unable to initialize the authorization context.` — de app heeft in de klanttenant geen service principal en dus geen autorisatiecontext. Elke klanttenant heeft dus een eenmalige onboarding nodig; GDAP slaat die stap niet over. Over 300 tenants is dat een geautomatiseerde onboardingflow, geen handwerk.
- **Een redirect URI-fout bewijst niets over de klanttenant.** Die validatie gebeurt tegen de app-registratie in de partnertenant. Tijdens deze sessie is dat signaal eerst verkeerd gelezen als bewijs dat de app in de klanttenant bekend was; dat is het niet.
- **Redirect URI's zijn hoofdlettergevoelig.** `ms-appx-web://Microsoft.AAD.BrokerPlugin/<clientId>` met exact die schrijfwijze, anders `AADSTS50011`. Neem de string altijd letterlijk uit de foutmelding over.
- **Owner op de subscription geeft geen Key Vault data plane-rechten.** Bij een vault in RBAC-modus zie je de vault wel maar mag je er geen sleutel in aanmaken. Er is `Key Vault Crypto Officer` op de vault zelf nodig. De preflight controleerde dit aanvankelijk niet en gaf dus groen licht op een run die later alsnog zou stranden; inmiddels gerepareerd.
- **Het WAM-aanmeldvenster is onbruikbaar vanuit een agent-sessie.** Het opent achter de terminal en wordt na 120 seconden afgebroken met *User canceled authentication*. Draai het script in een eigen PowerShell-venster, of gebruik `-UseDeviceCode`. Device code heeft ook maar 120 seconden, dus zet de aanmeldpagina van tevoren open.
- **Een magere GDAP-rolset geeft hetzelfde antwoord als een mislukte fase 0.** Zit Privileged Authentication Administrator niet in de relatie, dan faalt de registratie met 403 en noteert het script dat het GDAP-pad niet werkt — terwijl er niets over passkeys bewezen is. Stel de rolset van de relatie dus vast *voordat* je conclusies aan een 403 verbindt.

## Open vragen, in volgorde van belang

1. **Fase 0-uitkomst** — beide deelvragen, zie PRD §14.1. Blokkeert al het overige.
2. **Hoe onboarden we een klanttenant, en hoe draait het daarna onbeheerd?** De feiten staan inmiddels vast: Graph PowerShell komt er niet in, een GDAP-account mag geen apps inrichten, en ook een eigen multi-tenant app heeft per klanttenant een service principal nodig. Er is dus onvermijdelijk een eenmalige onboardingstap met verhoogde rechten, gevolgd door een steady state.

   Het beoogde model, nog te verifiëren:

   | | |
   |---|---|
   | Onboarding, één keer per klant | delegated via GDAP met tijdelijke verhoging, geautomatiseerd — consent + roltoewijzing aan het service principal |
   | Productie, dagelijks | app-only client credentials, geen mens in de lus |

   Twee dingen die dat model kunnen breken en die uitgezocht moeten worden: of `UserAuthenticationMethod.ReadWrite.All` als **application**-permissie ook auth-methoden van *privileged* accounts mag wijzigen — Microsoft beperkt dat en wij mikken juist op Global Admins — en of het service principal daarvoor zelf Privileged Authentication Administrator toegewezen moet krijgen. Dat is dezelfde rolvraag als §14.3, maar dan voor een app in plaats van een engineer.

   Voor fase 0 bewust delegated houden: vraag 2 gaat er juist over of een engineer dit via GDAP mág, en met app-only meet je dat niet.
3. **Graph API-versie en body-vorm** — het script gaat uit van `beta` en van `publicKeyCredential.response.{clientDataJSON,attestationObject}`. Niet geverifieerd; valt uit fase 0 te leren.
4. **Key Vault-tier** — Premium per sleutel per maand versus Managed HSM vast tarief, bij 1000–2000 sleutels. Ook sleutel- en throttlinglimieten per vault, zo nodig sharden. PRD §14.2.
5. **GDAP-rolkeuze** per klanttenant voor de registratieflow. PRD §14.3. Hangt samen met 2: de rolset van de relatie bepaalt óók of we er überhaupt een app in kunnen zetten.
6. De rest van PRD §14.

## Afspraken over dit project

- **Windows-provider-haalbaarheid (0b) is een gate, geen fase-6 nice-to-have.** Er is bewust geen browserextensie-fallback: als die route niet werkt, heeft doorbouwen weinig zin. Zie PRD v1.1 §11/§12.
- **Nooit vooruitbouwen op een onbeantwoorde fase.** De fasering in PRD §11 is bewust zo gesneden dat elke fase de volgende rechtvaardigt.
- **Testtenant, niet klanttenant**, tot fase 0 rond is. En: tenant en subscription staan expliciet vast voordat er iets uitgevoerd wordt, ook bij read-only verkenning.
- **Aannames markeren in plaats van hardcoderen.** RP ID, API-versie en body-vorm staan nu als expliciet openstaand in de code en de leesmij; dat zo houden tot ze bewezen zijn.
- De handgeschreven encoder blijft handgeschreven en getest. Een dependency erbij is verleidelijk maar dit is Tier-0-code die door een auditor gelezen moet kunnen worden.

---

## Log

### 3 september 2026 — herprioritering
- Besloten: Windows-provider-haalbaarheid is geen fase 6 meer maar fase 0b, gelijkwaardig blokkerend aan de Entra/GDAP-vraag (0a). Reden: er is bewust geen browserextensie-alternatief, dus zonder werkende Windows-provider heeft het project geen manier om passkeys daadwerkelijk te gebruiken.
- Geplande volgorde: Key Vault-schrijftest in de testtenant, direct gevolgd door een minimale POC van de Windows-provider die alleen aantoont dat Windows de plugin aanroept (rondje naar het bestaande `phase0`-script), nog geen productieflow.
- PRD bijgewerkt naar v1.1 (§11, §12, §14) om dit te reflecteren.

### 19 augustus 2026
- Repo `WilfredGen3e/passkeymanager` was leeg; ingericht met PRD als eerste commit.
- PRD v1.0 vastgelegd. Twee aanpassingen ten opzichte van het aangeleverde concept: fase 0 gesplitst in een formaat- en een rechtenvraag (§7, §11, §14.1), en de `BE`/`BS`-keuze toegelicht in §13 omdat "synced" hier iets anders betekent dan gebruikelijk.
- Fase 0-code geschreven: encoder, offline test (30 controles, slagen), en het testscript tegen Key Vault en Graph.
- Nog niet gedraaid tegen een tenant.

### 19 augustus 2026 (vervolg)
- Testtenant beschikbaar. Voorwaardenlijst uitgewerkt in de fase 0-leesmij; twee voorwaarden waren nog niet in beeld: sleutelbeperkingen uit, en het onderscheid tussen Authentication Administrator en Privileged Authentication Administrator.
- Script uitgebreid met een preflight (Az-context, modules, bereikbaarheid van de vault) zodat een misconfiguratie faalt vóórdat er een challenge opgehaald is, en met opruimen van de sleutel als de registratie mislukt.
- Script leest nu de adminrollen van het doelaccount uit en noteert daarmee welk van de twee rolscenario's er getest is.

### 19 augustus 2026 (einde dag)
- Testtenant en Key Vault staan klaar. Er is nog niets gedraaid: bij de eerste poging bleek de actieve Az-context op een klant-PROD-subscription te staan, en dat is precies het ongeluk dat we niet willen.
- Daarom `-SubscriptionId` verplicht gemaakt: het script weigert nu te draaien als de actieve context een andere subscription is dan opgegeven. Pakken wat er toevallig actief is, is voor dit soort code geen aanvaardbaar gedrag.
- Graph-sessie wordt hergebruikt als die al op de goede tenant staat; scheelt een browserprompt per run.
- **Deze twee wijzigingen zijn niet meer gecontroleerd.** Geen syntaxcheck, geen encodertest gedraaid. Morgen mee beginnen.
- Werkafspraak aangescherpt: niets uitvoeren tegen een omgeving zonder dat expliciet vaststaat welke tenant en welke subscription. Dat geldt ook voor read-only verkenning.

### 19 augustus 2026 (avond) — eerste echte runs

Het script heeft voor het eerst tegen een tenant gedraaid. Het is niet tot de registratie-POST gekomen: de hele avond ging op aan toegang krijgen. Dat leverde wel het antwoord op een vraag die we nog niet gesteld hadden.

- Openstaande wijzigingen van gisteren gecontroleerd: syntax schoon, encodertest slaagt (30 controles).
- Bij het nalopen vier gebreken gevonden en gerepareerd. Het zwaarste: een hergebruikte Graph-sessie werd alleen op tenant getoetst en niet op scopes, waardoor een 403 op de registratie uitgelegd zou worden als "het GDAP-pad werkt niet" terwijl het aan de sessie lag. Verder werd bij een fout alleen de exception message bewaard en niet de response body, waar bij een 400 juist de reden in staat.
- Omgeving vastgesteld: testtenant, testgebruiker, app-registratie, Key Vault. Zie *Omgeving* hierboven.
- **Toegang tot de klanttenant bleek de eigenlijke horde.** Achtereenvolgens: Graph PowerShell is niet bekend in de tenant → consent-URL werkt niet met een GDAP-account → service principal aanmaken via de Az-app geeft 403 → eigen multi-tenant app gemaakt → redirect URI's ontbraken → hoofdlettergevoeligheid → login geslaagd → en dan alsnog *Unsupported token, unable to initialize the authorization context*, want ook die app heeft in de klanttenant geen service principal.
- **Conclusie daaruit, en die is ontwerprelevant:** multi-tenant zijn plus GDAP neemt de per-tenant inrichting niet weg. Elke klanttenant heeft een eenmalige onboarding nodig met verhoogde rechten. Over 300 tenants moet dat een geautomatiseerde flow worden. Opgenomen als open vraag 2, inclusief het onderscheid tussen onboarding (delegated) en steady state (app-only).
- Preflight gerepareerd: die controleerde de vault met een management-call en gaf daarmee groen licht terwijl `Key Vault Crypto Officer` ontbrak. Owner op de subscription geeft geen data plane-rechten. Nu een echte data plane-call, met een foutmelding die de juiste rol noemt.
- `-UseDeviceCode` toegevoegd. Het WAM-venster komt vanuit een agent-sessie niet naar de voorgrond en breekt na 120 seconden af. Praktische les: **draai het script in een eigen PowerShell-venster**, niet vanuit de agent.
- Een eerdere gevolgtrekking in deze sessie was fout en is gecorrigeerd: een redirect URI-fout werd gelezen als bewijs dat de app in de klanttenant bekend was. Die validatie gebeurt in de partnertenant en zegt daar niets over.
