# Voortgang

Werkdocument om het project tussen sessies over te kunnen dragen. Wie hier koud instapt leest dit bestand en daarna de [PRD](PRD.md), en kan dan verder.

**Bijwerken bij elke betekenisvolle stap.** Niet als changelog van commits — die staan in git — maar als antwoord op "waar staan we en waarom".

---

## Waar we nu staan — de passkey werkt end-to-end (4 september 2026, avond)

**Een volledig in software gemaakte passkey meldt een echt Entra-account aan.** Daarmee is de vraag die 's middags openbleef — Entra accepteerde het credential bij registratie, maar is het ook bruikbaar? — beantwoord met ja.

```
[passkit] GET AANGEROEPEN, mediation=conditional, rpId=login.microsoft.com
[passkit] ASSERTION GEZET, signCount=0, sig 70 bytes
AANGEMELD. Entra accepteerde de assertion van het 0a-credential.
eind-URL: https://myaccount.microsoft.com/#code=1.AV0AHnGJDbBxGU6JOuul289-Ftf…
```

Die `#code=` is een echte authorization code: Entra heeft de handtekening gevalideerd tegen de publieke sleutel die het bij registratie opsloeg, en `ChrisG@cwtesttentant.onmicrosoft.com` aangemeld.

Gemeten met `phase0b/Invoke-PasskeySignIn.ps1`. Dat script vervangt in de pagina `navigator.credentials.get` door een eigen implementatie die `authenticatorData` opbouwt en met WebCrypto tekent met de sleutel uit het fase 0a-artefact. Geen Windows-provider, geen MSIX, geen KeePass — die zijn voor het *gebruiksmechanisme* nodig, niet om te bewijzen dat het credential deugt.

### Wat dit vaststelt, en het raakt het ontwerp

- **De signature counter moet 0 blijven.** Entra registreert deze credentials als `synced` en weigert elke opgehoogde teller met `AADSTS135017` ("Unexpected Signature Counter"). Dat is conform de FIDO-richtlijn voor multi-device credentials: over gesynchroniseerde kopieën is een teller niet coherent bij te houden. **De PassKit-provider moet hier altijd 0 sturen.** Hoort in PRD §13 naast de BE/BS-keuze.
- **Er komt geen prompt, en dat is normaal.** Entra vraagt de passkey op met `mediation: conditional` — autofill. Geen knop, geen keuze, direct binnen. Relevant voor het gebruiksontwerp van de Windows-provider: een providerkeuze krijg je alleen als Windows weet dát er een provider is.
- **RP ID en origin verschillen.** RP ID is `login.microsoft.com`, maar de ceremonie draait op `login.microsoftonline.com` of `login.live.com`. Dat is toegestaan via `.well-known/webauthn` (WebAuthn Related Origin Requests). `login.microsoft.com` zelf redirect en is dus geen bruikbare origin — een testpagina daar krijgt een `SecurityError`.
- **De vlaggen kloppen in de assertion.** `0x1D` — UP, UV, BE, BS — consistent met de `0x5D` waarmee 0a registreerde.

### Wat dit níet bewijst

| Vraag | Stand |
|---|---|
| Is het credential bruikbaar om mee aan te melden? | **ja**, bewezen |
| Remote signing: tekent Key Vault snel genoeg binnen de ceremonie? | **onbeantwoord** — de sleutel stond hier lokaal; niemand op GitHub doet dit, dit blijft projectspecifiek |
| Roept Windows een eigen provider aan? | **onbeantwoord** — fase 0b, zie hieronder |
| Werkt registratie via GDAP / tegen een Global Admin? | **onbeantwoord**, ongewijzigd |

### Twee valkuilen die tijd hebben gekost

- **Chrome's virtuele authenticator is voor dit project onbruikbaar.** Die hoogt de signature counter altijd op en dat is via het DevTools-protocol niet uit te zetten (de `VirtualAuthenticatorOptions` kennen geen counter-instelling). Eén testrun heeft daarmee een credential onbruikbaar gemaakt: Entra weigerde daarna ook counter 0 als terugval. Gebruik de eigen assertion-implementatie, niet `WebAuthn.addVirtualAuthenticator`.
- **Op dit beheerwerkstation neemt de browser-SSO de aanmelding over.** De machine is Entra-joined en het eigen account heeft via GDAP toegang tot de testtenant, dus Chrome levert de Primary Refresh Token en Entra meldt gewoon de engineer aan — ook met `prompt=login` en een `login_hint` voor iemand anders. Tijdelijk te omzeilen met de Chrome-beleidswaarde `CloudAPAuthEnabled = 0` onder `HKCU\Software\Policies\Google\Chrome`; `phase0b/Invoke-ColdSignIn.ps1` zet die en draait hem in een `finally` weer terug.

---

## Registratie: de kernvraag is beantwoord (4 september 2026, middag)

**Entra accepteert een passkey die nooit in een authenticator heeft gezeten.** De registratie is geslaagd tegen de testtenant, met een sleutel die in software is gegenereerd en die alleen in een lokaal bestand bestaat.

```
id               : Xd-q6r1BdYMX35ikRUkK66uS9jF7ZWEnfG9dJWBJMko1
displayName      : PassKit fase 0-test
attestationLevel : notAttested
passkeyType      : synced
aaGuid           : 00000000-0000-0000-0000-000000000000
```

Drie dingen die dit meteen vaststelt:

- **Attestation `none` wordt geaccepteerd terwijl de tenant `direct` vraagt.** De aanname uit PRD §4.3 klopt: een RP kan niet afdwingen wat een authenticator teruggeeft. Entra noteert het als `notAttested`.
- **Entra classificeert het credential als `synced`.** Dat is precies wat de BE/BS-vlaggen uit PRD §13 beogen, nu bevestigd in plaats van beredeneerd (flags `0x5D`).
- **Een AAGUID van louter nullen wordt zonder morren geslikt.** Zolang sleutelbeperkingen uit staan is de AAGUID advisory, zoals verwacht.

**Wat hiermee nog níet bewezen is** — en dit is belangrijker dan het lijkt, want het is verleidelijk om fase 0 nu af te vinken:

| Vraag | Stand |
|---|---|
| Slikt Entra het formaat? | **ja**, bewezen |
| Werkt het met alleen GDAP-rechten? | **onbeantwoord** — deze run gebruikte `cwadmin@cwtesttentant.onmicrosoft.com`, een account uit de klanttenant zelf. Er was geen delegatie in het spel. |
| Werkt het tegen een Global Admin? | **onbeantwoord** — `ChrisG` heeft geen adminrollen. In productie mikken we juist op GA's, en dan is Privileged Authentication Administrator vereist. |
| Werkt het met de sleutel in Key Vault? | **onbeantwoord** — die modus is nog niet gedraaid. |

De eerste kolom is de vraag waar het project op stond of viel. Die is beantwoord met ja. De rest is nu wél de moeite van het uitzoeken waard — daarvóór was het dat niet.

---

## De volgende stap

Nu het formaat bewezen is, valt 0a uiteen in drie resterende toetsen. Ze zijn alle drie goedkoop geworden: de inrichting staat, het script werkt, en elke run is nog een paar minuten.

1. **Tegen een Global Admin.** Maak een testaccount Global Admin en draai opnieuw. Dit is het scenario dat in productie geldt en het vraagt Privileged Authentication Administrator in plaats van Authentication Administrator. Doe deze eerst — hij kan nog roet in het eten gooien.
2. **Met het partner-account via GDAP.** Dezelfde run, maar aangemeld als `s.siemerink@connectworks.nl` tegen de testtenant. Dit is PRD §14.1 vraag 2, en de enige die nog echt open is voor het ontwerp.
3. **Met de sleutel in Key Vault.** `-KeyVaultName` in plaats van `-LocalKey`. Hiervoor is de `Key Vault Crypto Officer`-rol alsnog nodig (zie hieronder). Laag risico: het enige verschil is waar X en Y vandaan komen.

Daarna:

4. **Minimale POC van de Windows-provider (fase 0b, PRD §12.1).** Dit was tot nu toe geformuleerd als fase 6 — een "later" traject — en dat was een verkeerde risico-inschatting. Zonder werkende `IPluginAuthenticator` heeft de rest van dit ontwerp geen gebruiksmechanisme, en er is bewust **geen browserextensie-alternatief**. De eerste versie hoeft niets van de echte flow te doen: puur bewijzen dat Windows de plugin daadwerkelijk aanroept bij een passkey-aanmelding, door een rondje te maken dat naar een **tekstbestand of logregel** wegschrijft — nadrukkelijk **geen Key Vault-call** in deze POC. Dat isoleert de vraag: 0b test alleen of Windows de plugin aanroept, niet of Key Vault-rechten kloppen (dat is de aparte schrijftest hierboven). Voor de productieversie (fase 6) wordt de tekstbestand-stand-in vervangen door de echte Key Vault-aanroep — dat is dan een geïsoleerde, laag-risico vervolgstap, geen onderdeel van deze POC. Slaagt de POC niet, dan stopt het project hier — dat weegt zwaarder dan doorwerken aan de Entra/GDAP-registratieflow (0a).

   **Verkenning gedaan op 4 september; de onbekenden zijn weg, de bouw niet.** Wat we nu weten:

   | | |
   |---|---|
   | `IPluginAuthenticator` | vier methoden — `MakeCredential`, `GetAssertion`, `CancelOperation`, `GetLockStatus`. IID `d26bcf6f-b54c-43ff-9f06-d5bf148625f7`. Wire-formaat is CTAP2-CBOR |
   | C++ verplicht? | **nee** — de plugin-API is vanuit .NET aan te roepen; bewezen met P/Invoke, en `yusei36/KeePassPasskey` doet het volledig in C# |
   | MSIX package identity | **verplicht** — gemeten, niet aangenomen: `WebAuthNPluginAddAuthenticator` vanuit een onverpakt proces geeft `APPMODEL_ERROR_NO_PACKAGE` (0x80073D54). Zie `phase0b/Test-PluginRegistration.ps1` |
   | Registratie zonder `makeappx`/`signtool`/certificaat | kan, met `Add-AppxPackage -Register` op een losse map — vereist wel **ontwikkelaarsmodus** (anders `0x80073CFF`) |
   | Compiler | geen .NET SDK nodig; Windows PowerShell 5.1 heeft nog de CodeDom-compiler en maakt een .NET Framework-exe |
   | API-generatie | op build 26200 bestaan twee sets naast elkaar: de `EXPERIMENTAL_`-set (waar het Contoso-sample en de publieke documentatie op leunen) én een gestabiliseerde set zonder prefix, met `2`-varianten. Bouw op de laatste |
   | TPM | verplicht, en dat is functioneel: Windows maakt een TPM-backed sleutel en **ondertekent elk verzoek dat het aan de plugin geeft**. De plugin verifieert met `WebAuthNPluginGetOperationSigningPublicKey`. Een aanroep die binnenkomt is dus aantoonbaar van Windows en door de gebruiker goedgekeurd — dat versterkt "UV per handeling" uit het kernontwerp |

   Daarmee is de inschatting van 6–9 maanden uit PRD §12.2 (C++/COM/WinUI 3 vanaf nul) vermoedelijk te pessimistisch voor de plugin-kant. Wat nog echt gebouwd moet worden: een **CTAP2-CBOR-decoder** — de encoder in `phase0/` heeft er geen, en mist bovendien nog een array- en boolean-tak (majortype 4, simple values 20/21).

   `yusei36/KeePassPasskey` is bruikbaar als naslag voor de API-vorm, maar staat onder **GPL-3.0**: code overnemen kan niet zonder die verplichtingen. De headers van Microsoft zelf (`microsoft/webauthn`) zijn MIT, en daar binden we feitelijk tegenaan.

### Inrichting

**Consent voor onze app in de testtenant: gedaan.** Dit was de blokkade van 19 augustus en hij is weg. De service principal bestaat nu; de aanmelding met `-ClientId e3fb0cfc-…` werkt. De URL, mocht hij voor een volgende tenant nodig zijn:

```
https://login.microsoftonline.com/<tenant>/adminconsent?client_id=e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a
```

**Doelgroep van het passkey-beleid: opgelost.** De eerste registratiepoging faalde met `error_user_group_restriction_policy_failure` omdat `ChrisG` niet in de doelgroep van het beleid viel. Dat is geen randgeval maar een inrichtingsstap per tenant, en die hoort in de onboardingflow van open vraag 2.

**Key Vault Crypto Officer** op de vault — pas nodig voor toets 3 hierboven. Staat er nu niet; er is alleen Owner op de subscription en dat geeft geen data plane-rechten.

```powershell
New-AzRoleAssignment -ObjectId 9e3d0083-8ef0-40c9-82e8-f64467e96340 `
  -RoleDefinitionName 'Key Vault Crypto Officer' `
  -Scope '/subscriptions/bb23ea30-0ac7-4feb-b329-bb311d2322da/resourcegroups/rg_ssi_passkeymanager/providers/microsoft.keyvault/vaults/testpasskey'
```

**Stel de GDAP-rolset van de relatie vast** (Partner Center → Customers → Admin relationships) vóór toets 2. Zonder dat is een 403 niet te duiden. Uit de Graph-documentatie volstaan Global Reader, Authentication Administrator of Privileged Authentication Administrator.

### De run

In een eigen PowerShell-venster — niet vanuit de agent, want het aanmeldvenster komt daar niet naar de voorgrond. Interactief aanmelden werkt; `-UseDeviceCode` is alleen nodig als er geen venster naar voren kan komen.

```powershell
cd D:\Git\claudeprojects\passkit\phase0
.\Invoke-Phase0Test.ps1 `
  -CustomerTenantId 0d89711e-71b0-4e19-893a-eba5dbcf7e16 `
  -UserPrincipalName <doelaccount> `
  -LocalKey `
  -ClientId e3fb0cfc-8a8a-4a5c-aa18-fc9aaa016a8a
```

Voeg `-SkipRegistration` toe om alles op te bouwen zonder te registreren. Let bij elke run op de regel `ingelogd als … tegen tenant …`: met welk account je aanmeldt bepaalt wat de run bewijst, en dat is makkelijk over het hoofd te zien.

**Ruim geregistreerde credentials op** als je herhaald test — ze stapelen op bij het doelaccount. Het methode-ID staat in het artefactbestand onder `entra.methodId`:

```powershell
Remove-MgUserAuthenticationFido2Method -UserId <upn> -Fido2AuthenticationMethodId <id>
```

### Omgeving

| | |
|---|---|
| Testtenant | `0d89711e-71b0-4e19-893a-eba5dbcf7e16`, benaderd via GDAP |
| Testgebruiker (doelwit) | `ChrisG@cwtesttentant.onmicrosoft.com` (nog zonder adminrol), in de doelgroep van het passkey-beleid |
| Aanmeldaccount | `cwadmin@cwtesttentant.onmicrosoft.com` — uit de klanttenant zelf, dus **geen** GDAP-delegatie |
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
| Fase 0-testscript | werkt | `phase0/Invoke-Phase0Test.ps1` — registreert een credential bij Entra |
| `-LocalKey`-modus | werkt | sleutel lokaal, geen Azure; end-to-end gebruikt voor een geslaagde aanmelding |
| Credential-artefact | werkt | `results/credential-<timestamp>.json`, de overdracht naar 0b |
| App-registratie | aangemaakt | `e3fb0cfc-…` in de partnertenant, multi-tenant, delegated, drie redirect URI's |
| Consent in de testtenant | **gedaan** | service principal bestaat; aanmelden met `-ClientId` werkt |
| Registratie bij Entra | **geslaagd** | software-gegenereerd credential geaccepteerd, `notAttested`, `synced` |
| Aanmelden met het credential | **geslaagd** | `phase0b/Invoke-PasskeySignIn.ps1`; Entra gaf een authorization code |
| Passkeys opruimen | werkt | `phase0b/Reset-Passkeys.ps1` — alle FIDO2-methoden van een testaccount weg |
| Plugin-API-verkenning | gedaan | `phase0b/Test-PluginRegistration.ps1` — meet of MSIX-identity vereist is |
| Windows-provider (0b) | **niets gebouwd** | onbekenden weg, COM-server nog te schrijven; wacht op ontwikkelaarsmodus |
| Key Vault-rechten | ontbreken | Crypto Officer nog niet toegekend — blokkeert 0a niet meer sinds `-LocalKey` |
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
- **Er bestond al een werkende implementatie, en we hadden er eerder naar moeten kijken.** `DSInternals.Passkeys` (Michael Grafnetter) registreert passkeys namens andere gebruikers in Entra via precies dezelfde Graph-endpoints. Dat beantwoordt onze rechtenvraag grotendeels en levert een bewezen request-vorm. Het beantwoordt de formaatvraag *niet* — de module gebruikt de Windows WebAuthn-API en dus een echte authenticator. Zoek bij een volgende blokkade eerst of iemand het pad al gelopen heeft; dat had hier dagen gescheeld.
- **De fido2-provisioning-API is GA op `v1.0`.** Het script stond nog op `beta`. Met één verschil dat een run stilletjes sloopt: `challengeTimeoutInMinutes` bestaat alleen in beta, v1.0 hanteert een vaste time-out van vijf minuten en weigert de parameter.
- **`clientDataJson`, niet `clientDataJSON`.** Zo staat het in het Graph-contract. Waarschijnlijk hoofdletterongevoelig, maar "waarschijnlijk" is precies wat je bij het duiden van een 400 niet wilt hoeven uitsluiten.
- **Drie beleidsoorzaken geven een 400 die op een formaatfout lijkt.** "Allow self-service setup" uit (door Microsoft als *known issue* van deze API gedocumenteerd), het doelaccount buiten de doelgroep van het FIDO2-beleid ("User or group restriction policy failed"), en sleutelbeperkingen aan. Alle drie zouden ten onrechte gelezen worden als "Entra weigert ons credential" — de conclusie waar het hele project op hangt. Het script herkent de eerste twee nu in de response en zet de formaatconclusie dan op onbekend.
- **Zelfregistratie wordt door deze API niet ondersteund.** Testen tegen je eigen account werkt dus per definitie niet; het moet altijd namens een ander.
- **Er is een fijnmazige scope**, `UserAuthMethod-Passkey.ReadWrite.All`, naast de brede `UserAuthenticationMethod.ReadWrite.All`. Voor de onboardingflow over 300 tenants (open vraag 2) is dat de makkelijkere consent-vraag.
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
- **De signature counter is altijd 0.** Vastgesteld op 4 september: Entra weigert elke andere waarde op een credential dat als `synced` geregistreerd staat. Geldt voor de registratie én voor elke assertion, en dus ook voor de Windows-provider straks.
- **Niet testen met Chrome's virtuele authenticator.** Die hoogt de counter op en maakt daarmee credentials onbruikbaar. Gebruik `phase0b/Invoke-PasskeySignIn.ps1`, dat de assertion zelf zet.

---

## Log

### 4 september 2026 (avond) — aanmelden gelukt, en de plugin-API verkend

- **Aangemeld bij Entra met het 0a-credential.** Zie *Waar we nu staan*. Daarmee is de bruikbaarheidsvraag beantwoord, niet alleen de registratievraag.
- **`AADSTS135017` uitgezocht.** Kostte de meeste tijd van de avond. De counter moet 0 blijven; Chrome's virtuele authenticator kan dat niet en heeft er een credential mee gesloopt. Alle drie de toen bestaande credentials zijn daarna weggegooid en er is één verse geregistreerd.
- **Twee meetfouten van mijn kant, allebei relevant om te onthouden.** De eerste: succes werd afgelezen aan een vlag op het `window`-object, en die verdwijnt bij elke navigatie — drie geslaagde runs zagen er daardoor uit als mislukt. Nu wordt er op console-events via CDP gemeten, die blijven wél staan. De tweede: de aanmelding leek door de browser-SSO van het eigen account te komen, terwijl het in werkelijkheid de passkey was die via `mediation: conditional` stil werd afgehandeld.
- **Plugin-authenticator-API verkend** (zie *De volgende stap* punt 4). Belangrijkste harde uitkomst: MSIX-package-identity is verplicht — gemeten met `phase0b/Test-PluginRegistration.ps1`, niet afgeleid uit hoe anderen het doen.
- **`yusei36/KeePassPasskey` gevonden**: een werkende, in de Microsoft Store gepubliceerde Windows passkey-provider, volledig in C#. Bruikbaar als naslag voor de API-vorm; GPL-3.0, dus geen code overnemen.
- Nieuw in `phase0b/`: `Invoke-PasskeySignIn.ps1`, `Reset-Passkeys.ps1`, `Test-PluginRegistration.ps1`, `Invoke-ColdSignIn.ps1`. `Export-ToKeePass.ps1` was de KeePass-omweg en is niet meer nodig.

### 3 september 2026 — herprioritering
- Besloten: Windows-provider-haalbaarheid is geen fase 6 meer maar fase 0b, gelijkwaardig blokkerend aan de Entra/GDAP-vraag (0a). Reden: er is bewust geen browserextensie-alternatief, dus zonder werkende Windows-provider heeft het project geen manier om passkeys daadwerkelijk te gebruiken.
- Geplande volgorde: Key Vault-schrijftest in de testtenant, direct gevolgd door een minimale POC van de Windows-provider die alleen aantoont dat Windows de plugin aanroept (rondje naar een tekstbestand, bewust géén Key Vault-call — dat houdt de Windows/COM-vraag los van de Azure-RBAC-vraag), nog geen productieflow.
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

### 4 september 2026 — Key Vault uit fase 0, en bestaand werk gevonden

Geen run tegen de tenant gedaan; wel is de opzet van 0a op twee punten wezenlijk veranderd, allebei omdat er informatie boven tafel kwam die er eerder al had kunnen zijn.

- **Key Vault is uit fase 0 gehaald.** Het script heeft een `-LocalKey`-modus gekregen die de EC P-256-sleutel lokaal genereert met `System.Security.Cryptography.ECDsa` en Azure in het geheel niet aanraakt. De opbouw van COSE-sleutel, authenticatorData en attestation-object daarna is ongewijzigd en gedeeld met de Key Vault-modus, dus wat de lokale run over het formaat bewijst geldt ook daar.
- **Aanleiding:** de ontbrekende `Key Vault Crypto Officer`-rol blokkeerde 0a, terwijl die rol niets met de vraag van 0a te maken heeft. Bevestigd in deze sessie: de vault is bereikbaar via het management plane maar de data plane geeft `Assignment: (not found)` — Owner op de subscription erft geen data plane-rechten. Die rol is nu pas nodig als we ná een geslaagde lokale run de Key Vault-modus willen bevestigen.
- De sleutel gaat in `results/credential-<timestamp>.json`, het artefact dat fase 0b consumeert: private key (PKCS#8), credentialId, rpId, user handle, publieke X/Y, AAGUID, signCount en na een geslaagde registratie het methode-ID van Entra. Geverifieerd dat de sleutel uit dat bestand rondtript en een geldige ES256-handtekening zet.
- **De private key staat daarmee leesbaar op schijf.** Dat is de omkering van PRD §4.2 en uitsluitend aanvaardbaar in een testtenant. `results/` staat in `.gitignore`.

**`DSInternals.Passkeys` gevonden** ([webauthn-interop](https://github.com/MichaelGrafnetter/webauthn-interop)). Die module doet administratieve passkey-registratie in Entra via dezelfde Graph-endpoints, en had ons eerder werk bespaard.

- Wat het wél beantwoordt: de rechtenvraag (Authentication Administrator of Privileged Authentication Administrator, bevestigd in de Graph-documentatie) en de exacte vorm van het verzoek.
- Wat het **niet** beantwoordt: de formaatvraag. De module gebruikt de Windows WebAuthn-API en dus een echte authenticator of Windows Hello. Of Entra een credential accepteert dat nooit in een authenticator heeft gezeten, blijft onze eigen vraag — en blijft dus de kernvraag van dit project.
- Vier concrete correcties aan het script volgden hieruit: `v1.0` in plaats van `beta` (met het bijbehorende verschil rond `challengeTimeoutInMinutes`), `clientDataJson` in plaats van `clientDataJSON`, de fijnmazige scope als geldig alternatief, en herkenning van de beleids-400's. Zie *Wat we onderweg zijn tegengekomen*.

**Voor fase 0b, en het raakt de inschatting.** De registratiesleutel voor plugin-authenticators is `HKLM\SOFTWARE\Microsoft\FIDO\<SID>\Plugins`. Die bestaat op deze machine en is leeg; Windows-build 26200 (25H2), `webauthn.dll` 10.0.26100.8875. Belangrijker: `webauthn-interop` is een **.NET**-implementatie van deze API-oppervlakte, inclusief een `Get-PasskeyAuthenticatorPlugin`. PRD §12.2 gaat uit van C++/COM en schat 6–9 maanden; als de plugin-kant in .NET kan, is die inschatting te pessimistisch. Uitzoeken vóórdat 0b begroot wordt.

Gecontroleerd: syntax schoon, parametersets kloppen, encodertest slaagt (30 controles), en het lokale sleutelpad is end-to-end nagelopen tot en met een geldige handtekening. Niet gecontroleerd: iets tegen een echte tenant — de consent staat nog open.

### 4 september 2026 (vervolg) — de registratie is gelukt

Na de wijzigingen van vanochtend is fase 0a in drie runs rond gekomen.

- **Run 1 (`-SkipRegistration`)** kwam voor het eerst tot en met `creationOptions`. De consent had gewerkt; de `Unsupported token`-blokkade van 19 augustus is weg. Twee dingen uit de response die we niet hadden aangenomen: de RP ID is **`login.microsoft.com`**, niet `login.microsoftonline.com`, en de tenant vraagt `attestation: direct`.
- **Run 2** faalde met HTTP 400, `subCode error_user_group_restriction_policy_failure`: `ChrisG` viel niet in de doelgroep van het passkey-beleid. Beleid, geen formaat — het script herkende dat en zette de formaatconclusie op onbekend in plaats van op afgekeurd. Dat is precies waarvoor die herkenning gebouwd is.
- **Run 3, na het aanpassen van de doelgroep: geregistreerd.** Zie *De kernvraag is beantwoord* bovenaan.

Drie fouten in het script gevonden en gerepareerd, alle drie in de duiding en niet in de werking — en juist die duiding is de opbrengst van dit script:

- De scope-controle meldde `mist scopes: System.Object[]` bij een volledig toereikende sessie. Een komma-operator gaf de lege lijst als één element terug. De bijbehorende waarschuwing zei dat een 401/403 daarna niets over het GDAP-pad zou zeggen — de verkeerde conclusie, op een moment dat het ertoe deed.
- De notitie *"Geen -ClientId opgegeven"* hing aan de else-tak van `$UseDeviceCode` in plaats van aan `$ClientId`. Bestond al vóór vandaag en verscheen dus bij elke interactieve run.
- **`gdapPathWorks` werd bij een geslaagde POST onvoorwaardelijk op `true` gezet.** Deze run gebruikte een account uit de klanttenant zelf, dus er was geen delegatie in het spel. Een latere lezer zou uit het resultaatbestand hebben opgemaakt dat het GDAP-pad bewezen was. Nu wordt het aanmeldaccount met het doelaccount vergeleken en blijft de conclusie leeg als er niets te delegeren viel.

Verder is de foutparser herschreven. Graph zet de hele HTTP-dump in de body en de eigenlijke reden zit twee niveaus diep: `error.message` is zélf een JSON-tekst met een `odata.error` met een `subCode`. Zoeken op de eerste `{` werkt niet, want de header `x-ms-ags-diagnostic` bevat er een. De duiding hangt nu aan die `subCode` in plaats van aan een tekstpatroon.

**Wat dit betekent voor het ontwerp.** De aanname uit PRD §4.3 — dat een RP niet kan afdwingen wat een authenticator teruggeeft — is bevestigd: de tenant vroeg `direct`, wij leverden `none`, Entra accepteerde en noteerde `notAttested`. En de BE/BS-keuze uit §13 doet wat hij moet doen: Entra classificeert het credential als `synced`.

**De doelgroep van het passkey-beleid is een inrichtingsstap per tenant.** Dat is geen testartefact maar iets dat in de onboardingflow van open vraag 2 hoort. Over 300 tenants moet dat geautomatiseerd.
