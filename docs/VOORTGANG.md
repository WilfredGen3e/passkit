# Voortgang

Werkdocument om het project tussen sessies over te kunnen dragen. Wie hier koud instapt leest dit bestand en daarna de [PRD](PRD.md), en kan dan verder.

**Bijwerken bij elke betekenisvolle stap.** Niet als changelog van commits — die staan in git — maar als antwoord op "waar staan we en waarom".

---

## Waar we nu staan

**Fase 0, nog niet uitgevoerd.** De code om de test te doen ligt er en is offline gevalideerd, maar er is nog niet één keer echt tegen een tenant aan gedraaid. Daarmee is de kernvraag van het hele project onbeantwoord: accepteert Entra een passkey die nooit in een authenticator heeft gezeten?

Zolang dat zo is, is alles vanaf fase 1 hypothetisch. Niet vooruitbouwen.

## De volgende stap

Fase 0 daadwerkelijk draaien. Nodig:

1. Een testtenant met FIDO2 aan en "Allow self-service setup" ingeschakeld
2. Een Key Vault waarin sleutels aangemaakt mogen worden (rol *Key Vault Crypto Officer*)
3. GDAP vanaf het partner-account naar die testtenant — anders is alleen de formaatvraag te beantwoorden en de rechtenvraag niet

Dan `phase0/Invoke-Phase0Test.ps1`, eerst met `-SkipRegistration`. Zie [phase0/README.md](../phase0/README.md) voor de details en voor hoe je de uitkomst leest.

## Wat er ligt

| Onderdeel | Staat | Opmerking |
|---|---|---|
| PRD | vastgesteld | v1.0, [docs/PRD.md](PRD.md) |
| CBOR/COSE-encoder | werkt | `phase0/PasskeyManager.Phase0.psm1`, handgeschreven, geen dependencies |
| Encodertest | slaagt | `phase0/Test-Encoding.ps1`, 30 controles, draait offline |
| Fase 0-testscript | geschreven, ongetest | `phase0/Invoke-Phase0Test.ps1` — nooit tegen een echte tenant gedraaid |
| Alles vanaf fase 1 | niets | wacht op de uitkomst van fase 0 |

## Wat we onderweg zijn tegengekomen

Dingen die geld of tijd kosten als iemand ze opnieuw moet ontdekken.

- **PowerShell parseert `0xFFFFFFFF` als Int32 `-1`.** Kostte de CBOR-encoder stilzwijgend de 4-byte-tak: alles boven 65535 werd als 8 bytes gecodeerd. Opgelost door grenswaarden expliciet als `[uint64]` te schrijven. Precies het soort fout dat bij Entra terugkomt als een nietszeggende HTTP 400 — vandaar dat de encodertest bestaat.
- **`Guid.ToByteArray()` is mixed-endian.** WebAuthn wil de AAGUID zoals de GUID geschreven staat. Zonder omkering staat er een andere AAGUID in het credential dan op de allowlist, en dat valt pas bij rapportage op. Afgevangen in `ConvertTo-AaguidBytes`, met een test erop.
- **EC-coördinaten kunnen korter dan 32 bytes terugkomen** uit Key Vault als ze toevallig met een nulbyte beginnen. Een COSE-sleutel met een 31-byte X wordt afgekeurd. Treedt bij ongeveer 1 op de 256 sleutels op, dus zonder onvoorwaardelijke normalisatie is dit een fout die pas in productie opduikt.
- **Key Vault tekent ES256 als raw `r || s`,** WebAuthn wil ASN.1 DER in een assertion. Raakt fase 5, staat genoteerd in de fase 0-leesmij.

## Open vragen, in volgorde van belang

1. **Fase 0-uitkomst** — beide deelvragen, zie PRD §14.1. Blokkeert al het overige.
2. **Graph API-versie en body-vorm** — het script gaat uit van `beta` en van `publicKeyCredential.response.{clientDataJSON,attestationObject}`. Niet geverifieerd; valt uit fase 0 te leren.
3. **Key Vault-tier** — Premium per sleutel per maand versus Managed HSM vast tarief, bij 1000–2000 sleutels. Ook sleutel- en throttlinglimieten per vault, zo nodig sharden. PRD §14.2.
4. **GDAP-rolkeuze** per klanttenant voor de registratieflow. PRD §14.3.
5. De rest van PRD §14.

## Afspraken over dit project

- **Nooit vooruitbouwen op een onbeantwoorde fase.** De fasering in PRD §11 is bewust zo gesneden dat elke fase de volgende rechtvaardigt.
- **Testtenant, niet klanttenant**, tot fase 0 rond is.
- **Aannames markeren in plaats van hardcoderen.** RP ID, API-versie en body-vorm staan nu als expliciet openstaand in de code en de leesmij; dat zo houden tot ze bewezen zijn.
- De handgeschreven encoder blijft handgeschreven en getest. Een dependency erbij is verleidelijk maar dit is Tier-0-code die door een auditor gelezen moet kunnen worden.

---

## Log

### 19 augustus 2026
- Repo `WilfredGen3e/passkeymanager` was leeg; ingericht met PRD als eerste commit.
- PRD v1.0 vastgelegd. Twee aanpassingen ten opzichte van het aangeleverde concept: fase 0 gesplitst in een formaat- en een rechtenvraag (§7, §11, §14.1), en de `BE`/`BS`-keuze toegelicht in §13 omdat "synced" hier iets anders betekent dan gebruikelijk.
- Fase 0-code geschreven: encoder, offline test (30 controles, slagen), en het testscript tegen Key Vault en Graph.
- Nog niet gedraaid tegen een tenant.
