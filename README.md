# Passkey Manager

Centraal beheer van passkeys voor MSP-beheerde admin-accounts in klanttenants.

Wij beheren in elke klanttenant een Global Admin-account. De TOTP-seeds daarvan staan nu in IT Glue; IT Glue kent geen passkey-object. Dit systeem geeft die credentials een plek: registreren, inzien, gebruiken en intrekken, per klant gescheiden, met de private keys non-exportable in Azure Key Vault.

Kern van het ontwerp: **de private key verlaat Key Vault nooit.** De backend is zelf de authenticator en tekent op afstand. Er staat dus nooit sleutelmateriaal op een endpoint.

## Documentatie

| | |
|---|---|
| [PRD](docs/PRD.md) | Productdefinitie, ontwerpbeslissingen, architectuur, fasering |
| [Voortgang](docs/VOORTGANG.md) | Waar we staan en wat de volgende stap is — **lees dit eerst** |
| [Fase 0](phase0/README.md) | De test die bepaalt of de rest zin heeft |

## Status

Fase 0, nog niet uitgevoerd. De testcode ligt er en is offline gevalideerd, maar er is nog niet tegen een tenant aan gedraaid. Zolang niet vaststaat dat Entra een volledig in software gegenereerde credential accepteert — en dat dat met alleen GDAP-rechten kan — is de rest van de bouw hypothetisch.
