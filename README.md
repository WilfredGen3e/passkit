# Passkey Manager

Centraal beheer van passkeys voor MSP-beheerde admin-accounts in klanttenants.

Wij beheren in elke klanttenant een Global Admin-account. De TOTP-seeds daarvan staan nu in IT Glue; IT Glue kent geen passkey-object. Dit systeem geeft die credentials een plek: registreren, inzien, gebruiken en intrekken, per klant gescheiden, met de private keys non-exportable in Azure Key Vault.

Kern van het ontwerp: **de private key verlaat Key Vault nooit.** De backend is zelf de authenticator en tekent op afstand. Er staat dus nooit sleutelmateriaal op een endpoint.

## Documentatie

- [PRD](docs/PRD.md) — volledige productdefinitie, ontwerpbeslissingen, architectuur en fasering

## Status

Fase 0 — nog te bevestigen dat Entra een volledig in software gegenereerde credential accepteert via de provisioning-API. Zolang dat niet vaststaat is de rest van de bouw hypothetisch.
