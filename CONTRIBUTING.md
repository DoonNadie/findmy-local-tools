# Contributing

This project is experimental and uses unofficial Apple interfaces. Keep changes small, reviewable and explicit about what has actually been tested.

## Local checks

Run the offline suite from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

These synthetic tests do not prove that authentication or location queries work with a real account. Document live validation separately; never use account credentials in automated tests.

## Protect private data

- Do not commit accessory keys, account identifiers, tokens, passwords, location reports or encrypted personal state.
- Use synthetic examples and keep runtime state outside the checkout.
- Do not bundle Apple libraries, APKs or exported accessory data.
- Review dependency changes before installing them. Do not add implicit downloads or weaken TLS checks.
- Do not rerun key export or iCloud trust-circle enrollment as a routine test.

For security reports, follow [SECURITY.md](SECURITY.md). Describe limitations accurately: passing tests is not an independent security audit.

## AI-assisted contributions

Disclose substantial AI assistance and keep a human owner responsible for review. BobNadie is the supervised AI service account assisting DoonNadie; it does not represent an independent human reviewer.
