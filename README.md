# FindMy Local Tools

Experimental **macOS-only** tools for querying location reports for accessories you own, using [FindMy.py](https://github.com/malmeloo/FindMy.py), a local Anisette provider and encrypted state.

This is **not** Apple's Find My app, an official Apple API, or a fork/redistribution of export-findmy. It does not export accessory keys and does not include Apple libraries, an APK, account data or compiled binaries.

**Status:** an account-specific predecessor was tested locally. This portable edition has synthetic/offline tests; it has **not** been end-to-end tested on a fresh Mac/account. It is not independently audited. Expect private APIs to change.

## Features

- AES-256-GCM state encryption; storage key in the macOS login Keychain.
- Accessory keys, account session, Anisette state and location results encrypted on disk; plaintext only in process memory.
- Local Unicorn-based Anisette emulation. No public Anisette server or implicit library downloads.
- HTTPS with certificate validation; no automatic redirects for credential-bearing requests.
- Local library/helper SHA256 pins and private file permissions. The compiled helper and its pin live together in the selected private state directory.
- Persisted tokens with the raw Apple account password excluded from serialized state.
- A client-info identity consistency correction and explicit handling of successful numeric `0` delegate status.

Encryption is **not** a security boundary against malicious processes running as the same user. Such processes may invoke the helper or inspect memory. Enable appropriate host protections and plan backups; losing both the Keychain and encrypted state means losing access to this local state.

## Prerequisites

- macOS, Python **3.14** (tested predecessor version), Swift compiler and codesign from Apple's developer tools.
- Your own accessory JSON keys compatible with FindMy.py. Obtain/export them separately, review that tool and understand any iCloud trust-circle effects. This repository does not perform that operation.
- A **locally reviewed, legally obtained** library ZIP containing `libstoreservicescore.so` and `libCoreADI.so` for arm64-v8a. Newer Apple Music versions may use `libstoreapi.so`; compatibility and any alias must be reviewed separately. We do not supply, download or guarantee those proprietary libraries.

Review source/dependencies before installation. To create an isolated environment yourself:

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

`requirements-tested.txt` records a development dependency snapshot, including macOS-specific packages. Pins are not a vulnerability scan or cryptographic hashes; review current advisories before installing. Never install into your system Python.

## Setup

Default private state: `~/Library/Application Support/findmy-local-tools`, **outside this checkout**. Set `FINDMY_TOOLS_HOME` consistently to use another absolute private directory. This namespace is separate from other Find My installations.

```sh
.venv/bin/python -I tools/initialize.py \
  --libs /absolute/path/to/reviewed-libraries.zip \
  --accessory /absolute/path/to/your-accessory.json
```

Repeat `--accessory` for additional objects. Setup compiles only the included local Swift helper; it may ask for Keychain authorization. It does not log in to Apple or export keys. It validates input format, not whether the source keys are authentic. Original input JSON files are **not** removed: protect or archive them appropriately yourself.

Then, in an interactive terminal:

```sh
.venv/bin/python -I tools/query_locations.py --json
```

Enter account credentials and any 2FA **only in that terminal**. The program retains encrypted tokens, not the raw password. Apple can expire/revoke tokens or require another interactive login; indefinite unattended authentication is not promised. No automatic credential saving or key regeneration is provided as a workaround.

With `--json`, stdout is a single JSON document; prompts and human-readable summaries go to stderr. The output contains last retrieved report timestamps, coordinates and accuracy. These are sensitive personal data. Avoid sharing terminal captures or logs. Reports are not live GPS and may be older than those visible in Apple's app.

## Recovery and maintenance

- Back up encrypted state **and** plan recovery of the corresponding login Keychain. A ciphertext-only backup without a recoverable key is insufficient.
- Never replace a helper/hash or storage key just to make an integrity error disappear. Recompilation may require fresh Keychain approval.
- No daemon, background polling, update service, account credentials in CI or iCloud trust maintenance is installed.
- Private endpoints, third-party dependencies and OS keychain APIs may change. Test changes with synthetic data before using a real account.
- If the integration fails, use the official Find My app rather than disabling TLS or operating-system protections.

## Offline tests

After installing the reviewed dependencies:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Tests use a random in-memory storage key and temporary directories. They do not access your Keychain, Apple account, real accessories or network.

## People behind the project

Created by [DoonNadie](https://github.com/DoonNadie) with [BobNadie](https://github.com/BobNadie), his supervised AI agent. DoonNadie directs the project; Bob assists with implementation, testing, documentation and maintenance. BobNadie is an AI service account, not a separate human contributor.

## License and attribution

New tools: MIT, copyright DoonNadie. Query code incorporates MIT-licensed FindMy.py adaptations; see [NOTICE.md](NOTICE.md), [LICENSE](LICENSE) and [FINDMY-LICENSE.md](FINDMY-LICENSE.md). Dependencies and separately obtained prerequisites retain their own licenses. No Apple endorsement is implied.
