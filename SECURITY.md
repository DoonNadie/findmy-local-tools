# Security

This is experimental personal tooling, not an audited security product. No supported-version SLA or bug bounty is offered.

Please do not publish credentials, tokens, accessory private keys, recovery material, device serial numbers or location data in issues. For a suspected vulnerability, use GitHub private vulnerability reporting if enabled; otherwise open a minimal issue requesting a private contact channel **without exploit details or personal data**. Do not assume such a channel is already configured.

Scope: host compromise by the same macOS user, compromised dependencies and changes to Apple's private protocols are not solved by encrypting local state. The Keychain helper exposes the key only through a captured subprocess pipe in normal use, but authorized same-user code can invoke it. No forensic erase of old plaintext inputs, APFS snapshots or backups is promised.

Do not run this project with elevated privileges. Do not disable certificate verification, SIP or Keychain controls to force it to work. A checksum records expected bytes; it is not independent proof of publisher identity.
