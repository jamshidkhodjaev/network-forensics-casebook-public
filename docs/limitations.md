# Scope and limitations

- No completed download, actual rendering, user action, code execution or compromise is established by this public edition.
- TLS metadata cannot reveal the encrypted HTTP path. Shared hosting is not inherently malicious.
- Static code inspection establishes intended behavior, not a browser runtime trace.
- The 35-event selection does not replace the original capture or the complete private reconstruction. Identities, addresses, queries and fingerprint submissions cannot be reconstructed from included public expectations.
- No private stream exports are needed or supported. Their byte-for-byte newline-normalized comparisons and private export hashes are unavailable here. The optional PCAP script instead checks public fields and selected body features directly.
- Use reference TShark 4.6.9 for optional checks. Profile/dissector changes may affect results. Missing evidence is an error, not a skipped successful verification.
- Hashes detect divergence from the included manifest, not authenticity against a maliciously modified repository. Automated prose checks cannot prove every semantic conclusion.
- Fresh-copy tests were performed locally on macOS with Python 3.13.0. Hosted public GitHub Actions and other operating systems have not been independently observed.
- Test fixtures are synthetic, explicitly labeled, and use reserved example names. They are not evidence from the incident.
