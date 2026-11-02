# Network Forensics Incident Report — Redacted Public Edition

**Incident date:** 2018-06-30. **Assessment:** fake browser-update delivery chain; endpoint impact unconfirmed.

## Executive summary

A workstation's browsing activity was followed by obfuscated JavaScript responses, browser/environment profiling and code constructing a deceptive Chrome-update page. The delivered code defines automatic navigation after 3000 milliseconds and a download-button handler targeting a cloud-hosted JavaScript filename. The reviewed packet sequence and static analysis support a high-confidence fake-update social-engineering interpretation (EV-001, EV-002, EV-006, EV-008).

Subsequent Dropbox-related Client Hellos are consistent with that intended destination, but TLS metadata does not establish the HTTP path or a completed transfer. Successful downloading, payload execution and endpoint compromise remain unconfirmed (EV-004, EV-009). The public edition omits workstation/account identities, addresses, query values and fingerprint submissions. No replacement identities or synthetic incident events have been introduced. Original website compromise, the initial injection mechanism and browser-user attribution remain unresolved (EV-007).

## Scope and evidence handling

The source capture contains 46,937 packets; its reference hash and attribution are in [provenance](data/provenance.json). This edition selects 35 packet events from the reviewed investigation. The [timeline](evidence/timeline.csv) preserves UTC times and packet/event IDs; the [register](evidence/evidence.csv) distinguishes observed facts, static code analysis, inference and unknown outcomes. Omissions are documented in [publication notes](docs/publication-notes.md).

The earlier review used offline TShark 4.6.9 and inert comparison of recovered stream text with response bodies. No script evaluation or HTML rendering was performed. Raw bodies and exports are excluded. The public reproduction tool can corroborate selected fields and static body features directly from an independently supplied PCAP, but cannot reproduce private export hashes.

## Sequence and technical analysis

| Packet references | Evidence | Finding |
| --- | --- | --- |
| P527, P528, P555, P615, P616, P733, P738, P1620 | EV-001 | DNS and HTTP browsing sequence for `www[.]stmarybahrain[.]com`, including `/`, `/new` and `/new/`. No named user is attributed. |
| P2254, P2420, P5704, P6151 | EV-002 | DNS and first `/s_code.js` exchange at `track[.]positiverefreshment[.]org`. Delivered code dynamically inserts a script. |
| P6424 | EV-002 | Follow-up script request corresponding to the decoded target in the first response. |
| P6582, P6904 | EV-003 | Landing-domain DNS occurs before the final fingerprint-bearing request. |
| P7330, P7343, P7639 | EV-006, EV-007 | Collection logic is delivered; a later request carries compatible environment values; the final response inserts the landing script. Values are intentionally withheld. |
| P7871, P8064 | EV-003, EV-008 | `/topics/index.php` exchange at `lw2e[.]sineadhollywoodnutt[.]com`; response contains update-lure code. |
| P8066, P8194, P8140, P8376 | EV-003, EV-008 | Subsequent styles/image resource requests and responses support the content sequence. |
| P9407, P9472, P9498, P9499, P9693, P9813, P9888, P9891, P10717 | EV-004, EV-009 | Dropbox-related DNS and TLS observations; application path and transfer outcome remain unknown. |

All timestamps are available in the UTC timeline. This table groups related observations rather than claiming strict causation. Landing-domain DNS P6582 precedes response P7639, even though that response statically constructs the subsequently requested landing URL. Its earlier resolution is unexplained by the available analysis and must not be rewritten as a linear redirect sequence.

**Static script analysis:** responses P6151, P7330 and P7639 create asynchronous script elements and set source URLs. The inspected decoder selects zero-based odd-index characters and reverses their order. Inert decoding connects targets to requests P6424, P7343 and P7871. Callback alternatives are not assumed to be observed requests. Source code in P7330 collects navigator, screen, language, storage, plugins, WebGL and DOM properties; P7343 contains compatible values. This corroborates profiling but is not an independent runtime trace (EV-002, EV-006, EV-007).

**Update impersonation:** P8064 is labeled `text/html`, but its body is JavaScript replacing document head/body markup. It constructs “Update Chrome” branding, an older-version warning and automatic-download messaging. Both a 3000 ms timer handler and a button handler assign an intended URL to browser navigation. The intended filename is `Chrome_72.3.22.js`; the unique share path and query are withheld. These are code-defined behaviors, not observed page rendering, timer firing or a click (EV-008, EV-009).

**TLS boundary:** P9693 targets `www[.]dropbox[.]com`; P9813 names `log[.]getdropbox[.]com`; P10717 names a subdomain of `dl[.]dropboxusercontent[.]com`, with the unique prefix withheld. The first Hello occurs 3.126372 seconds after the landing response, consistent with—but not proof of—the timer mechanism. Shared cloud infrastructure is not inherently malicious. No encrypted path, completed download or downloaded-file hash is established (EV-004, EV-009).

## Investigation indicators

| Indicator | Interpretation |
| --- | --- |
| `www[.]stmarybahrain[.]com` | Initial browsing context; compromise unconfirmed (EV-001, EV-007). |
| `track[.]positiverefreshment[.]org`, `/s_code.js` | Observed script destination and path; all query values withheld (EV-002). |
| `lw2e[.]sineadhollywoodnutt[.]com`, `/topics/index.php`, `/chromefiles/` | Landing-code and resource context; query values withheld (EV-003, EV-008). |
| `www[.]dropbox[.]com`, `log[.]getdropbox[.]com`, `dl[.]dropboxusercontent[.]com` | Cloud-service context, not a blanket blocking recommendation (EV-004). |
| `Chrome_72.3.22.js` | Code-derived intended filename, not a confirmed recovered download (EV-009). |

## Competing hypotheses

Ordinary third-party tracking can explain profiling, and concurrent news/advertising-related Client Hellos P549 and P1693 show other activity (EV-005). It is a weaker explanation for update impersonation directing navigation to a JavaScript target (EV-008). Malicious third-party content is supported by the code chain, while compromised-site injection remains unconfirmed without original-page/server evidence. Referer and timing alone do not establish the injection source (EV-007).

Fake-update social engineering is the strongest interpretation of the delivered content. Its success is unknown. Unrelated Dropbox activity remains possible because process/tab attribution and decrypted HTTP are absent, although code-target and timing correspondence strengthen linkage (EV-009).

## Detection hypothesis and response

Proposed, **not SIEM-tested**: correlate update-warning/download content plus externally targeted script-file navigation with subsequent DNS/TLS contact from the same endpoint/session. Inspect bodies as inert text only; never evaluate recovered code. A proposed 60-second correlation window requires tuning. Benign update pages, developer tests and unrelated shared-service traffic are false-positive candidates. Encryption, missing SNI, obfuscation changes and NAT/session ambiguity limit coverage. Validate offline with synthetic `.invalid` destinations, not live malicious content (EV-008, EV-009).

For an authorized operational investigation, preserve browser/download history and endpoint file/process telemetry, investigate the intended filename with provenance, and use proportionate targeted controls for the script/landing hosts. Do not globally classify Dropbox as malicious or attribute activity to an authenticated user without browser evidence. Obtain original page/server evidence before assigning a site-compromise mechanism (EV-007, EV-009).

## Conclusion and limitations

Delivered content strongly supports a fake-update lure. Successful downloading, payload execution and endpoint compromise remain unconfirmed. No claim is made that a page rendered, a button was clicked or a timer fired. Capture clock accuracy, original acquisition history and chain of custody are not fully established. Reassembly timestamps are not browser event times. The selected public evidence is not a capture-wide clearance; redaction prevents exact reconstruction of queries and identities.

See [methodology](docs/methodology.md), [limitations](docs/limitations.md) and the [release audit](docs/public-release-audit.md) for reproduction boundaries and results. All public scripts operate independently of the private repository.
