# Network Forensics Casebook — Public Portfolio Edition

A privacy-reduced, evidence-linked investigation of a **fake Chrome-update delivery chain**. This project demonstrates DNS/HTTP/TLS correlation, static JavaScript analysis, forensic timelines and calibrated reporting—not a confirmed endpoint infection.

Read the [incident report](report.md), [methodology](docs/methodology.md), [redaction policy](docs/publication-notes.md) and [release audit](docs/public-release-audit.md).

```text
Independently obtained PCAP --> offline TShark field/body checks
                                         |
                            selected redacted observations
                                         |
                         timeline + evidence register --> report
                                         |
                            public-file validation + tests
```

## Findings

- Browsing was followed by obfuscated script delivery and browser/environment collection (EV-001, EV-002, EV-006).
- Delivered code constructs Chrome-update messaging and timer/button navigation to an intended JavaScript filename (EV-008).
- Dropbox-related TLS follows; a completed download, page rendering, user interaction, payload execution and endpoint compromise remain unconfirmed (EV-004, EV-009).

The public selection contains **35 observed packet events and nine evidence records**. Packet numbers, original event IDs and UTC timestamps are preserved. Addresses, account/machine identities, unique cloud subdomains, query values and fingerprint submissions are withheld. These are redacted observations, not synthetic incident events. Test fixtures are separately labeled synthetic.

## Quick start: entirely offline

Python **3.13** and its standard library are sufficient. No pip packages, capture, TShark or private repository are required:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -B -m unittest discover -s tests -v
python -B -O scripts/validate.py
```

The public suite has **13 tests**. It validates schemas, references, chronology, labels, safety checks, deterministic output and hashes. This count belongs to this edition only. CI uses Python 3.13 and does not download evidence. The first hosted **Public offline verification** run (#1) succeeded on commit `52e3a98` in **44 seconds**; see [GitHub Actions](https://github.com/jamshidkhodjaev/network-forensics-casebook-public/actions). This success covers hosted offline validation, not the optional PCAP-dependent reproduction described below.

## Optional local PCAP reproduction

Obtain the training capture independently from the [original exercise page](https://malware-traffic-analysis.net/2018/06/30/index.html), subject to the source's terms and your authorization. This repository provides no downloader and no capture/archive. Keep it outside the repository. Reference TShark version: **4.6.9**.

```sh
python -B scripts/reproduce.py --pcap /path/to/independently-obtained-capture.pcap
```

Use `--tshark` to supply an executable when it is not on PATH. The script verifies the capture hash/count, all 35 selected packets' public fields and timestamps, and five response bodies' lengths and static features in memory. It prints only a sanitized result; it does not execute scripts, render HTML, export bodies or contact destinations. Missing evidence is an explicit error. Private stream-export byte comparisons and the complete private 145-event reconstruction are **not available in this edition**. See [scope and limitations](docs/limitations.md).

## Structure

| Path | Purpose |
| --- | --- |
| `report.md` | Standalone sanitized incident report |
| `evidence/` | Selected redacted timeline and evidence register |
| `data/` | Attribution, capture hash, public field checks and artifact hashes |
| `scripts/` | Standalone offline validator and optional PCAP corroborator |
| `tests/fixtures/` | Explicitly synthetic input; no recovered code |
| `docs/` | Methodology, limitations, source/rights notes and release audit |
| `.github/workflows/verify.yml` | Offline tests and validation only |

## Attribution and publication boundaries

Source: Malware-Traffic-Analysis.net, 2018-06-30 traffic-analysis exercise. Source attribution does not establish redistribution permission. No blanket permission for third-party evidence has been established; no license is granted over it. Original project code licensing may be considered separately. See [source attribution](docs/source-attribution.md).

No original PCAP, recovered TCP stream, raw script body, complete connection export, complete corroboration export or private Git history is included. Domains in prose are defanged, shared cloud infrastructure is not labeled inherently malicious, and redacted values are not replaced with invented observations. Publication remains subject to the rights review documented in the release audit.
