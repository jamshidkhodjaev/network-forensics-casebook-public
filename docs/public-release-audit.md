# Public-edition release preparation audit

## Recommendation

**GO for technical/analyst review of this independently prepared directory. NO-GO for public publication until the owner resolves third-party derivative-rights questions and explicitly approves release.** No license has been added. No Git repository was initialized; no commit, remote, push, tag or publication was performed.

The private repository was treated as read-only. A before/after SHA-256 inventory covered project files and Git metadata. All private project files and user Git state were unchanged. Four tool-managed references were added or updated under `.git/refs/codex/` across the resumed assistant turns. No explicit Git mutation command was run. This environment-managed exception means whole-directory Git byte identity cannot be certified; those refs were not removed or copied. The public directory contains no private Git history. The original private hosted-CI success was supplied as context; it is not represented as a hosted CI result for this edition.

## Created and reused material

- `README.md`, `report.md`: new public documents preserving reviewed conclusions, with actual local links and public-only commands. Existing redacted previews were reviewed, not blindly copied; their private commands, identity appendix and incomplete links were not retained.
- `evidence/timeline.csv`: 35 selected existing events, retaining original event IDs, packet numbers and UTC times. New public schema replaces address columns with explicitly withheld roles and removes queries/submissions.
- `evidence/evidence.csv`: nine original evidence IDs with supporting references restricted to the public selection. Analytical descriptions distinguish observed packets, static code analysis, inference and unknown outcomes.
- `data/provenance.json`: source attribution, expected capture hash/count, public handling labels and hashes identifying the reviewed source artifacts. These hashes confer no redistribution rights.
- `data/packet-checks.json`: safe, redacted field expectations for optional PCAP checks; no query strings, addresses or fingerprint vectors.
- `data/checksums.json`: public artifact SHA-256 values; excludes itself only.
- `scripts/casebook.py`, `scripts/validate.py`, `scripts/reproduce.py`: new standalone tools adapting audited concepts from the private workflow. No dependency on private imports, directories or exports.
- `tests/test_public.py`, `tests/fixtures/synthetic.json`: 13 portable tests with explicitly synthetic fixture data and negative mutations, separate from the real incident derivatives.
- `docs/`: methodology, limitations, attribution/rights, sanitization, this audit, exact validation results and the complete prospective file inventory.
- `.github/workflows/verify.yml`: Python `3.13`, read-only permissions, tests and offline validation; no capture download.
- `.gitignore`: captures, archives, streams, payloads, environments, credentials files and caches excluded.

The complete prospective Git-tracked list is [prospective-files.txt](prospective-files.txt). This is an inventory only; nothing has been staged.

## Intentionally excluded

Private `.git` and all history/configuration/remotes; original PCAPs and archives; recovered TCP streams; raw HTTP/JavaScript/HTML bodies; payloads; complete DNS/HTTP/TCP exports; the full private corroboration JSON and encoded URLs; private asset/user identity records; the private report-validation file; private-only reproduction scripts and old test results.

The optional public PCAP check does not reproduce private recovered-export hashes or the complete private timeline. Those operations are documented as unavailable rather than silently skipped.

## Sanitization decisions

Detailed transformations are in [publication-notes.md](publication-notes.md). Internal/external addresses, account/domain/machine identifiers, opaque keys, storage/session identifiers, fingerprint values, unique cloud prefixes/share paths and full query strings are excluded. Withheld values are labeled, never fabricated. Historical domains needed to explain the chain are retained in defanged form. The intended filename is retained as a code-derived target, not a downloaded artifact. No raw dangerous URL is made clickable.

The publication preserves the key correction: the landing response is labeled HTML but contains JavaScript constructing a deceptive update page. It preserves actual ordering, including landing DNS before the final script response. Static timer/button definitions are not endpoint events. Download, execution and compromise remain unconfirmed.

## Validation commands and exact results

A fresh copy in a separate temporary directory was tested with a newly created Python 3.13.0 virtual environment. `PYTHONPATH` was removed; no project dependencies were installed; only pip 24.2 was listed. No PCAP, stream exports or private repository were present in the offline copy. This directory has no Git history, so this was a clean file-copy test, not a clone.

Commands below ran from that clean public root. [validation-results.json](validation-results.json) records stdout, stderr and exit codes.

| Command | Result |
| --- | --- |
| `python --version` | Exit 0; Python 3.13.0 |
| `python -m pip list --format=json` | Exit 0; pip 24.2 only |
| `python -B -m unittest discover -s tests -v` | Exit 0; **13 tests passed** |
| `python -B -O scripts/validate.py` (twice) | Exit 0 both times; byte-identical sanitized output; 35 events and nine evidence records |
| `python -B scripts/reproduce.py --pcap missing.pcap` | Expected exit 1; explicit missing-local-evidence error |
| `python -B scripts/reproduce.py --pcap ../local-evidence/source.pcap` | Exit 0 with permitted evidence supplied externally and TShark 4.6.9 on PATH; 35 selected packets and five static body checks passed; capture hash unchanged |

Tests cover report references, CSV schema/order, duplicate IDs, redaction labels, synthetic fixture labeling, prohibited files, sensitive token detection, standalone operation, deterministic offline output and unavailable-PCAP handling. Public artifact hashes and the prospective file list are validated. No test assertions were disabled or counts borrowed from the private project. Safety scans are targeted guardrails, not comprehensive credential discovery.

The optional capture was copied outside the fresh public repository only for the second stage. No recovered streams were required. No body or query was printed/exported by reproduction. A comparison confirmed public files were unchanged by the validation commands. Hosted public GitHub Actions has not run; local macOS execution is not presented as an observed Ubuntu CI result.

## Remaining risks and release gates

1. Source attribution is not blanket permission to redistribute analytical derivatives. Obtain owner/legal review before public release; raw source material is excluded regardless.
2. Historical domains and the intended filename remain case indicators. Do not browse them or label shared cloud infrastructure as malicious. Report conclusions require analyst review beyond automated reference checks.
3. Optional reproduction requires independently supplied permitted evidence and the reference TShark version. It corroborates selected public facts, not private stream provenance or endpoint execution.
4. A code-only license may be proposed separately after ownership review; no license here grants third-party rights.
5. After explicit approval, initialize a new independent Git repository, review its actual staged files, and observe its own hosted CI before making a public-release success claim. None of those actions has occurred.
