# Methodology and public schemas

The public selection retains 35 existing event IDs, packet numbers and UTC timestamps from the reviewed timeline. Nine evidence categories retain their original IDs. No incident timestamp is synthesized. Explicit role labels replace withheld endpoint addresses; they are descriptions, not replacement IP values. Only necessary historical destination domains and the intended filename are retained.

`evidence/timeline.csv` schema `public-1.0` has event ID, UTC timestamp, packet number, source/destination role, protocol, description, evidence IDs, classification and handling. Every event is an observed packet. Static findings are separate register entries, not new endpoint events.

`evidence/evidence.csv` contains evidence ID, supporting packet numbers, observed fact, interpretation, classification, confidence, limitations, related event IDs and handling. Classification is observed, static code analysis, inference or unknown. Semicolons delimit multiple references. CSVs are UTF-8 with LF endings and normal CSV quoting. Public schemas intentionally differ from private schemas to avoid retaining identifying columns. They are labeled redacted derivatives, never raw evidence.

`data/packet-checks.json` contains only public field expectations: protocol flags, response/request associations, streams, query-free paths and defanged hosts. It does not contain raw query submissions. `data/checksums.json` records public artifact SHA-256 values; it excludes only itself to avoid circular hashing. These are public-derivative hashes, not substitutes for original evidence hashes.

Offline commands validate the included files without PCAP, network, TShark or private imports. Optional `scripts/reproduce.py` verifies the expected PCAP hash/count and selected fields/timestamps using TShark `-n -2 -T json`. Five HTTP bodies are inspected in memory for lengths and static features, including inert URL decoding. It prints no bodies, queries or identifiers and does not write evidence. This checks selected public claims; it is not a complete re-execution of the private workflow.

The public tools are new, narrowed adaptations of the private extraction/validation concepts. No private-only script was copied unchanged. Decimal epoch conversion, explicit errors and odd-index string decoding were retained as audited concepts. No package installation is needed.
