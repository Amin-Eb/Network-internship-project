# P2 design notes

Design write-ups produced while building the analyzer, one per stage of the assignment.
They are kept largely as written at the time, including the reasoning behind approaches
that were tried and then abandoned — that history is the most useful part.

| Doc | Covers |
| --- | --- |
| [`P2-1.md`](P2-1.md) | DNS on the wire: a real capture, annotated request/response pairs, successful and `NXDOMAIN`. Read this first — it makes the reporter code concrete. |
| [`P2-2.md`](P2-2.md) | `DnsReporter` design. Why the first two implementations (fixed byte offsets, then full PcapPlusPlus parsing) were rejected in favour of reading header fields directly out of the buffer. Also documents the TDD approach and coverage figures. |
| [`P2-3.md`](P2-3.md) | `PacketCapture` — the original static `fromFile` / `fromInterface` interface and its unit-test coverage. Note the shipped class is now instance-based (`openFile` / `openInterface` / `getNextPacket` / `close`) so it can be driven per-thread; see `P2/include/PacketCapture.h`. |
| [`P2-12.md`](P2-12.md) | Running the reporter end to end: building `statistics`, scraping with Prometheus, importing the Grafana dashboard. |

## Reading order

`P2-1` → `P2-2` → `P2-3` → `P2-12`, then the source guided by the
[repository README](../README.md#suggested-reading-order).

## Coverage figures

`P2-2.md` and `P2-3.md` quote coverage measured at the time each class was written. The
`DnsAnalyzer` / `DnsAnalyzerLib` names in `P2-2.md` predate the rename to
`DnsReporter` / `PacketAnalyzerLib`; the file paths have since moved to `src/` and
`include/`.

## Things the notes do not cover

- The TCP and SCTP reporters (`src/TcpReporter.cpp`, `src/SctpReporter.cpp`) postdate
  these notes. Both are covered by tests in `tests/test_tcp.cpp` and `tests/test_sctp.cpp`,
  including md5 verification of reassembled payloads.
- The multithreaded pipeline and flow-hash dispatch in `src/statistics.cpp` are described
  in the [repository README](../README.md#p2-architecture) rather than here.