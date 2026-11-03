# Test fixtures

All of these were made for OSINTrix's tests and contain only synthetic data: hosts end in
`.example`, IP addresses come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), and the people and accounts do not exist.

- `security-sample.evtx`, `sysmon-sample.evtx`: Windows event logs written by
  `make_evtx.py` (Python 3, standard library only). They follow the real format (file header,
  64 KB chunks with CRC32 checksums, templates with substitution values) and tell a short intrusion
  story: a password spray, an RDP logon, a new admin account, an encoded PowerShell download,
  a C2 connection, LSASS access and a Run-key. Regenerate with `python3 tests/fixtures/make_evtx.py`.
- The other files (`History`, `sample.pcap(ng)`, `photo-gps.jpg`, `forum-post.mhtml`,
  `fortigate-40.csv`) were also built for these tests.
