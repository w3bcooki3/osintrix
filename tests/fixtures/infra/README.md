Files for the infrastructure-pivot tests.

- `whois/` and `expected/`: real WHOIS answers from many registries, with the values another parser (python-whois) reads from them — from github.com/richardpenman/whois (MIT licence).
- `case/`: one made-up phishing set-up on reserved `.test` names and documentation addresses, written in the formats the tools produce: registrar WHOIS, RDAP JSON, dig output, crt.sh JSON, Shodan and Censys host JSON, VirusTotal resolutions, CIRCL passive DNS (JSON lines) and a passive DNS CSV.
