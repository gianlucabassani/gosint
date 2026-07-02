<h1 align="center">GOSINT</h1>

<p align="center">
  <b>Go Security Intelligence Toolkit — fast, single-binary OSINT & reconnaissance.</b><br>
  Domain recon, web crawling, fuzzing, and entity-centric OSINT profiling — from one
  concurrent, dependency-free CLI that persists everything to a local SQLite database.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25%2B-3D9BFF">
  <img src="https://img.shields.io/badge/status-active_development-F5A524">
  <img src="https://img.shields.io/badge/stack-Go_·_Cobra_·_GORM_·_SQLite-3D9BFF">
  <img src="https://img.shields.io/badge/build-single_static_binary-34D399">
  <img src="https://img.shields.io/badge/license-MIT-8A93A8">
</p>

---

GOSINT gathers intelligence about domains, sites, and identities and stores it in a
structured local database you can query, enrich, and export. Active recon
(DNS/WHOIS/subdomains/tech/fuzzing) runs concurrently; API-backed OSINT (Hunter.io,
HaveIBeenPwned, Shodan, social) degrades gracefully when keys are absent; and an
**entity model** ties findings about the same target — its domain facts, per-source
profiles, and harvested contacts — into one profile you can report on.

> **Authorized use only.** GOSINT is for security research, authorized assessments,
> and educational use. You are responsible for having permission to probe any target.

> **Successor to [Browsint](../browsint).** GOSINT absorbs Browsint's OSINT
> entity/contact model and extraction pipeline into Go (single static binary,
> concurrency, tests). Migrate an existing Browsint database with
> `gosint import-browsint <path.db>`.

## Capabilities

| Area | What it does |
|------|--------------|
| **Domain recon** | DNS (A/AAAA/MX/NS/TXT), WHOIS, technology fingerprinting, passive intel (crt.sh, Wayback), concurrent subdomain enumeration — across 5 scan modes |
| **Web crawling** | Recursive, domain-scoped crawl harvesting emails, phone numbers, and links |
| **Fuzzing** | Directory, virtual-host, and subdomain fuzzing with embedded wordlists |
| **OSINT profiling** | Email breach/deliverability (HIBP, Hunter.io), social enumeration (Sherlock), domain enrichment (Shodan/Wayback) — assembled into an **entity** with per-source profiles + contacts |
| **Storage & reports** | Persistent SQLite (`~/.gosint/gosint.db`); export to JSON, HTML, CSV, PDF |

## Quick start

No cgo, no system libraries — the SQLite driver is pure Go, so it builds to one static binary.

```bash
git clone https://github.com/gianlucabassani/gosint.git
cd gosint
make build           # or: go build -o gosint ./cmd
./gosint             # launch the interactive menu
```

Optional API keys (all optional — modules degrade without them):

```bash
export HIBP_API_KEY=...     # HaveIBeenPwned (breaches)
export HUNTER_API_KEY=...   # Hunter.io (email deliverability)
export SHODAN_API_KEY=...   # Shodan (host enrichment)
```

Common flows:

```bash
# Recon a domain, then export a report
./gosint scan -t example.com --deep
./gosint export -t example.com -f html -o report.html

# Full OSINT profile (auto-detects domain / email / username)
./gosint osint profile -t example.com
./gosint osint profile -t alice@example.com
./gosint osint profile -u johndoe

# Crawl for contacts, or fuzz for hidden infrastructure
./gosint crawl -u https://example.com -D 3
./gosint fuzz  -u https://example.com -m directory -T 50

# Migrate data from the retired Browsint toolkit
./gosint import-browsint ~/.browsint/osint.db
```

## Scan modes

| Mode | Techniques | Target interaction | Detection risk |
|------|-----------|--------------------|----------------|
| `--basic` | DNS · WHOIS · tech detection | none (DNS/WHOIS only) | minimal |
| `--deep` | basic + crt.sh + Wayback | none (public archives) | none (passive) |
| `--stealth` | basic + reduced, rate-limited subdomain probing | active, minimal | low |
| `--aggressive` | basic + full subdomain enum + directory/vhost fuzzing | extensive | very high |
| `--custom` | user-selected (`--enable-dns/-whois/-tech/-passive/-subdomains/-fuzzing`, thread/limit/timeout tuning) | varies | varies |

## Architecture

```
   gosint            ┌──────────────────────── cmd/main.go ────────────────────────┐
   (CLI + TUI)  ───▶ │                     cobra command tree                       │
                     └───────┬──────────┬──────────┬───────────────┬───────────────┘
                             ▼          ▼          ▼               ▼
                          scanner    crawler     fuzzer          osint
                       DNS·WHOIS·   emails·     dir·vhost·   HIBP·Hunter·Shodan·
                       tech·crt.sh  phones·links subdomain   social  ─┐
                             │          │          │                  │ raw data
                             │          │          │                  ▼
                             │          │          │           osint/entities
                             │          │          │        entity upsert · per-source
                             │          │          │        profile · contact harvest
                             └──────────┴──────────┴──────────┬───────┘
                                                              ▼
                                storage — GORM + SQLite (pure Go, no cgo)
                                  Target (recon hub) ◀── FK ──▶ Entity (OSINT hub)
                                                              ▼
                                    reports — JSON · HTML · CSV · PDF
```

- **scanner / crawler / fuzzer** — concurrent recon; context-cancellable (Ctrl-C safe).
- **osint / osint/entities** — API-backed lookups, then entity persistence: emails/phones
  are harvested via a recursive walk and deduped; each source becomes an `OSINTProfile`.
- **storage** — one SQLite file; `Target` (what you scanned) links to `Entity`
  (who/what you profile). WHOIS is stored structurally as `DomainInfo`.
- **reports** — the `export` command renders any target (with its entity data) to four formats.

## Command reference

| Command | Purpose |
|---------|---------|
| `scan -t <domain> [--basic\|--deep\|--stealth\|--aggressive\|--custom]` | Domain reconnaissance |
| `crawl -u <url> [-D depth]` | Recursive OSINT web crawl |
| `fuzz (-u <url>\|-t <host>) -m <directory\|vhost\|subdomain>` | Fuzzing |
| `osint email -t <email>` · `osint social -u <user>` · `osint domain -t <domain>` | Single-source OSINT |
| `osint profile (-t <domain\|email>\|-u <user>)` | Full profile: fetch → persist entity → print |
| `export -t <target> -f <json\|html\|csv\|pdf> [-o file]` | Generate a report |
| `import-browsint <browsint.db>` | Migrate a legacy Browsint database |

Run without arguments for an interactive menu.

## Configuration & storage

- **Database:** `~/.gosint/gosint.db` (created on first run). Environment: `~/.gosint/.env`.
- **Management:** view stats, clear tables, or reset via the interactive menu (Settings).
- **API keys:** read from the environment (see Quick start).

## Project layout

```
cmd/main.go                     entry point (DB init, env, CLI dispatch)
internal/
  cli/         commands.go · menu.go        cobra commands + interactive TUI
  scanner/     dns · whois · subdomain · tech · passive · scanner
  crawler/     crawler · extractor          crawl + email/phone extraction
  fuzzer/      fuzzer · wordlists           fuzzing engine + embedded lists
  osint/       email · social · domain · client · config
    entities/  extractor · contacts · structured · profile   OSINT entity pipeline
  storage/     database · models · queries · import_browsint  GORM + SQLite
  reports/     generator · html · pdf · json_csv             report generators
```

## Development

```bash
make check     # gofmt + go vet + build + go test ./...  (the gate before "done")
make test      # tests only
```

Tested packages: `storage`, `osint`, `osint/entities`, `crawler`.

## License

MIT.
