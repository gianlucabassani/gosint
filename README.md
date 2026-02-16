# GOSINT - Go Security Intelligence Toolkit

A command-line OSINT and reconnaissance toolkit written in Go, inspired by Browsint.

## Features

**Domain Reconnaissance**
- 5 scan modes: Basic, Deep, Stealth, Aggressive, Custom
- DNS enumeration (A, AAAA, MX, NS, TXT records)
- WHOIS lookups
- Technology stack detection
- Passive intelligence (crt.sh, Wayback Machine)
- Active subdomain enumeration

**Web Crawling**
- Email harvesting
- Phone number detection
- Link discovery
- Configurable depth and concurrency

**Fuzzing**
- Directory fuzzing
- Subdomain fuzzing
- Virtual host discovery
- Embedded wordlists

**Storage**
- SQLite database for persistent results
- Database management and statistics

**Interface**
- Clean Unicode box-drawing output
- Interactive menu system
- CLI mode for automation

## Installation

### Prerequisites
- Go 1.18 or higher

### Build
```bash
git clone https://github.com/yourusername/gosint.git
cd gosint
go mod download
go build -o gosint ./cmd
```

### Dependencies
- `github.com/pterm/pterm` - Terminal UI
- `github.com/spf13/cobra` - CLI framework
- `gorm.io/gorm` - Database ORM
- `gorm.io/driver/sqlite` - SQLite driver

## Quick Start

### Interactive Mode
```bash
./gosint
```

Navigate through menus to:
1. Domain Reconnaissance - Scan domains with different intensity levels
2. Web Crawler - Extract OSINT data from websites
3. Fuzzing - Discover hidden infrastructure
4. OSINT Investigation - Coming soon
5. Settings - Database management

### CLI Mode

**Domain Scanning:**
```bash
# Basic passive scan
./gosint scan -t example.com --basic

# Deep passive scan (includes crt.sh, Wayback)
./gosint scan -t example.com --deep

# Stealth active scan (limited subdomain enumeration)
./gosint scan -t example.com --stealth

# Aggressive scan (full enumeration + fuzzing)
./gosint scan -t example.com --aggressive

# Custom scan (choose features)
./gosint scan -t example.com --custom \
  --enable-dns --enable-whois --enable-tech \
  --enable-passive --enable-subdomains \
  --subdomain-limit 100 --verbose
```

**Web Crawling:**
```bash
./gosint crawl -u https://example.com -D 2
```

**Fuzzing:**
```bash
# Directory fuzzing
./gosint fuzz -u https://example.com -m directory

# Subdomain fuzzing
./gosint fuzz -t example.com -m subdomain

# Virtual host fuzzing
./gosint fuzz -t 192.168.1.1 -m vhost
```

## Scan Modes

### BASIC - Passive Infrastructure Analysis
**Techniques:**
- DNS enumeration (A, AAAA, MX, NS, TXT records)
- WHOIS domain registration data
- Technology stack detection

**Target Interaction:** None - only DNS and WHOIS queries  
**Detection Risk:** Minimal  
**Use Case:** Initial reconnaissance, compliance scanning  
**CLI:** `./gosint scan -t example.com --basic`

### DEEP - External Passive Intelligence
**Techniques:**
- All BASIC techniques
- Certificate Transparency (crt.sh) subdomain enumeration
- Wayback Machine historical crawling

**Target Interaction:** None - queries public archives only  
**Detection Risk:** None (completely passive)  
**Use Case:** Passive intelligence gathering, historical analysis  
**CLI:** `./gosint scan -t example.com --deep`

### STEALTH - Limited Active Enumeration
**Techniques:**
- All BASIC techniques
- Reduced subdomain wordlist (50 entries)
- Rate-limited HTTP probing

**Target Interaction:** Active but minimal  
**Detection Risk:** Low  
**Use Case:** Authorized testing with OPSEC requirements  
**CLI:** `./gosint scan -t example.com --stealth`

### AGGRESSIVE - Comprehensive Active Scanning
**Techniques:**
- All BASIC techniques
- Full subdomain enumeration
- Directory fuzzing (50 concurrent threads)
- Virtual host discovery

**Target Interaction:** Extensive active probing  
**Detection Risk:** Very High  
**Use Case:** Full authorized security assessments  
**CLI:** `./gosint scan -t example.com --aggressive`

### CUSTOM - User-Defined Configuration
**Techniques:** User-selected features  
**CLI:** `./gosint scan -t example.com --custom [options]`

**Available Options:**
- `--enable-dns` - DNS enumeration
- `--enable-whois` - WHOIS lookup
- `--enable-tech` - Technology detection
- `--enable-passive` - crt.sh + Wayback Machine
- `--enable-subdomains` - Active subdomain enumeration
- `--enable-fuzzing` - Directory/vhost fuzzing
- `--subdomain-limit N` - Limit subdomain wordlist (0=unlimited)
- `--subdomain-threads N` - Concurrent subdomain checks
- `--fuzz-threads N` - Concurrent fuzzing threads
- `--fuzz-directories` - Enable directory fuzzing
- `--fuzz-vhosts` - Enable vhost fuzzing
- `--http-timeout N` - HTTP timeout in seconds
- `--verbose` - Detailed output

## Output Example

```
╔════════════════════════════════════════════════════════╗
║          DOMAIN RECONNAISSANCE SCAN                    ║
╚════════════════════════════════════════════════════════╝

┌─ Target:      example.com
├─ Mode:        deep
└─ Description: The Historian - Public records only

  ▶ Enabled modules: DNS, WHOIS, Tech, Passive

⏳ Resolving DNS records...

┏━━━━━━━━━━━━━━━━━━━ DNS RECORDS ━━━━━━━━━━━━━━━━━━━┓
  ┌─ Record A:
  │  └─ 93.184.216.34
  ┌─ Record MX:
  │  └─ mail.example.com
  ┌─ Record NS:
  │  └─ ns1.example.com
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

⏳ Querying WHOIS database...

┏━━━━━━━━━━━━━━━━━ WHOIS DATA ━━━━━━━━━━━━━━━━━┓
  ┌─ Registrar:  Amazon Registrar, Inc.
  ├─ Created:    2019-08-05
  └─ Expires:    2026-08-05
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

⏳ Starting passive reconnaissance...

┏━━━━━━━━━━━━━━━ PASSIVE INTELLIGENCE ━━━━━━━━━━━━━━┓
  ▶ Subdomains (crt.sh): 23 found
  ▶ Archived URLs (Wayback): 147 found
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

╔════════════════════════════════════════════════════════╗
║                  SCAN COMPLETE                         ║
╚════════════════════════════════════════════════════════╝

┏━━━━━━━━━━━━━━ SCAN RESULTS SUMMARY ━━━━━━━━━━━━━━┓
  ▶ DNS Records:         4
  ▶ WHOIS Data:          Available
  ▶ Technologies:        3 detected
  ▶ Passive Subdomains:  23
  ▶ Archived URLs:       147
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## Web Crawler

Extract OSINT data from websites recursively.

**Features:**
- Email harvesting (pattern: `name@domain.com`)
- Phone number detection (patterns: `+1-234-567-8900`, `(123) 456-7890`)
- Link discovery
- Configurable depth (default: 2)
- 10 concurrent crawlers
- Scoped to target domain

**Usage:**
```bash
./gosint crawl -u https://example.com -D 3
```

**Data Storage:**
All extracted emails and phone numbers are saved to the database with source URLs.

## Fuzzing

Discover hidden infrastructure using embedded wordlists.

**Directory Fuzzing:**
- Discovers hidden web paths and files
- HTTP status codes: 200, 204, 301, 302, 307, 401, 403 considered valid
- Default threads: 40

```bash
./gosint fuzz -u https://example.com -m directory -T 50
```

**Subdomain Fuzzing:**
- DNS-based subdomain discovery
- Tests common subdomain names
- Default threads: 40

```bash
./gosint fuzz -t example.com -m subdomain
```

**Virtual Host Fuzzing:**
- Discovers vhosts on shared hosting
- Tests Host header variations
- Default threads: 40

```bash
./gosint fuzz -t 192.168.1.1 -m vhost
```

**Embedded Wordlists:**
- `directories.txt` - 5,000 web paths
- `subdomains.txt` - 10,000 subdomain names
- `vhosts.txt` - 1,000 virtual host names

## Database

Results are automatically stored in `~/.gosint/gosint.db`

**Management:**
- View database statistics
- Clear specific tables
- Reset entire database
- Historical tracking of all results

**Access:**
```bash
./gosint  # Interactive menu > Settings > Database Management
```

## Project Structure

```
gosint/
├── cmd/
│   └── main.go              # Entry point
├── internal/
│   ├── cli/
│   │   ├── commands.go      # CLI commands
│   │   └── menu.go          # Interactive menu
│   ├── scanner/
│   │   ├── scanner.go       # Scan orchestrator
│   │   ├── dns.go           # DNS queries
│   │   ├── whois.go         # WHOIS lookups
│   │   ├── subdomain.go     # Subdomain enumeration
│   │   ├── tech.go          # Technology detection
│   │   └── passive.go       # Passive reconnaissance
│   ├── crawler/
│   │   ├── crawler.go       # Web crawler
│   │   └── extractor.go     # OSINT extraction
│   ├── fuzzer/
│   │   ├── fuzzer.go        # Fuzzing engine
│   │   ├── wordlists.go     # Wordlist manager
│   │   └── wordlists/       # Embedded wordlists
│   └── storage/
│       ├── database.go      # DB initialization
│       ├── models.go        # Data models
│       └── queries.go       # DB operations
├── go.mod
└── README.md
```

## Performance

- **DNS Queries:** 10 concurrent workers, 5s timeout
- **Subdomain Enumeration:** 5-50 workers (mode-dependent)
- **Web Crawling:** 10 concurrent crawlers
- **Directory Fuzzing:** Up to 50 concurrent threads
- **Passive Recon:** Parallel execution (45% faster)


## Technical Details

**Architecture:**
- Concurrent design using Go goroutines
- Context-based cancellation for all operations
- Clean signal handling (menu vs operation contexts)
- GORM ORM with SQLite for persistence


## License

MIT License
