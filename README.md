# GOSINT - Go Security Intelligence Toolkit

A comprehensive, command-line security intelligence and reconnaissance tool written in Go. GOSINT provides automated domain reconnaissance, web crawling for OSINT data extraction, infrastructure fuzzing, and persistent result storage.

## Features

### ✅ Implemented
- **Interactive Menu System** - User-friendly CLI menu for all operations
- **Domain Reconnaissance** - 4 scan modes (Basic, Deep, Stealth, Aggressive)
  - DNS enumeration (A, AAAA, MX, NS, CNAME, TXT records)
  - WHOIS lookups
  - Technology detection (servers, frameworks, CMS platforms)
  - Subdomain enumeration
- **Web Crawling** - Recursive website crawling with OSINT data extraction
  - Email harvesting
  - Phone number extraction
  - Link discovery
  - Configurable depth and concurrency
- **Fuzzing** - Multi-mode fuzzing with embedded wordlists
  - Directory fuzzing (web paths)
  - Subdomain fuzzing (DNS)
  - Virtual host discovery
  - Configurable threads and HTTP status codes
- **Persistent Storage** - SQLite database for storing all reconnaissance results
- **Ctrl+C Handling** - Clean signal handling
  - Ctrl+C in menu: Exit program
  - Ctrl+C during operations: Stop operation, return to menu

### 🔄 In Progress
- OSINT Investigation module (profile domains, emails, usernames)
- Settings & configuration management

### 📋 TODO
- Configuration file support (.gosint.yaml)
- Custom wordlist support
- Export functionality (JSON, CSV, HTML reports)
- API endpoint scanning
- SSL/TLS certificate analysis

## Installation

### Prerequisites
- Go 1.18 or higher

### Build
```bash
go build -o gosint ./cmd
```

### Dependencies
All dependencies are managed via `go.mod`:
- `gorm.io/gorm` - Database ORM
- `gorm.io/driver/sqlite` - SQLite driver
- `github.com/spf13/cobra` - CLI framework
- `github.com/fatih/color` - Colored terminal output

## Usage

### Interactive Mode (Default)
```bash
./gosint
```

Launch the interactive menu and choose from:
1. **Domain Reconnaissance** - Scan domains with 4 different intensity levels
2. **Web Crawler** - Crawl websites to extract emails, phones, and metadata
3. **Fuzzing** - Fuzz for directories, subdomains, or virtual hosts
4. **OSINT Investigation** - Coming in Phase 3 (profile domains/emails/usernames)
5. **Settings** - Database management and result viewing

**Keyboard Shortcuts:**
- `Ctrl+C` in menu: Exit the program
- `Ctrl+C` during scanning: Stop operation and return to menu

### CLI Mode
```bash
./gosint scan -t example.com -b         # Basic scan
./gosint scan -t example.com -d         # Deep passive scan
./gosint scan -t example.com -s         # Stealth active scan
./gosint scan -t example.com -a         # Aggressive scan
./gosint crawl -u https://example.com   # Web crawling
./gosint fuzz -t example.com            # Subdomain fuzzing
```

Run `./gosint --help` for complete command documentation.

## Project Structure

```
.
├── cmd/
│   └── main.go                    # Application entry point
├── internal/
│   ├── cli/
│   │   ├── commands.go            # CLI command definitions
│   │   ├── menu.go                # Interactive menu system
│   │   └── Execute()              # Main CLI entry point
│   ├── scanner/                   # Reconnaissance modules
│   │   ├── scanner.go             # Main scan orchestrator (4 modes)
│   │   ├── dns.go                 # DNS record queries
│   │   ├── whois.go               # WHOIS lookups
│   │   ├── subdomain.go           # Subdomain enumeration
│   │   ├── tech.go                # Technology detection
│   │   ├── passive.go             # External passive queries (crt.sh, Wayback)
│   │   └── models.go              # Scan result structures
│   ├── crawler/                   # Web crawling module
│   │   ├── crawler.go             # Main crawler implementation
│   │   ├── extractor.go           # OSINT data extraction (emails, phones)
│   │   └── models.go              # Crawl result structures
│   ├── fuzzer/                    # Fuzzing module
│   │   ├── fuzzer.go              # Main fuzzer implementation
│   │   ├── wordlists.go           # Embedded wordlist management
│   │   ├── models.go              # Fuzz result structures
│   │   └── wordlists/             # Embedded wordlists
│   │       ├── directories.txt    # Web directory paths
│   │       ├── subdomains.txt     # Common subdomains
│   │       └── vhosts.txt         # Virtual hosts
│   ├── storage/                   # Database layer
│   │   ├── database.go            # Database initialization & queries
│   │   ├── models.go              # Database models (GORM)
│   │   └── queries.go             # Database operations
│   └── config/                    # Configuration management
├── go.mod & go.sum               # Dependency management
├── gosint                         # Compiled binary (after build)
└── README.md
```

## Database

GOSINT automatically creates and manages an SQLite database at `~/.gosint/gosint.db`.

### Available Commands
- View database statistics
- Clear specific tables
- Reset entire database
- Export scan results (coming soon)

All reconnaissance and fuzzing results are automatically persisted for historical tracking and future analysis.

## Wordlists

Fuzzing uses embedded wordlists for maximum portability:

- **directories.txt** - Common web directories and file paths (~5,000 entries)
- **subdomains.txt** - Common subdomain names (~10,000 entries)
- **vhosts.txt** - Virtual host names (~1,000 entries)

Custom wordlists can be specified in interactive mode.

## Scanning Modes

GOSINT provides 4 distinct reconnaissance modes tailored for different objectives and risk profiles:

### 1. **BASIC** - Passive Infrastructure Analysis
- **Techniques**:
  - DNS enumeration (A, AAAA, MX, NS, CNAME, SOA, TXT records)
  - WHOIS domain registration data
  - Technology stack detection
- **Target Interaction**: None - only DNS and WHOIS queries
- **Detection Risk**: ⭐ Minimal
- **Use Case**: Initial reconnaissance, compliance scanning, non-intrusive assessment
- **CLI**: `./gosint scan -t example.com -b`

### 2. **DEEP** - External Passive Intelligence
- **Techniques**:
  - All BASIC techniques
  - Certificate Transparency (crt.sh) subdomain enumeration
  - Wayback Machine (CDX API) historical crawling
  - External passive service queries
- **Target Interaction**: None - queries public archives only
- **Detection Risk**: ⭐ None (completely passive)
- **Use Case**: Deep passive intelligence, historical analysis, subdomain discovery without detection
- **CLI**: `./gosint scan -t example.com -d`

### 3. **STEALTH** - Limited Active Enumeration
- **Techniques**:
  - All BASIC techniques
  - Reduced subdomain wordlist enumeration (50 entries)
  - Rate-limited, concurrent DNS checks
  - Limited HTTP probing (max 10 concurrent workers)
- **Target Interaction**: Active but minimal - limited requests spread over time
- **Detection Risk**: ⭐⭐ Low
- **Use Case**: Authorized penetration testing with OPSEC, careful active enumeration, compliance testing
- **CLI**: `./gosint scan -t example.com -s`

### 4. **AGGRESSIVE** - Comprehensive Active Scanning
- **Techniques**:
  - All BASIC techniques
  - Full subdomain enumeration (complete wordlist)
  - Directory fuzzing (50 concurrent threads)
  - Virtual host discovery
  - Comprehensive HTTP probing
- **Target Interaction**: Extensive active probing - high volume of requests
- **Detection Risk**: ⭐⭐⭐⭐⭐ Very High
- **Use Case**: Full authorized red team exercises, security assessments with explicit permission, comprehensive engagement
- **CLI**: `./gosint scan -t example.com -a`

### Scan Mode Comparison

| Feature | BASIC | DEEP | STEALTH | AGGRESSIVE |
|---------|-------|------|---------|-----------|
| DNS/WHOIS Lookup | ✅ | ✅ | ✅ | ✅ |
| Technology Detection | ✅ | ✅ | ✅ | ✅ |
| Certificate Transparency | ❌ | ✅ | ✅ | ✅ |
| Wayback Machine | ❌ | ✅ | ✅ | ✅ |
| Subdomain Enumeration | ❌ | ❌ | ✅ (50) | ✅ (Full) |
| Directory Fuzzing | ❌ | ❌ | ❌ | ✅ |
| Virtual Host Discovery | ❌ | ❌ | ❌ | ✅ |
| Request Volume | Minimal | Minimal | Low | Maximum |
| Detection Risk | None | None | Low | Very High |
| Stealth Rating | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐ |

## Web Crawler

The web crawler recursively explores websites to extract OSINT intelligence.

### Features
- **Email Harvesting** - Extracts email addresses from page content
- **Phone Number Detection** - Identifies phone numbers using pattern matching
- **Link Discovery** - Maps website structure and internal links
- **Scoped Crawling** - Stays within target domain boundaries
- **Concurrency** - 10 concurrent crawlers for efficient traversal
- **Depth Limiting** - Configurable crawl depth (default: 2)

### Usage
```bash
./gosint                           # Interactive mode, select "Web Crawler"
./gosint crawl -u https://example.com -d 3   # CLI mode with depth 3
```

### Data Extraction
Results are automatically scanned for:
- Email patterns: `name@domain.com`
- Phone patterns: `+1-234-567-8900`, `(123) 456-7890`, etc.
- All results stored in database with source URLs

## Fuzzing

Three fuzzing modes for comprehensive infrastructure discovery.

### 1. **Directory Fuzzing**
- Discovers hidden web directories and files
- Uses HTTP status codes to identify valid paths
- Responses: 200, 204, 301, 302, 307, 401, 403 considered valid
- Configurable threads (default: 40)
- CLI: `./gosint fuzz -t https://example.com -m directory`

### 2. **Subdomain Fuzzing**
- Discovers subdomains via DNS enumeration
- Tests common subdomain names against target
- Validates response with configurable timeout
- Configurable threads (default: 40)
- CLI: `./gosint fuzz -t example.com -m subdomain`

### 3. **Virtual Host Fuzzing**
- Discovers virtual hosts on target server/IP
- Useful for shared hosting environments
- Tests Host header variations
- Configurable threads (default: 40)
- CLI: `./gosint fuzz -t 192.168.1.1 -m vhost`

All fuzzing results are persisted to the database for historical tracking.

## Database

GOSINT automatically creates and manages an SQLite database at `~/.gosint/gosint.db`.

### Features
- View database statistics
- Clear specific tables
- Reset entire database
- All reconnaissance and fuzzing results automatically persisted
- Historical tracking for future analysis

## Wordlists

Fuzzing uses embedded wordlists for maximum portability:

- **directories.txt** - Common web directories and file paths (~5,000 entries)
- **subdomains.txt** - Common subdomain names (~10,000 entries)  
- **vhosts.txt** - Virtual host names (~1,000 entries)

Custom wordlists can be specified in interactive mode.

## Technical Details

### Architecture
- **Concurrent Design** - Heavy use of Go goroutines for parallel enumeration
- **Context Cancellation** - All long-running operations support graceful interruption
- **Signal Handling** - Clean Ctrl+C handling distinguishes between menu and operation contexts
- **Database Persistence** - GORM ORM with SQLite for reliable result storage

### Performance Characteristics
- **DNS Queries**: 10 concurrent workers, timeout 5 seconds per query
- **Subdomain Enumeration**: Configurable concurrency (10 stealth, 50+ aggressive)
- **Web Crawling**: 10 concurrent crawlers with depth limiting
- **Directory Fuzzing**: Up to 50 concurrent threads in aggressive mode

### Security Considerations
- No credentials stored in plaintext
- Database is local and user-owned
- Signal handling allows stopping scans without data loss
- Configurable request rates to avoid detection or overload

