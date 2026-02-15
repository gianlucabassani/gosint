# GoSint - Go Security Intelligence Toolkit

A comprehensive security reconnaissance and intelligence gathering tool written in Go. GoSint automates domain and IP reconnaissance, technology detection, subdomain enumeration, and directory/vhost fuzzing.

## Features

- **DNS Reconnaissance** - Query DNS records for domains and IPs
- **WHOIS Lookups** - Retrieve WHOIS information for targets
- **Technology Detection** - Identify tech stacks used by websites
- **Subdomain Enumeration** - Discover subdomains using wordlists and concurrent checking
- **Directory Fuzzing** - Fuzz for hidden directories and files
- **Virtual Host Discovery** - Find vhosts associated with target IPs
- **Persistent Storage** - Store and query reconnaissance results in SQLite database
- **Multiple Scan Modes** - Basic, deep, stealth, and aggressive scanning modes

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

Interactive:
```bash
./gosint
```

CLI commands:
```bash
./gosint [command] [options]
```

### Available Commands
Run `./gosint --help` for a complete list of commands.

## Project Structure

```
.
├── cmd/
│   └── main.go           # Entry point
├── internal/
│   ├── cli/              # CLI commands and menus
│   ├── scanner/          # Reconnaissance modules
│   │   ├── dns.go        # DNS queries
│   │   ├── whois.go      # WHOIS lookups
│   │   ├── subdomain.go  # Subdomain enumeration
│   │   ├── tech.go       # Tech detection
│   │   └── scanner.go    # Main scanning orchestration
│   ├── fuzzer/           # Directory and vhost fuzzing
│   ├── storage/          # Database models and queries
│   ├── crawler/          
│   └── config/           
├── go.mod
├── go.sum
└── README.md
```

## Configuration

Database is stored at `~/.gosint/gosint.db` and is automatically created on first run.

Wordlists for fuzzing are located in `internal/fuzzer/wordlists/`:
- `subdomains.txt` - Subdomain wordlist
- `directories.txt` - Directory fuzzing wordlist
- `vhosts.txt` - Virtual host wordlist

## Scan Modes

- **Basic** - DNS lookups and basic WHOIS queries
- **Deep** - Includes technology detection and subdomain enumeration
- **Stealth** - Slower but less detectable scanning
- **Aggressive** - All techniques with higher concurrency

## Implementation Notes

- Subdomain enumeration uses concurrent goroutines (10 workers) for fast, parallel checking
- HTTP status codes 200-399 are considered valid responses
- DNS lookups are performed for all discovered subdomains
- All results are persisted to the SQLite database for historical tracking

## TODO

- [ ] Web crawling functionality
- [ ] Configuration file support
- [ ] Custom wordlist support
- [ ] Export functionality (JSON, CSV)
- [ ] API endpoint scanning
- [ ] SSL/TLS certificate analysis

