package reports

import (
	"time"

	"github.com/gianlucabassani/gosint/internal/storage"
)

// ReportData holds all information needed for report generation
type ReportData struct {
	Target   string
	ScanDate time.Time
	Duration string
	ScanMode string

	// Data from DB
	TargetObj    *storage.Target
	DNS          []storage.ScanResult
	WHOIS        storage.ScanResult
	Technologies []storage.Technology
	Subdomains   []storage.Subdomain
	Fuzzing      []storage.FuzzResult
	Wayback      storage.ScanResult
}

// Generator defines the interface for different report formats
type Generator interface {
	Generate(filePath string, data ReportData) error
}

// GenerateReport is the main entry point to generate a report
func GenerateReport(format, filePath string, data ReportData) error {
	var gen Generator

	switch format {
	case "html":
		gen = &HTMLGenerator{}
	case "pdf":
		gen = &PDFGenerator{}
	case "json":
		gen = &JSONGenerator{}
	case "csv":
		gen = &CSVGenerator{}
	default:
		return nil
	}

	return gen.Generate(filePath, data)
}
