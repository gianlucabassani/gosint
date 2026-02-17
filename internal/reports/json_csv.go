package reports

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strconv"
)

// JSONGenerator implements JSON export
type JSONGenerator struct{}

func (g *JSONGenerator) Generate(filePath string, data ReportData) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// CSVGenerator implements CSV export
type CSVGenerator struct{}

func (g *CSVGenerator) Generate(filePath string, data ReportData) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	// Header
	if err := writer.Write([]string{"Category", "Type", "Name/URL", "Value/Status", "Extra"}); err != nil {
		return err
	}

	// Target Info
	writer.Write([]string{"Target", "Info", data.Target, "", ""})
	writer.Write([]string{"Target", "ScanMode", data.ScanMode, "", ""})
	writer.Write([]string{"Target", "Date", data.ScanDate.String(), "", ""})

	// DNS
	for _, dns := range data.DNS {
		writer.Write([]string{"DNS", dns.Type, "Record", dns.Data, ""})
	}

	// Tech
	for _, tech := range data.Technologies {
		writer.Write([]string{"Technology", tech.Category, tech.Name, tech.Version, ""})
	}

	// Subdomains
	for _, sub := range data.Subdomains {
		writer.Write([]string{"Subdomain", "Active", sub.Subdomain, sub.IP, sub.Status})
	}

	// Fuzzing
	for _, fuzz := range data.Fuzzing {
		writer.Write([]string{"Fuzzing", fuzz.FuzzType, fuzz.URL, strconv.Itoa(fuzz.StatusCode), strconv.Itoa(fuzz.Size)})
	}

	return nil
}
