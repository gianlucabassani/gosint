package crawler

import (
	"regexp"
	"strings"
)

// Regex patterns ported from Browsint
var (
	// Matches standard emails
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	
	// Matches international phone numbers (simplified for broad capture)
	phoneRegex = regexp.MustCompile(`\+?[\d\s\-\(\)]{7,}`)
	
	// Excluded extensions to avoid false positives in emails
	excludedExtensions = []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".pdf", ".mp3", ".mp4"}
)

type ExtractedData struct {
	Emails []string
	Phones []string
}

func ExtractOSINT(content string) ExtractedData {
	return ExtractedData{
		Emails: extractEmails(content),
		Phones: extractPhones(content),
	}
}

func extractEmails(content string) []string {
	matches := emailRegex.FindAllString(content, -1)
	unique := make(map[string]bool)
	var validEmails []string

	for _, email := range matches {
		lowerEmail := strings.ToLower(email)
		
		// Filter out binary/asset false positives
		isAsset := false
		for _, ext := range excludedExtensions {
			if strings.HasSuffix(lowerEmail, ext) {
				isAsset = true
				break
			}
		}
		if isAsset {
			continue
		}

		if !unique[lowerEmail] {
			unique[lowerEmail] = true
			validEmails = append(validEmails, lowerEmail)
		}
	}
	return validEmails
}

func extractPhones(content string) []string {
	// Phone extraction is noisy, this is a basic filter matching Browsint's logic
	matches := phoneRegex.FindAllString(content, -1)
	unique := make(map[string]bool)
	var validPhones []string

	for _, phone := range matches {
		clean := strings.TrimSpace(phone)
		// Basic length check (7 to 15 digits is standard for phones)
		digits := countDigits(clean)
		if digits < 7 || digits > 15 {
			continue
		}
		
		if !unique[clean] {
			unique[clean] = true
			validPhones = append(validPhones, clean)
		}
	}
	return validPhones
}

func countDigits(s string) int {
	count := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			count++
		}
	}
	return count
}