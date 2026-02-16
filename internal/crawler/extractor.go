package crawler

import (
	"log"
	"regexp"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

var logger = log.New(log.Writer(), "osint.extractors: ", log.LstdFlags|log.Lshortfile)

// Email regex pattern
var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

var excludedExtensions = []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".pdf", ".doc", ".mp3", ".mp4"}

var excludedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^[0-9a-f]{32}@`),                                             // MD5 hash
	regexp.MustCompile(`^[0-9a-f]{8}[0-9a-f]{4}[0-9a-f]{4}[0-9a-f]{4}[0-9a-f]{12}@`), // UUID
}

var excludedDomains = map[string]bool{
	"example.com": true, "domain.com": true, "test.com": true, "sentry.io": true,
	"wixpress.com": true,
}

// Filters for common false positives
var datePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^20\d{6}$`),     // YYYYMMDD
	regexp.MustCompile(`^\d{8}$`),       // 8 digits (often dates/IDs)
	regexp.MustCompile(`^(19|20)\d{2}`), // Starts with year
}
var ipPattern = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

type ExtractedData struct {
	Emails []string
	Phones []string
}

func ExtractOSINT(content string) ExtractedData {
	return ExtractedData{
		Emails: ExtractEmails(content),
		Phones: ExtractPhoneNumbers(content),
	}
}

// ExtractPhoneNumbers uses Regex to find candidates, then strictly validates them using libphonenumber
func ExtractPhoneNumbers(text string) []string {
	logger.Println("Starting phone number extraction...")
	foundPhones := make(map[string]bool)
	var phones []string

	// 1. Regex to find CANDIDATES (Loose match)
	// Catches: (555) 123-4567, +1-555-123-4567, 555.123.4567
	// We are slightly restrictive to avoid picking up single digits or short garbage
	phoneRegex := regexp.MustCompile(`\+?[\d\s\-\(\)\.]{7,}`)
	matches := phoneRegex.FindAllString(text, -1)

	for _, match := range matches {
		// Clean up match (trim whitespace)
		match = strings.TrimSpace(match)

		// 2. Parse with Default Region "US"
		// This handles local numbers like "650-253-0000" correctly.
		// If the number starts with +, the region param is ignored by the library.
		numObj, err := phonenumbers.Parse(match, "US")
		if err != nil {
			continue // Not a parseable number
		}

		// 3. STRICT VALIDATION
		// This is the key fix. IsValidNumber checks length, prefixes, and region rules.
		if !phonenumbers.IsValidNumber(numObj) {
			continue // Skip invalid numbers (garbage)
		}

		// 4. Format to E.164 (Standard +CountryCode Format)
		formatted := phonenumbers.Format(numObj, phonenumbers.E164)

		// 5. Post-Validation Heuristics (Remove Dates/IPs that happened to be valid numbers)
		if isFalsePositive(formatted) {
			continue
		}

		if !foundPhones[formatted] {
			foundPhones[formatted] = true
			phones = append(phones, formatted)
			logger.Printf("Found Valid Phone: %s", formatted)
		}
	}

	logger.Printf("Extraction complete. Found %d valid numbers.", len(phones))
	return phones
}

func ExtractEmails(text string) []string {
	matches := emailRegex.FindAllString(text, -1)
	uniqueEmails := make(map[string]bool)
	var validEmails []string

	for _, email := range matches {
		lower := strings.ToLower(email)
		
		// 1. Check Extensions
		isAsset := false
		for _, ext := range excludedExtensions {
			if strings.HasSuffix(lower, ext) {
				isAsset = true; break
			}
		}
		if isAsset { continue }

		// 2. Check Excluded Domains
		parts := strings.Split(lower, "@")
		if len(parts) == 2 && excludedDomains[parts[1]] {
			continue
		}

		if !uniqueEmails[lower] {
			uniqueEmails[lower] = true
			validEmails = append(validEmails, lower)
		}
	}
	return validEmails
}

// isFalsePositive catches numbers that are technically valid but likely garbage
func isFalsePositive(phone string) bool {
	// Remove the '+' for analysis
	clean := strings.TrimPrefix(phone, "+")

	// 1. Check if it matches an IP address structure
	if ipPattern.MatchString(clean) { return true }

	// 2. Check for Sequential numbers (e.g. +1 12345678)
	if isSequential(clean) { return true }

	// 3. Check for Repeats (e.g. +1 00000000)
	if isRepeated(clean) { return true }

	// 4. Check for Date-like patterns
	for _, p := range datePatterns {
		if p.MatchString(clean) { return true }
	}

	return false
}

func isSequential(s string) bool {
	if len(s) < 6 { return false }
	count := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i+1] == s[i]+1 {
			count++
		} else {
			count = 0
		}
		if count > 4 { return true }
	}
	return false
}

func isRepeated(s string) bool {
	if len(s) < 6 { return false }
	count := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i+1] == s[i] {
			count++
		} else {
			count = 0
		}
		if count > 4 { return true }
	}
	return false
}