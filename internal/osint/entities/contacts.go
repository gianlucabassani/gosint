package entities

import (
	"strings"

	"github.com/gianlucabassani/gosint/internal/crawler"
)

// HarvestFromData recursively walks arbitrary OSINT data (maps, slices, strings)
// and returns the unique emails and phone numbers found within.
//
// This is the Go port of browsint's `_extract_and_save_contacts` recursive
// `find_contacts_recursive` helper. The actual email/phone recognition reuses
// gosint's existing, stricter extractors (crawler.ExtractEmails /
// crawler.ExtractPhoneNumbers — the latter validates via libphonenumber and
// rejects dates/IPs/sequences) rather than re-porting browsint's regexes.
func HarvestFromData(data any) (emails []string, phones []string) {
	emailSet := make(map[string]struct{})
	phoneSet := make(map[string]struct{})

	var walk func(item any)
	walk = func(item any) {
		switch v := item.(type) {
		case map[string]any:
			for k, val := range v {
				// Prioritise explicitly email-named fields (browsint heuristic):
				// still run the value through the extractor so malformed values
				// (e.g. "Contact: a@b.com") are cleaned rather than stored raw.
				if s, ok := val.(string); ok && strings.Contains(strings.ToLower(k), "email") {
					for _, e := range crawler.ExtractEmails(s) {
						emailSet[e] = struct{}{}
					}
				}
				walk(val)
			}
		case map[string]string:
			for _, val := range v {
				walk(val)
			}
		case []any:
			for _, it := range v {
				walk(it)
			}
		case []string:
			for _, it := range v {
				walk(it)
			}
		case string:
			for _, e := range crawler.ExtractEmails(v) {
				emailSet[e] = struct{}{}
			}
			for _, p := range crawler.ExtractPhoneNumbers(v) {
				phoneSet[p] = struct{}{}
			}
		}
	}
	walk(data)

	for e := range emailSet {
		emails = append(emails, e)
	}
	for p := range phoneSet {
		phones = append(phones, p)
	}
	return emails, phones
}
