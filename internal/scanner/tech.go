package scanner

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// TechResult holds all detected technologies
type TechResult struct {
	WebServer       string            `json:"web_server"`
	Frameworks      []string          `json:"frameworks"`
	JSLibraries     []string          `json:"js_libraries"`
	Analytics       []string          `json:"analytics"`
	SecurityHeaders map[string]string `json:"security_headers"`
	MetaTags        map[string]string `json:"meta_tags"`
}

// AnalyzeTech performs comprehensive technology detection by analyzing HTTP responses
func AnalyzeTech(targetURL string) (*TechResult, error) {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	result := &TechResult{
		Frameworks:      []string{},
		JSLibraries:     []string{},
		Analytics:       []string{},
		SecurityHeaders: make(map[string]string),
		MetaTags:        make(map[string]string),
	}

	// Fetch Content with SSL skip
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)
	headers := resp.Header

	// Server Header
	if server := headers.Get("Server"); server != "" {
		result.WebServer = server
	}

	// Detect Frameworks / CMS
	detectFrameworks(result, headers, body, targetURL)

	// Detect JS Libraries
	detectJSLibraries(result, body)

	// Detect Analytics
	detectAnalytics(result, body)

	// Check Security Headers
	checkSecurityHeaders(result, headers)

	return result, nil
}

func detectFrameworks(r *TechResult, headers http.Header, body string, url string) {
	// Header Checks
	if powered := headers.Get("X-Powered-By"); powered != "" {
		r.Frameworks = append(r.Frameworks, "Powered-By: "+powered)
	}
	if gen := headers.Get("X-Generator"); gen != "" {
		r.Frameworks = append(r.Frameworks, "Generator: "+gen)
	}

	// Meta Generator Check
	metaGenRe := regexp.MustCompile(`(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	if match := metaGenRe.FindStringSubmatch(body); len(match) > 1 {
		r.Frameworks = append(r.Frameworks, strings.TrimSpace(match[1]))
	}

	// Content Signatures
	if strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes") {
		addUnique(r, "WordPress")
	}
	if strings.Contains(body, "drupal-css") {
		addUnique(r, "Drupal")
	}
	if strings.Contains(body, "joomla") {
		addUnique(r, "Joomla")
	}
	if strings.Contains(body, "Powered by Shopify") {
		addUnique(r, "Shopify")
	}
	if strings.Contains(body, "squarespace.com") {
		addUnique(r, "Squarespace")
	}
	if strings.Contains(body, "wix.com") {
		addUnique(r, "Wix")
	}

	// URL Pattern Checks
	if strings.Contains(url, "/wp-admin") || strings.Contains(url, "/wp-login") {
		addUnique(r, "WordPress")
	}
}

func detectJSLibraries(r *TechResult, body string) {
	// Pattern map
	patterns := map[string]string{
		"jQuery":    `jquery(-[0-9\.]*(\.min)?\.js|\.js)|window\.jQuery|\$\(|jQuery\(`,
		"React":     `react(-dom)?(-[0-9\.]*(\.min)?\.js|\.js)|React\.createElement|ReactDOM\.render`,
		"Angular":   `angular(-[0-9\.]*(\.min)?\.js|\.js)|ng-app|angular\.module`,
		"Vue.js":    `vue(-[0-9\.]*(\.min)?\.js|\.js)|new Vue\(`,
		"Bootstrap": `bootstrap(-[0-9\.]*(\.bundle|\.min)?\.js|\.js)`,
		"Lodash":    `lodash(-[0-9\.]*(\.min)?\.js|\.js)`,
		"Moment.js": `moment(-[0-9\.]*(\.min)?\.js|\.js)`,
		"D3.js":     `d3(-[0-9\.]*(\.min)?\.js|\.js)`,
	}

	for name, pattern := range patterns {
		re := regexp.MustCompile("(?i)" + pattern)
		if re.MatchString(body) {
			r.JSLibraries = append(r.JSLibraries, name)
		}
	}
}

func detectAnalytics(r *TechResult, body string) {
	if regexp.MustCompile(`(www\.google-analytics\.com/analytics\.js|gtag\('config', 'UA-|gtag\('config', 'G-)`).MatchString(body) {
		r.Analytics = append(r.Analytics, "Google Analytics")
	}
	if strings.Contains(body, "googletagmanager.com/gtm.js") {
		r.Analytics = append(r.Analytics, "Google Tag Manager")
	}
	if strings.Contains(body, "connect.facebook.net/en_US/fbevents.js") || strings.Contains(body, "fbq('init'") {
		r.Analytics = append(r.Analytics, "Facebook Pixel")
	}
	if strings.Contains(body, "matomo.js") || strings.Contains(body, "piwik.js") {
		r.Analytics = append(r.Analytics, "Matomo")
	}
	if strings.Contains(body, "static.hotjar.com") || strings.Contains(body, "hj('event'") {
		r.Analytics = append(r.Analytics, "Hotjar")
	}
	if strings.Contains(body, "js.hs-scripts.com") {
		r.Analytics = append(r.Analytics, "HubSpot")
	}
}

func checkSecurityHeaders(r *TechResult, headers http.Header) {
	secHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Frame-Options":           "X-Frame-Options",
		"X-Content-Type-Options":    "X-Content-Type-Options",
		"Referrer-Policy":           "Referrer-Policy",
		"Permissions-Policy":        "Permissions-Policy",
		"X-XSS-Protection":          "X-XSS-Protection",
	}

	for header, display := range secHeaders {
		if val := headers.Get(header); val != "" {
			r.SecurityHeaders[display] = val
		}
	}
}

func addUnique(r *TechResult, val string) {
	for _, v := range r.Frameworks {
		if v == val {
			return
		}
	}
	r.Frameworks = append(r.Frameworks, val)
}
