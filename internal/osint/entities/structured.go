package entities

// ExtractStructuredFields distills the key fields from raw per-source OSINT data
// into a flat, queryable summary. Go port of browsint's `extract_structured_fields`
// (data_processing.py). The `source` selects the shape of the input.
//
// Supported sources: "domain" (whois/shodan/dns/wayback), "email" (hunterio/breaches),
// "social" (profiles). Unknown sources yield an empty map.
func ExtractStructuredFields(data map[string]any, source string) map[string]any {
	out := map[string]any{}
	if len(data) == 0 {
		return out
	}

	switch source {
	case "domain":
		if whois, ok := asMap(data["whois"]); ok {
			out["registrar"] = str(whois["registrar"])
			out["creation_date"] = firstStr(whois, "creation_date", "created")
			out["expiration_date"] = firstStr(whois, "expiration_date", "expires")
			out["domain_name"] = firstStr(whois, "domain_name", "domain")
			out["org"] = str(whois["org"])
			out["name_servers"] = whois["name_servers"]
		}
		if shodan, ok := asMap(data["shodan"]); ok {
			out["ip"] = str(shodan["ip_str"])
			out["ports"] = shodan["ports"]
			out["hostnames"] = shodan["hostnames"]
			out["isp"] = str(shodan["isp"])
			out["org"] = str(shodan["org"])
		}
		if dns, ok := data["dns"]; ok {
			out["dns_records"] = dns
		}

	case "email":
		if hunter, ok := asMap(data["hunterio"]); ok {
			content := hunter
			if inner, ok := asMap(hunter["data"]); ok {
				content = inner
			}
			out["hunterio_status"] = firstStr(content, "status", "result")
			out["hunterio_score"] = content["score"]
			out["hunterio_disposable"] = content["disposable"]
			out["hunterio_webmail"] = content["webmail"]
		}
		if breaches, ok := data["breaches"].([]any); ok {
			out["breach_count"] = len(breaches)
			sites := []string{}
			for i, b := range breaches {
				if i >= 5 {
					break
				}
				if bm, ok := asMap(b); ok {
					sites = append(sites, str(bm["Name"]))
				}
			}
			out["breached_sites"] = sites
		}

	case "social":
		if profiles, ok := asMap(data["profiles"]); ok {
			found := map[string]any{}
			for platform, details := range profiles {
				if dm, ok := asMap(details); ok {
					if exists, _ := dm["exists"].(bool); exists {
						found[platform] = dm["url"]
					}
				}
			}
			out["social_media_presence"] = found
			out["platform_count"] = len(found)
		}
	}

	return out
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// firstStr returns the first non-empty string value among the given keys.
func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
