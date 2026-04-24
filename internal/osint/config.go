package osint

import "os"

// LoadAPIKeys reads OSINT API credentials from the environment.
// The environment is pre-populated by config.LoadEnv() at application startup,
// which reads from ~/.gosint/.env. Keys can also be set manually via the
// Settings → Manage API Keys menu.
func LoadAPIKeys() APIKeys {
	return APIKeys{
		HIBP:    os.Getenv("HIBP_API_KEY"),
		HunterIO: os.Getenv("HUNTER_API_KEY"),
		Shodan:  os.Getenv("SHODAN_API_KEY"),
	}
}
