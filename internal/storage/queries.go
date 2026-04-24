package storage

import (
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"time"
)

// CreateOrUpdateTarget finds or creates a target
func (d *Database) CreateOrUpdateTarget(domain, targetType string) (*Target, error) {
	var target Target
	// search for existing target
	result := d.db.Where("domain = ?", domain).First(&target)

	// crate new target entry or update last scanned time
	if result.Error == gorm.ErrRecordNotFound {
		target = Target{
			Domain:      domain,
			Type:        targetType,
			CreatedAt:   time.Now(),
			LastScanned: time.Now(),
		}
		// save to db
		if err := d.db.Create(&target).Error; err != nil {
			return nil, err
		}
	} else {
		// update last scanned time
		target.LastScanned = time.Now()
		d.db.Save(&target)
	}

	return &target, nil
}

// SaveScanResult stores scan data
func (d *Database) SaveScanResult(targetID uint, scanMode, scanType string, data map[string]interface{}, requests int) error {
	jsonData, _ := json.Marshal(data)

	result := &ScanResult{
		TargetID:    targetID,
		ScanMode:    scanMode,
		Type:        scanType,
		Data:        string(jsonData),
		TotRequests: requests,
		CreatedAt:   time.Now(),
	}

	return d.db.Create(result).Error
}

// SaveFuzzResult stores fuzzing discovery
func (d *Database) SaveFuzzResult(targetID uint, fuzzType, url string, statusCode, size int, word string) error {
	result := &FuzzResult{
		TargetID:   targetID,
		FuzzType:   fuzzType,
		URL:        url,
		StatusCode: statusCode,
		Size:       size,
		WordUsed:   word,
		CreatedAt:  time.Now(),
	}

	return d.db.Create(result).Error
}

// GetTarget retrieves a target by domain
func (d *Database) GetTarget(domain string) (*Target, error) {
	var target Target
	result := d.db.Where("domain = ?", domain).
		Preload("ScanResults").
		Preload("FuzzResults").
		First(&target)

	if result.Error != nil {
		return nil, result.Error
	}

	return &target, nil
}

// GetAllTargets returns all scanned targets
func (d *Database) GetAllTargets() ([]Target, error) {
	var targets []Target
	result := d.db.Find(&targets)
	return targets, result.Error
}

// GetDatabaseStats returns statistics
func (d *Database) GetDatabaseStats() map[string]int64 {
	stats := make(map[string]int64)
	var count int64

	d.db.Model(&Target{}).Count(&count)
	stats["targets"] = count
	d.db.Model(&ScanResult{}).Count(&count)
	stats["scans"] = count
	d.db.Model(&FuzzResult{}).Count(&count)
	stats["fuzzing_hits"] = count
	d.db.Model(&Subdomain{}).Count(&count)
	stats["subdomains"] = count
	d.db.Model(&Technology{}).Count(&count)
	stats["technologies"] = count
	d.db.Model(&EmailProfile{}).Count(&count)
	stats["email_profiles"] = count
	d.db.Model(&BreachEntry{}).Count(&count)
	stats["breaches"] = count
	d.db.Model(&SocialProfile{}).Count(&count)
	stats["social_profiles"] = count

	return stats
}

// ClearTable empties a specific table
func (d *Database) ClearTable(tableName string) error {
	switch tableName {
	case "targets":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Target{}).Error
	case "scan_results":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ScanResult{}).Error
	case "fuzz_results":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&FuzzResult{}).Error
	case "subdomains":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Subdomain{}).Error
	case "technologies":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Technology{}).Error
	default:
		return fmt.Errorf("unknown table: %s", tableName)
	}
}

// ClearAllTables empties all tables
func (d *Database) ClearAllTables() error {
	tables := []string{"targets", "scan_results", "fuzz_results", "subdomains", "technologies"}
	for _, table := range tables {
		if err := d.ClearTable(table); err != nil {
			return err
		}
	}
	return nil
}

// SaveSubdomain stores a discovered subdomain
func (d *Database) SaveSubdomain(targetID uint, subdomain, ip, status string) error {
	sub := &Subdomain{
		TargetID:  targetID,
		Subdomain: subdomain,
		IP:        ip,
		Status:    status,
		CreatedAt: time.Now(),
	}

	return d.db.Create(sub).Error
}

// SaveTechnology stores detected technology
func (d *Database) SaveTechnology(targetID uint, name, version, category string) error {
	tech := &Technology{
		TargetID:  targetID,
		Name:      name,
		Version:   version,
		Category:  category,
		CreatedAt: time.Now(),
	}

	return d.db.Create(tech).Error
}

// SaveEmailProfile persists an EmailProfile and its associated BreachEntry records.
// targetID is optional (0 = standalone scan not linked to a domain target).
func (d *Database) SaveEmailProfile(targetID uint, email, deliverable string, score int, disposable bool, breachCount int, breaches []struct{ Name, Domain, BreachDate, DataClasses string; PwnCount int }) (*EmailProfile, error) {
	profile := &EmailProfile{
		TargetID:    targetID,
		Email:       email,
		Disposable:  disposable,
		Deliverable: deliverable,
		Score:       score,
		BreachCount: breachCount,
		CreatedAt:   time.Now(),
	}

	if err := d.db.Create(profile).Error; err != nil {
		return nil, err
	}

	for _, b := range breaches {
		entry := &BreachEntry{
			EmailProfileID: profile.ID,
			Name:           b.Name,
			Domain:         b.Domain,
			BreachDate:     b.BreachDate,
			DataClasses:    b.DataClasses,
			PwnCount:       b.PwnCount,
			CreatedAt:      time.Now(),
		}
		if err := d.db.Create(entry).Error; err != nil {
			return nil, fmt.Errorf("saving breach entry %q: %w", b.Name, err)
		}
	}

	return profile, nil
}

// SaveSocialProfiles bulk-saves a slice of social profiles for a target/username.
// targetID is optional (0 = standalone scan).
func (d *Database) SaveSocialProfiles(targetID uint, username string, profiles []struct{ Platform, URL string; Confirmed bool }) error {
	for _, p := range profiles {
		record := &SocialProfile{
			TargetID:  targetID,
			Username:  username,
			Platform:  p.Platform,
			URL:       p.URL,
			Confirmed: p.Confirmed,
			CreatedAt: time.Now(),
		}
		if err := d.db.Create(record).Error; err != nil {
			return fmt.Errorf("saving social profile %q/%q: %w", username, p.Platform, err)
		}
	}
	return nil
}

// GetEmailProfiles returns all EmailProfile records, optionally filtered by target.
func (d *Database) GetEmailProfiles(targetID uint) ([]EmailProfile, error) {
	var profiles []EmailProfile
	query := d.db.Preload("Breaches")
	if targetID != 0 {
		query = query.Where("target_id = ?", targetID)
	}
	return profiles, query.Find(&profiles).Error
}

// GetSocialProfiles returns all SocialProfile records for a given username.
func (d *Database) GetSocialProfiles(username string) ([]SocialProfile, error) {
	var profiles []SocialProfile
	return profiles, d.db.Where("username = ?", username).Find(&profiles).Error
}
