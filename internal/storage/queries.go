package storage

import (
	"encoding/json"
	"fmt"
	"time"
	"gorm.io/gorm"
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