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
	d.db.Model(&Entity{}).Count(&count)
	stats["entities"] = count
	d.db.Model(&DomainInfo{}).Count(&count)
	stats["domain_info"] = count
	d.db.Model(&OSINTProfile{}).Count(&count)
	stats["osint_profiles"] = count
	d.db.Model(&Contact{}).Count(&count)
	stats["contacts"] = count

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
	case "email_profiles":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&EmailProfile{}).Error
	case "breach_entries":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&BreachEntry{}).Error
	case "social_profiles":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&SocialProfile{}).Error
	case "entities":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Entity{}).Error
	case "domain_info":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&DomainInfo{}).Error
	case "osint_profiles":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&OSINTProfile{}).Error
	case "contacts":
		return d.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Contact{}).Error
	default:
		return fmt.Errorf("unknown table: %s", tableName)
	}
}

// ClearAllTables empties all tables
func (d *Database) ClearAllTables() error {
	tables := []string{"targets", "scan_results", "fuzz_results", "subdomains", "technologies", "email_profiles", "breach_entries", "social_profiles", "entities", "domain_info", "osint_profiles", "contacts"}
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
func (d *Database) SaveEmailProfile(targetID uint, email, deliverable string, score int, disposable bool, breachCount int, breaches []struct {
	Name, Domain, BreachDate, DataClasses string
	PwnCount                              int
}) (*EmailProfile, error) {
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
func (d *Database) SaveSocialProfiles(targetID uint, username string, profiles []struct {
	Platform, URL string
	Confirmed     bool
}) error {
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

// --- Entity / OSINT hub (browsint consolidation — see CONSOLIDATION.md) ---

// CreateOrUpdateEntity finds or creates an Entity (the OSINT hub). Mirrors
// browsint's `_get_or_create_entity`. A non-empty domain is matched first (it is
// unique); otherwise the (name, type) pair is used. domain "" is stored as NULL.
func (d *Database) CreateOrUpdateEntity(name, entityType, domain string) (*Entity, error) {
	var entity Entity
	var domainPtr *string
	if domain != "" {
		domainPtr = &domain
	}

	var result *gorm.DB
	if domainPtr != nil {
		result = d.db.Where("domain = ?", domain).First(&entity)
	} else {
		result = d.db.Where("name = ? AND type = ?", name, entityType).First(&entity)
	}

	if result.Error == gorm.ErrRecordNotFound {
		entity = Entity{
			Type:      entityType,
			Name:      name,
			Domain:    domainPtr,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := d.db.Create(&entity).Error; err != nil {
			return nil, err
		}
	} else if result.Error != nil {
		return nil, result.Error
	} else {
		entity.UpdatedAt = time.Now()
		if name != "" {
			entity.Name = name
		}
		d.db.Save(&entity)
	}

	return &entity, nil
}

// UpsertDomainInfo stores (or replaces) the one DomainInfo row for an entity.
func (d *Database) UpsertDomainInfo(entityID uint, registrar, regDate, expDate string, nameServers []string) (*DomainInfo, error) {
	nsJSON, _ := json.Marshal(nameServers)

	var info DomainInfo
	result := d.db.Where("entity_id = ?", entityID).First(&info)
	if result.Error == gorm.ErrRecordNotFound {
		info = DomainInfo{
			EntityID:         entityID,
			Registrar:        registrar,
			RegistrationDate: regDate,
			ExpirationDate:   expDate,
			NameServers:      string(nsJSON),
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}
		return &info, d.db.Create(&info).Error
	} else if result.Error != nil {
		return nil, result.Error
	}

	info.Registrar = registrar
	info.RegistrationDate = regDate
	info.ExpirationDate = expDate
	info.NameServers = string(nsJSON)
	info.UpdatedAt = time.Now()
	return &info, d.db.Save(&info).Error
}

// SaveDomainInfoForDomain ensures a domain-type Entity exists for the domain and
// upserts its DomainInfo in one call, returning the entity so callers can link it
// to a Target (see LinkTargetToEntity).
func (d *Database) SaveDomainInfoForDomain(domain, registrar, regDate, expDate string, nameServers []string) (*Entity, error) {
	entity, err := d.CreateOrUpdateEntity(domain, "domain", domain)
	if err != nil {
		return nil, err
	}
	if _, err := d.UpsertDomainInfo(entity.ID, registrar, regDate, expDate, nameServers); err != nil {
		return nil, err
	}
	return entity, nil
}

// LinkTargetToEntity sets a target's EntityID, wiring the recon hub (Target) to
// the OSINT hub (Entity). Idempotent.
func (d *Database) LinkTargetToEntity(targetID, entityID uint) error {
	return d.db.Model(&Target{}).Where("id = ?", targetID).Update("entity_id", entityID).Error
}

// SaveOSINTProfile upserts a per-source profile for an entity (UNIQUE(entity, source)).
func (d *Database) SaveOSINTProfile(entityID uint, source, rawData, extractedFields string) (*OSINTProfile, error) {
	var profile OSINTProfile
	result := d.db.Where("entity_id = ? AND source = ?", entityID, source).First(&profile)
	if result.Error == gorm.ErrRecordNotFound {
		profile = OSINTProfile{
			EntityID:        entityID,
			Source:          source,
			RawData:         rawData,
			ExtractedFields: extractedFields,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		return &profile, d.db.Create(&profile).Error
	} else if result.Error != nil {
		return nil, result.Error
	}

	profile.RawData = rawData
	profile.ExtractedFields = extractedFields
	profile.UpdatedAt = time.Now()
	return &profile, d.db.Save(&profile).Error
}

// SaveContact stores a harvested email/phone for an entity, deduped on
// (entity, email, phone). Returns the existing row if it already exists.
func (d *Database) SaveContact(entityID uint, email, phone, source string) (*Contact, error) {
	var contact Contact
	result := d.db.Where("entity_id = ? AND email = ? AND phone = ?", entityID, email, phone).First(&contact)
	if result.Error == nil {
		return &contact, nil // already present
	}
	if result.Error != gorm.ErrRecordNotFound {
		return nil, result.Error
	}

	contact = Contact{
		EntityID:  entityID,
		Email:     email,
		Phone:     phone,
		Source:    source,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return &contact, d.db.Create(&contact).Error
}

// GetEntityByDomain returns an entity (with DomainInfo, Profiles, Contacts) by domain.
func (d *Database) GetEntityByDomain(domain string) (*Entity, error) {
	var entity Entity
	result := d.db.
		Preload("DomainInfo").
		Preload("Profiles").
		Preload("Contacts").
		Where("domain = ?", domain).
		First(&entity)
	if result.Error != nil {
		return nil, result.Error
	}
	return &entity, nil
}

// GetEntityByID returns an entity (with DomainInfo, Profiles, Contacts) by ID.
func (d *Database) GetEntityByID(id uint) (*Entity, error) {
	var entity Entity
	result := d.db.
		Preload("DomainInfo").
		Preload("Profiles").
		Preload("Contacts").
		First(&entity, id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &entity, nil
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
