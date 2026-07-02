package storage

import (
	"fmt"
	"os"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ImportStats summarizes what an import migrated.
type ImportStats struct {
	Entities    int
	DomainInfos int
	Profiles    int
	Contacts    int
	Skipped     int // source rows whose entity could not be mapped
}

// Legacy browsint row shapes (column names map via GORM snake_case).
type browsintEntity struct {
	ID     int
	Type   string
	Name   string
	Domain *string
}
type browsintDomainInfo struct {
	EntityID         int
	Registrar        *string
	RegistrationDate *string
	ExpirationDate   *string
}
type browsintProfile struct {
	EntityID        int
	Source          string
	RawData         *string
	ExtractedFields *string
}
type browsintContact struct {
	EntityID int
	Email    *string
	Phone    *string
	Source   string
}

// ImportBrowsint reads a legacy browsint SQLite database and imports its OSINT
// entity data (entities → domain_info → osint_profiles → contacts) into gosint,
// reusing the normal upsert paths so a re-run is idempotent. The source is opened
// read-only-ish (never written). Tables absent in the source are skipped.
func (d *Database) ImportBrowsint(srcPath string) (*ImportStats, error) {
	if srcPath == d.path {
		return nil, fmt.Errorf("refusing to import a database into itself: %s", srcPath)
	}
	if _, err := os.Stat(srcPath); err != nil {
		return nil, fmt.Errorf("source database not found: %w", err)
	}

	src, err := gorm.Open(sqlite.Open(srcPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("opening browsint db: %w", err)
	}
	defer func() {
		if sqlDB, err := src.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()

	if !src.Migrator().HasTable("entities") {
		return nil, fmt.Errorf("%s does not look like a browsint database (no 'entities' table)", srcPath)
	}

	stats := &ImportStats{}
	// Maps a browsint entity id → the gosint entity id it was imported as.
	idMap := make(map[int]uint)

	var entities []browsintEntity
	if err := src.Raw("SELECT id, type, name, domain FROM entities").Scan(&entities).Error; err != nil {
		return nil, fmt.Errorf("reading entities: %w", err)
	}
	for _, be := range entities {
		domain := ""
		if be.Domain != nil {
			domain = *be.Domain
		}
		ent, err := d.CreateOrUpdateEntity(be.Name, be.Type, domain)
		if err != nil {
			return stats, fmt.Errorf("importing entity %q: %w", be.Name, err)
		}
		idMap[be.ID] = ent.ID
		stats.Entities++
	}

	if src.Migrator().HasTable("domain_info") {
		var rows []browsintDomainInfo
		if err := src.Raw("SELECT entity_id, registrar, registration_date, expiration_date FROM domain_info").Scan(&rows).Error; err == nil {
			for _, r := range rows {
				gid, ok := idMap[r.EntityID]
				if !ok {
					stats.Skipped++
					continue
				}
				if _, err := d.UpsertDomainInfo(gid, deref(r.Registrar), deref(r.RegistrationDate), deref(r.ExpirationDate), nil); err != nil {
					return stats, fmt.Errorf("importing domain_info for entity %d: %w", r.EntityID, err)
				}
				stats.DomainInfos++
			}
		}
	}

	if src.Migrator().HasTable("osint_profiles") {
		var rows []browsintProfile
		if err := src.Raw("SELECT entity_id, source, raw_data, extracted_fields FROM osint_profiles").Scan(&rows).Error; err == nil {
			for _, r := range rows {
				gid, ok := idMap[r.EntityID]
				if !ok {
					stats.Skipped++
					continue
				}
				if _, err := d.SaveOSINTProfile(gid, r.Source, deref(r.RawData), deref(r.ExtractedFields)); err != nil {
					return stats, fmt.Errorf("importing profile (entity %d, source %s): %w", r.EntityID, r.Source, err)
				}
				stats.Profiles++
			}
		}
	}

	if src.Migrator().HasTable("contacts") {
		var rows []browsintContact
		if err := src.Raw("SELECT entity_id, email, phone, source FROM contacts").Scan(&rows).Error; err == nil {
			for _, r := range rows {
				gid, ok := idMap[r.EntityID]
				if !ok {
					stats.Skipped++
					continue
				}
				if _, err := d.SaveContact(gid, deref(r.Email), deref(r.Phone), r.Source); err != nil {
					return stats, fmt.Errorf("importing contact for entity %d: %w", r.EntityID, err)
				}
				stats.Contacts++
			}
		}
	}

	return stats, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
