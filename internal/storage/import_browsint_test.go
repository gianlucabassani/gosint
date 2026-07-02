package storage

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// makeBrowsintDB creates a SQLite file with browsint's legacy schema + sample rows.
func makeBrowsintDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "browsint.db")
	src, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	stmts := []string{
		`CREATE TABLE entities (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, name TEXT, domain TEXT)`,
		`CREATE TABLE domain_info (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER, registrar TEXT, registration_date TEXT, expiration_date TEXT)`,
		`CREATE TABLE osint_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER, source TEXT, raw_data TEXT, extracted_fields TEXT)`,
		`CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER, email TEXT, phone TEXT, source TEXT)`,
		`INSERT INTO entities (id, type, name, domain) VALUES (1, 'company', 'acme.com', 'acme.com'), (2, 'person', 'Alice', NULL)`,
		`INSERT INTO domain_info (entity_id, registrar, registration_date, expiration_date) VALUES (1, 'RegX', '2010-01-01', '2030-01-01')`,
		`INSERT INTO osint_profiles (entity_id, source, raw_data, extracted_fields) VALUES (1, 'domain', '{"a":1}', '{"b":2}')`,
		`INSERT INTO contacts (entity_id, email, phone, source) VALUES (1, 'admin@acme.com', NULL, 'crawl'), (2, NULL, '+16502530000', 'social')`,
	}
	for _, s := range stmts {
		if err := src.Exec(s).Error; err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	if sqlDB, err := src.DB(); err == nil {
		_ = sqlDB.Close()
	}
	return path
}

func TestImportBrowsint(t *testing.T) {
	db := setupTestDB(t)
	srcPath := makeBrowsintDB(t)

	stats, err := db.ImportBrowsint(srcPath)
	if err != nil {
		t.Fatalf("ImportBrowsint: %v", err)
	}
	if stats.Entities != 2 || stats.DomainInfos != 1 || stats.Profiles != 1 || stats.Contacts != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// The domain entity came across with its DomainInfo, profile, and contact.
	ent, err := db.GetEntityByDomain("acme.com")
	if err != nil {
		t.Fatalf("GetEntityByDomain: %v", err)
	}
	if ent.DomainInfo == nil || ent.DomainInfo.Registrar != "RegX" {
		t.Fatalf("expected imported DomainInfo RegX, got %+v", ent.DomainInfo)
	}
	if len(ent.Profiles) != 1 || ent.Profiles[0].Source != "domain" {
		t.Fatalf("expected 1 imported profile, got %+v", ent.Profiles)
	}
	if len(ent.Contacts) != 1 || ent.Contacts[0].Email != "admin@acme.com" {
		t.Fatalf("expected imported email contact, got %+v", ent.Contacts)
	}

	// Idempotent: a second import must not duplicate.
	stats2, err := db.ImportBrowsint(srcPath)
	if err != nil {
		t.Fatalf("second ImportBrowsint: %v", err)
	}
	if stats2.Entities != 2 {
		t.Fatalf("re-import entity count changed: %+v", stats2)
	}
	again, _ := db.GetEntityByDomain("acme.com")
	if len(again.Contacts) != 1 {
		t.Fatalf("re-import duplicated contacts: %d", len(again.Contacts))
	}
}
