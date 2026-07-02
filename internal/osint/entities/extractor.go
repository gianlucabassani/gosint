// Package entities ports browsint's OSINT entity-extraction pipeline onto
// gosint's storage layer: it turns raw per-source OSINT data into persisted
// entities, per-source profiles, and harvested contacts, and reassembles them
// into a full profile.
//
// Ported from browsint's OSINTExtractor (osint_extractor.py) — the persistence
// and extraction logic only; its ~450 lines of CLI `_display_*` presentation are
// intentionally dropped (gosint's internal/reports covers presentation).
package entities

import (
	"encoding/json"
	"fmt"

	"github.com/gianlucabassani/gosint/internal/storage"
)

// Extractor orchestrates entity persistence on top of a storage.Database.
type Extractor struct {
	db *storage.Database
}

// New returns an Extractor backed by the given database.
func New(db *storage.Database) *Extractor {
	return &Extractor{db: db}
}

// GetOrCreateEntity finds or creates the entity for an identifier. Go port of
// browsint's `_get_or_create_entity`. A "domain" entity stores its domain (unique);
// other types ("person", "company") store a NULL domain.
func (e *Extractor) GetOrCreateEntity(identifier, entityType string) (*storage.Entity, error) {
	domain := ""
	if entityType == "domain" {
		domain = identifier
	}
	return e.db.CreateOrUpdateEntity(identifier, entityType, domain)
}

// SaveProfile persists raw + structured per-source data for an entity. Go port of
// browsint's `_save_osint_profile` (standardize_for_json → json.Marshal;
// extract_structured_fields → ExtractStructuredFields). No-op on empty data.
func (e *Extractor) SaveProfile(entityID uint, source string, data map[string]any) error {
	if len(data) == 0 {
		return nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling raw data: %w", err)
	}
	structured, err := json.Marshal(ExtractStructuredFields(data, source))
	if err != nil {
		return fmt.Errorf("marshalling structured fields: %w", err)
	}
	_, err = e.db.SaveOSINTProfile(entityID, source, string(raw), string(structured))
	return err
}

// HarvestContacts extracts emails/phones from data and stores them (deduped) for
// the entity. Go port of browsint's `_extract_and_save_contacts`. Returns the
// number of contact rows saved (existing ones are skipped by the storage layer).
func (e *Extractor) HarvestContacts(entityID uint, data any, source string) (int, error) {
	emails, phones := HarvestFromData(data)
	saved := 0
	for _, email := range emails {
		c, err := e.db.SaveContact(entityID, email, "", source)
		if err != nil {
			return saved, fmt.Errorf("saving email contact %q: %w", email, err)
		}
		if c != nil {
			saved++
		}
	}
	for _, phone := range phones {
		c, err := e.db.SaveContact(entityID, "", phone, source)
		if err != nil {
			return saved, fmt.Errorf("saving phone contact %q: %w", phone, err)
		}
		if c != nil {
			saved++
		}
	}
	return saved, nil
}

// Ingest is the persistence core of browsint's `entity()` orchestrator: it
// ensures the entity exists, saves the source profile, and harvests contacts —
// all from data already fetched by the caller.
//
// Note: browsint's `entity()` also *fetched* the data (`_process_domain_data`,
// fetch_email_osint, fetch_social_osint). In gosint that fetching is reused from
// the existing scanner/osint packages; the CLI command (M3) fetches and hands the
// result here, so recon code is not duplicated.
func (e *Extractor) Ingest(identifier, entityType, source string, data map[string]any) (*Profile, error) {
	entity, err := e.GetOrCreateEntity(identifier, entityType)
	if err != nil {
		return nil, fmt.Errorf("get/create entity: %w", err)
	}
	if len(data) > 0 {
		if err := e.SaveProfile(entity.ID, source, data); err != nil {
			return nil, fmt.Errorf("saving profile: %w", err)
		}
		if _, err := e.HarvestContacts(entity.ID, data, source); err != nil {
			return nil, fmt.Errorf("harvesting contacts: %w", err)
		}
	}
	return e.BuildFullProfile(entity.ID)
}

// BuildFullProfile reassembles an entity's persisted data into a Profile.
// Go port of browsint's `_build_full_profile`.
func (e *Extractor) BuildFullProfile(entityID uint) (*Profile, error) {
	entity, err := e.db.GetEntityByID(entityID)
	if err != nil {
		return nil, fmt.Errorf("fetching entity %d: %w", entityID, err)
	}

	profile := &Profile{
		Entity: EntitySummary{
			ID:   entity.ID,
			Type: entity.Type,
			Name: entity.Name,
		},
		Sources:  make(map[string]SourceProfile),
		Contacts: []ContactSummary{},
	}
	if entity.Domain != nil {
		profile.Entity.Domain = *entity.Domain
	}

	if entity.DomainInfo != nil {
		var ns []string
		_ = json.Unmarshal([]byte(entity.DomainInfo.NameServers), &ns)
		profile.DomainInfo = &DomainInfoSummary{
			Registrar:        entity.DomainInfo.Registrar,
			RegistrationDate: entity.DomainInfo.RegistrationDate,
			ExpirationDate:   entity.DomainInfo.ExpirationDate,
			NameServers:      ns,
		}
	}

	for _, p := range entity.Profiles {
		sp := SourceProfile{
			Extracted: decodeJSONMap(p.ExtractedFields),
			Raw:       decodeJSONMap(p.RawData),
			UpdatedAt: p.UpdatedAt,
		}
		profile.Sources[p.Source] = sp
	}

	for _, c := range entity.Contacts {
		if c.Email != "" {
			profile.Contacts = append(profile.Contacts, ContactSummary{
				ContactType: "email", Value: c.Email, Source: c.Source, CreatedAt: c.CreatedAt,
			})
		}
		if c.Phone != "" {
			profile.Contacts = append(profile.Contacts, ContactSummary{
				ContactType: "phone", Value: c.Phone, Source: c.Source, CreatedAt: c.CreatedAt,
			})
		}
	}

	return profile, nil
}

// decodeJSONMap best-effort decodes a JSON object string into a map (nil on failure).
func decodeJSONMap(s string) map[string]any {
	if s == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}
