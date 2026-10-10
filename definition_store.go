package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	errDefinitionNameTaken = errors.New("a definition with this name already exists")
	errDefinitionNotFound  = errors.New("definition not found")
)

// CertDefinition says how device certificates look. A push (next phase) uses it
// with a device to build the signing request.
type CertDefinition struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CAID         string    `json:"ca_id"`
	Profile      string    `json:"profile"` // certificate template name
	Country      string    `json:"country"`
	State        string    `json:"state"`
	Organization string    `json:"organization"`
	City         string    `json:"city,omitempty"`
	OU           string    `json:"ou,omitempty"`
	ValidDays    int       `json:"valid_days"`
	CertID       string    `json:"cert_id"`
	ExtraSANs    []string  `json:"extra_sans,omitempty"` // fixed DNS or IP SANs added to every push
	Created      time.Time `json:"created"`
	Updated      time.Time `json:"updated"`
}

func (s *Store) definitionsPath() string { return filepath.Join(s.dir, "definitions.json") }

func (s *Store) loadDefinitions() ([]CertDefinition, error) {
	b, err := os.ReadFile(s.definitionsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var defs []CertDefinition
	err = json.Unmarshal(b, &defs)
	return defs, err
}

func (s *Store) saveDefinitions(defs []CertDefinition) error {
	b, err := json.MarshalIndent(defs, "", "  ")
	if err != nil {
		return err
	}
	return durableWrite(s.definitionsPath(), b)
}

// ListDefinitions returns all definitions sorted by name.
func (s *Store) ListDefinitions() ([]CertDefinition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defs, err := s.loadDefinitions()
	sort.Slice(defs, func(i, j int) bool { return strings.ToLower(defs[i].Name) < strings.ToLower(defs[j].Name) })
	return defs, err
}

// GetDefinition returns the definition with the given id.
func (s *Store) GetDefinition(id string) (CertDefinition, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defs, err := s.loadDefinitions()
	if err != nil {
		return CertDefinition{}, false, err
	}
	for _, d := range defs {
		if d.ID == id {
			return d, true, nil
		}
	}
	return CertDefinition{}, false, nil
}

// SaveDefinition creates the definition when d.ID is empty, otherwise replaces
// the one with that id. Names must stay unique.
func (s *Store) SaveDefinition(d *CertDefinition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defs, err := s.loadDefinitions()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	d.Updated = now
	for _, o := range defs {
		if strings.EqualFold(o.Name, d.Name) && o.ID != d.ID {
			return errDefinitionNameTaken
		}
	}
	if d.ID == "" {
		id, err := newDeviceID()
		if err != nil {
			return err
		}
		d.ID, d.Created = id, now
		defs = append(defs, *d)
	} else {
		i := -1
		for j := range defs {
			if defs[j].ID == d.ID {
				i = j
			}
		}
		if i < 0 {
			return errDefinitionNotFound
		}
		d.Created = defs[i].Created
		defs[i] = *d
	}
	return s.saveDefinitions(defs)
}

// DeleteDefinition removes the definition. Devices and certificates pushed with
// it are not touched.
func (s *Store) DeleteDefinition(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defs, err := s.loadDefinitions()
	if err != nil {
		return err
	}
	out := defs[:0]
	found := false
	for _, d := range defs {
		if d.ID == id {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return errDefinitionNotFound
	}
	return s.saveDefinitions(out)
}
