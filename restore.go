package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A prepared transaction always rolls back; a committed transaction always
// rolls forward. Each component's original presence is journaled before its
// first rename. Root /data itself is never renamed (it may be a mount point).
// Recovery is idempotent, including a crash during rollback or cleanup.
type restoreJournal struct {
	Version   int
	Committed bool
	Present   map[string]bool
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func durableRename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(to)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(from))
}

// rename is injectable per invocation for deterministic storage-failure tests.
func activateBackup(dir, stage string, rename func(string, string) error) error {
	tx := filepath.Join(dir, ".restore")
	if err := os.Mkdir(tx, 0700); err != nil {
		return err
	}
	prepared := false
	defer func() {
		if !prepared {
			os.RemoveAll(tx)
		}
	}()
	if err := os.Mkdir(filepath.Join(tx, "old"), 0700); err != nil {
		return err
	}
	if err := durableRename(stage, filepath.Join(tx, "new")); err != nil {
		return err
	}
	j := restoreJournal{Version: 1, Present: map[string]bool{}}
	for _, root := range backupRoots {
		present, err := exists(filepath.Join(dir, root))
		if err != nil {
			return err
		}
		j.Present[root] = present
	}
	b, _ := json.Marshal(j)
	if err := syncDir(tx); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	// durableWrite may return an error after renaming the journal. Recovery must
	// inspect it even then, and must not discard the rollback material.
	prepared = true
	if err := durableWrite(filepath.Join(tx, "journal.json"), b); err != nil {
		return err
	}
	fail := func(cause error) error {
		if err := recoverRestore(dir); err != nil {
			return fmt.Errorf("activation failed (%v); recovery requires restart: %w", cause, err)
		}
		return cause
	}
	for _, root := range backupRoots {
		if j.Present[root] {
			if err := rename(filepath.Join(dir, root), filepath.Join(tx, "old", root)); err != nil {
				return fail(err)
			}
		}
		present, err := exists(filepath.Join(tx, "new", root))
		if err != nil {
			return fail(err)
		}
		if present {
			if err := rename(filepath.Join(tx, "new", root), filepath.Join(dir, root)); err != nil {
				return fail(err)
			}
		}
	}
	j.Committed = true
	b, _ = json.Marshal(j)
	if err := durableWrite(filepath.Join(tx, "journal.json"), b); err != nil {
		// Commit durability is uncertain. Do not resume the process. Startup
		// resolves whichever durable journal is present.
		return fmt.Errorf("restore commit uncertain; restart required: %w", err)
	}
	// Cleanup failure does not undo a committed restore. Startup finishes it.
	_ = recoverRestore(dir)
	return nil
}

func recoverRestore(dir string) error {
	tx := filepath.Join(dir, ".restore")
	b, err := os.ReadFile(filepath.Join(tx, "journal.json"))
	if errors.Is(err, os.ErrNotExist) {
		// No journal means staging never reached activation (or cleanup finished).
		if err = os.RemoveAll(tx); err != nil {
			return err
		}
	} else {
		if err != nil {
			return err
		}
		var j restoreJournal
		if err = strictJSON(b, &j); err != nil {
			return err
		}
		if j.Version != 1 || len(j.Present) != len(backupRoots) {
			return errors.New("unsupported restore journal")
		}
		for _, root := range backupRoots {
			if _, ok := j.Present[root]; !ok {
				return errors.New("incomplete restore journal")
			}
		}
		if !j.Committed {
			for _, root := range backupRoots {
				old := filepath.Join(tx, "old", root)
				live := filepath.Join(dir, root)
				present, err := exists(old)
				if err != nil {
					return err
				}
				if present || !j.Present[root] {
					if err = os.RemoveAll(live); err != nil {
						return err
					}
					if err = syncDir(dir); err != nil {
						return err
					}
					if present {
						if err = durableRename(old, live); err != nil {
							return err
						}
					}
				}
			}
		}
		// Remove journal only after the decided state is durable. A missing
		// journal thereafter means merely abandoned temporary material.
		if err = syncDir(dir); err != nil {
			return err
		}
		if err = os.Remove(filepath.Join(tx, "journal.json")); err != nil {
			return err
		}
		if err = syncDir(tx); err != nil {
			return err
		}
		if err = os.RemoveAll(tx); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".backup-stage-") {
			if err = os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return syncDir(dir)
}
