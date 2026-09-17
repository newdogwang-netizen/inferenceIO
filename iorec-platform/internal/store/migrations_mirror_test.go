package store

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestExternalMigrationsExactlyMirrorEmbeddedMigrations(t *testing.T) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var embeddedNames []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			embeddedNames = append(embeddedNames, entry.Name())
		}
	}
	sort.Strings(embeddedNames)

	externalEntries, err := os.ReadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	var externalNames []string
	for _, entry := range externalEntries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			externalNames = append(externalNames, entry.Name())
		}
	}
	sort.Strings(externalNames)
	if strings.Join(embeddedNames, "\n") != strings.Join(externalNames, "\n") {
		t.Fatalf("migration file sets differ: embedded=%v external=%v", embeddedNames, externalNames)
	}

	for _, name := range embeddedNames {
		embedded, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		external, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded, external) {
			t.Errorf("migration %s differs between embedded and external copies", name)
		}
	}
}
