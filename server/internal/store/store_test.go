package store

import (
	"context"
	"os"
	"testing"
)

func TestMigrate(t *testing.T) {
	dsn := os.Getenv("SIEPMU_TEST_DSN")
	if dsn == "" {
		t.Skip("SIEPMU_TEST_DSN not set")
	}
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal("second migrate must be a no-op:", err)
	}
}
