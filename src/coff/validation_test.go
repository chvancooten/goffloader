package coff

import (
	"os"
	"testing"
)

func exampleCOFF(t *testing.T) []byte {
	t.Helper()
	coffBytes, err := os.ReadFile("../../cmd/bof_example/whoami.x64.o")
	if err != nil {
		t.Fatalf("read example COFF: %v", err)
	}
	return coffBytes
}

func TestParseCOFFRejectsTruncatedObject(t *testing.T) {
	coffBytes := exampleCOFF(t)
	if _, err := parseCOFF(coffBytes[:len(coffBytes)-1]); err == nil {
		t.Fatal("truncated COFF object should be rejected before loading")
	}
}

func TestValidateCOFFAcceptsExampleEntrypoint(t *testing.T) {
	parsed, err := parseCOFF(exampleCOFF(t))
	if err != nil {
		t.Fatalf("parse example COFF: %v", err)
	}
	if err := validateCOFF(parsed, "go"); err != nil {
		t.Fatalf("valid COFF object should pass validation: %v", err)
	}
}

func TestValidateCOFFRejectsMissingEntrypoint(t *testing.T) {
	parsed, err := parseCOFF(exampleCOFF(t))
	if err != nil {
		t.Fatalf("parse example COFF: %v", err)
	}
	if err := validateCOFF(parsed, "missing"); err == nil {
		t.Fatal("missing COFF entrypoint should be rejected")
	}
}
