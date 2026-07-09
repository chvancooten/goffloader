package coff

import (
	"errors"
	"strings"
	"testing"
)

func TestVirtualProtectErrorIgnoresLocalizedSuccessMessage(t *testing.T) {
	t.Parallel()

	err := virtualProtectError(1, errors.New("De bewerking is voltooid."))
	if err != nil {
		t.Fatalf("VirtualProtect success return should ignore localized success message, got %v", err)
	}
}

func TestVirtualProtectErrorReportsFailedCall(t *testing.T) {
	t.Parallel()

	err := virtualProtectError(0, errors.New("Access is denied."))
	if err == nil {
		t.Fatal("VirtualProtect failure return should report an error")
	}
	if !strings.Contains(err.Error(), "Access is denied.") {
		t.Fatalf("VirtualProtect failure should include Windows error, got %v", err)
	}
}
