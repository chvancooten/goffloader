package coff

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/RIscRIpt/pecoff/windef"
)

func exampleCOFF(t *testing.T) []byte {
	t.Helper()
	coffBytes, err := os.ReadFile("../../cmd/bof_example/whoami.x64.o")
	if err != nil {
		t.Fatalf("read example COFF: %v", err)
	}
	return coffBytes
}

// findSectionHeader returns the file offset of the header of the named
// section in the example object, or fails the test if the section is
// absent. The example object has no optional header, so section headers
// begin at coffFileHeaderSize.
func findSectionHeader(t *testing.T, coffBytes []byte, name string) int {
	t.Helper()
	numSections := int(binary.LittleEndian.Uint16(coffBytes[coffFileNumberOfSectionsOffset:]))
	optionalHeader := int(binary.LittleEndian.Uint16(coffBytes[coffFileSizeOfOptionalHeaderOffset:]))
	headersStart := coffFileHeaderSize + optionalHeader
	for i := 0; i < numSections; i++ {
		start := headersStart + i*coffSectionHeaderSize
		raw := coffBytes[start : start+8]
		end := 0
		for end < len(raw) && raw[end] != 0 {
			end++
		}
		if string(raw[:end]) == name {
			return start
		}
	}
	t.Fatalf("section %q not found in example COFF", name)
	return -1
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

// The example object has a .bss section with SizeOfRawData=0. Rewrite its
// header so it matches the mingw-w64 uninitialized-data layout: a positive
// SizeOfRawData with PointerToRawData=0 and the uninitialized-data
// characteristic bit set. parseCOFF and validateCOFF must accept it.
func TestParseCOFFAcceptsUninitializedDataSection(t *testing.T) {
	coffBytes := exampleCOFF(t)
	patched := append([]byte(nil), coffBytes...)
	headerStart := findSectionHeader(t, patched, ".bss")
	binary.LittleEndian.PutUint32(patched[headerStart+coffSectionSizeOfRawDataOffset:], 8192)
	binary.LittleEndian.PutUint32(patched[headerStart+coffSectionPointerToRawDataOffset:], 0)
	characteristics := binary.LittleEndian.Uint32(patched[headerStart+coffSectionCharacteristicsOffset:])
	characteristics |= windef.IMAGE_SCN_CNT_UNINITIALIZED_DATA
	binary.LittleEndian.PutUint32(patched[headerStart+coffSectionCharacteristicsOffset:], characteristics)

	parsed, err := parseCOFF(patched)
	if err != nil {
		t.Fatalf("uninitialized-data section should parse: %v", err)
	}
	if err := validateCOFF(parsed, "go"); err != nil {
		t.Fatalf("uninitialized-data section should validate: %v", err)
	}
}

// A section that has SizeOfRawData beyond the file size and NO uninitialized
// characteristic must still be rejected. This confirms the fix does not
// suppress the earlier validation for real truncation.
func TestParseCOFFRejectsInitializedSectionBeyondFile(t *testing.T) {
	coffBytes := exampleCOFF(t)
	patched := append([]byte(nil), coffBytes...)
	headerStart := findSectionHeader(t, patched, ".text")
	characteristics := binary.LittleEndian.Uint32(patched[headerStart+coffSectionCharacteristicsOffset:])
	characteristics &^= windef.IMAGE_SCN_CNT_UNINITIALIZED_DATA
	binary.LittleEndian.PutUint32(patched[headerStart+coffSectionCharacteristicsOffset:], characteristics)
	binary.LittleEndian.PutUint32(patched[headerStart+coffSectionSizeOfRawDataOffset:], uint32(len(patched))+1024)

	if _, err := parseCOFF(patched); err == nil {
		t.Fatal("initialized section with an out-of-range size must be rejected")
	}
}
