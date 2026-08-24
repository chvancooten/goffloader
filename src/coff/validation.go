package coff

import (
	"fmt"
	"math"
	"strings"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
)

const (
	coffPointerSize = 8
	coffAddressSize = 4
)

// parseCOFF parses the complete object before any native memory is allocated.
// pecoff returns errors for truncated tables and sections, but callers must
// check that error: a partially populated File is not safe to execute.
func parseCOFF(coffBytes []byte) (file *pecoff.File, err error) {
	if len(coffBytes) == 0 {
		return nil, fmt.Errorf("COFF object is empty")
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			file = nil
			err = fmt.Errorf("COFF parser panicked: %v", recovered)
		}
	}()

	file = pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	if err = file.ReadAll(); err != nil {
		return nil, fmt.Errorf("failed to parse COFF: %w", pecoff.ErrorFlatten(err))
	}
	file.Seal()
	return file, nil
}

// validateCOFF checks every index that the native loader later dereferences.
// This is intentionally independent of VirtualAlloc and Windows APIs so the
// malformed-object cases can be tested on the development host.
func validateCOFF(file *pecoff.File, entrypoint string) error {
	if file == nil || file.Sections == nil || file.Sections.Len() == 0 {
		return fmt.Errorf("COFF object has no sections")
	}
	if entrypoint == "" {
		return fmt.Errorf("COFF entrypoint is empty")
	}

	sections := file.Sections.Array()
	for symbolIndex, symbol := range file.Symbols {
		if symbol == nil {
			return fmt.Errorf("COFF symbol %d is nil", symbolIndex)
		}
		if symbol.SectionNumber == 0 {
			continue
		}
		if symbol.SectionNumber < 0 {
			// File/section/absolute symbols are legal COFF metadata.  They
			// are rejected below if a relocation tries to dereference them.
			continue
		}
		if int(symbol.SectionNumber) > len(sections) {
			return fmt.Errorf("COFF symbol %d references section %d", symbolIndex, symbol.SectionNumber)
		}
	}

	foundEntrypoint := false
	var gotSize uint64
	var bssSize uint64
	for _, symbol := range file.Symbols {
		if symbol.SectionNumber != 0 || symbol.StorageClass != windef.IMAGE_SYM_CLASS_EXTERNAL {
			continue
		}
		if strings.HasPrefix(symbol.NameString(), "__imp_") {
			gotSize += coffPointerSize
		} else {
			bssSize += uint64(symbol.Value) + coffPointerSize
		}
	}
	if gotSize > math.MaxUint32 || bssSize > math.MaxUint32 {
		return fmt.Errorf("COFF special-symbol storage is too large")
	}
	for sectionIndex, section := range sections {
		if section == nil {
			return fmt.Errorf("COFF section %d is nil", sectionIndex+1)
		}
		if uint64(len(section.RawData())) != uint64(section.SizeOfRawData) {
			return fmt.Errorf("COFF section %q has inconsistent raw data size", section.NameString())
		}

		for relocationIndex, relocation := range section.Relocations() {
			if uint64(relocation.SymbolTableIndex) >= uint64(len(file.Symbols)) {
				return fmt.Errorf(
					"COFF section %q relocation %d references symbol %d",
					section.NameString(),
					relocationIndex,
					relocation.SymbolTableIndex,
				)
			}

			symbol := file.Symbols[relocation.SymbolTableIndex]
			if symbol == nil {
				return fmt.Errorf("COFF relocation %d references a nil symbol", relocationIndex)
			}
			if symbol.SectionNumber < 0 ||
				(symbol.SectionNumber == 0 && symbol.StorageClass != windef.IMAGE_SYM_CLASS_EXTERNAL) ||
				symbol.SectionNumber > int16(len(sections)) {
				return fmt.Errorf("COFF relocation %d references invalid symbol section %d", relocationIndex, symbol.SectionNumber)
			}
			if symbol.SectionNumber > 0 {
				targetSection := sections[symbol.SectionNumber-1]
				if !strings.HasPrefix(targetSection.NameString(), ".bss") &&
					uint64(symbol.Value) >= uint64(targetSection.SizeOfRawData) {
					return fmt.Errorf("COFF relocation %d references a symbol outside its section", relocationIndex)
				}
			}

			width := relocationWidth(relocation.Type)
			if width > 0 && uint64(relocation.VirtualAddress)+width > uint64(section.SizeOfRawData) {
				return fmt.Errorf(
					"COFF section %q relocation %d writes past raw data",
					section.NameString(),
					relocationIndex,
				)
			}
		}

		for _, symbol := range file.Symbols {
			if symbol.NameString() != entrypoint || int(symbol.SectionNumber) != sectionIndex+1 {
				continue
			}
			if strings.HasPrefix(section.NameString(), ".bss") ||
				uint64(symbol.Value) < uint64(section.SizeOfRawData) {
				foundEntrypoint = true
			}
		}
	}

	if !foundEntrypoint {
		return fmt.Errorf("COFF entrypoint %q is missing or outside a section", entrypoint)
	}
	return nil
}

func relocationWidth(relocationType uint16) uint64 {
	switch relocationType {
	case windef.IMAGE_REL_AMD64_ADDR64:
		return coffPointerSize
	case windef.IMAGE_REL_AMD64_ADDR32,
		windef.IMAGE_REL_AMD64_ADDR32NB,
		windef.IMAGE_REL_AMD64_REL32,
		windef.IMAGE_REL_AMD64_REL32_1,
		windef.IMAGE_REL_AMD64_REL32_2,
		windef.IMAGE_REL_AMD64_REL32_3,
		windef.IMAGE_REL_AMD64_REL32_4,
		windef.IMAGE_REL_AMD64_REL32_5:
		return coffAddressSize
	default:
		// processRelocation reads a 32-bit addend before its type switch,
		// including for relocation types it does not otherwise support.
		return coffAddressSize
	}
}
