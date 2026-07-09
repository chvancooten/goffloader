package coff

import "fmt"

func virtualProtectError(ret uintptr, err error) error {
	if ret != 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Error calling VirtualProtect:\r\n%s", err.Error())
	}
	return fmt.Errorf("Error calling VirtualProtect")
}
