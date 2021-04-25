package tests

import (
	"testing"

	"github.com/foxboron/go-uefi/tests/utils"
)

func TestKeyEnrollment(t *testing.T) {
	conf := utils.NewConfig()
	utils.WithVM(conf,
		func(vm *utils.TestVM) {
			t.Run("Check SetupMode enabled", vm.RunTest("./integrations/secureboot_disabled_test.go"))
			t.Run("Enroll Keys", vm.RunTest("./integrations/enroll_keys_test.go"))
		})

	utils.WithVM(conf,
		func(vm *utils.TestVM) {
			t.Run("Check SecureBoot enabled", vm.RunTest("./integrations/secureboot_enabled_test.go"))
		})
}
