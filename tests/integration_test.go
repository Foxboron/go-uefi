package tests

import (
	"testing"

	"github.com/foxboron/go-uefi/tests/utils"
)

func TestRun(t *testing.T) {
	conf := utils.NewConfig()
	utils.WithVM(conf,
		func(vm *utils.TestVM) {
			t.Run("Read EFIVars", func(t *testing.T) {
				t.Run("Read", vm.RunTest("./integrations/read_test.go"))
			})
		})
}
