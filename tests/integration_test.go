package tests

import (
	"os"
	"testing"

	"github.com/foxboron/goefi/tests/utils"
)

var vm *utils.TestVM

func TestRun(t *testing.T) {
	t.Run("Read EFIVars", func(t *testing.T) {
		t.Run("Read", vm.RunTest("./integrations/read_efivars"))
	})
}

func TestMain(m *testing.M) {
	vm = utils.StartVM()
	exitVal := m.Run()
	vm.Close()
	os.Exit(exitVal)
}
