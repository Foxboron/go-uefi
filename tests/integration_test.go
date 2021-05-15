package tests

import (
	"testing"

	"github.com/foxboron/go-uefi/tests/utils"
)

func TestKeyEnrollment(t *testing.T) {
	conf := utils.NewConfig()
	conf.AddFile("./ovmf/keys/db/db.key")
	conf.AddFile("./ovmf/keys/db/db.pem")
	conf.AddFile("./ovmf/keys/KEK/KEK.key")
	conf.AddFile("./ovmf/keys/KEK/KEK.pem")
	conf.AddFile("./ovmf/keys/PK/PK.key")
	conf.AddFile("./ovmf/keys/PK/PK.pem")
	utils.WithVM(conf,
		func(vm *utils.TestVM) {
			t.Run("Check SetupMode enabled", vm.RunTest("./integrations/secureboot_disabled_test.go"))
			t.Run("Enroll Keys", vm.RunTest("./integrations/enroll_keys_test.go"))
		})

	utils.WithVM(conf,
		func(vm *utils.TestVM) {
			t.Run("Check SecureBoot enabled", vm.RunTest("./integrations/secureboot_enabled_test.go"))
			t.Run("Check remove PK", vm.RunTest("./integrations/remove_pk_test.go"))
			t.Run("Check rewrite dbx", vm.RunTest("./integrations/modify_dbx_test.go"))
		})
}
