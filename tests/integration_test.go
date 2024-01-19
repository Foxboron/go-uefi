package itest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/hugelgupf/vmtest"
	"github.com/hugelgupf/vmtest/qemu"
)

func CopyFile(src, dst string) bool {
	source, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()

	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	io.Copy(f, source)
	si, err := os.Stat(src)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		log.Fatal(err)
	}
	return true
}

type VMTest struct {
	ovmf    string
	secboot string
}

func (vm *VMTest) RunTests(packages ...string) func(t *testing.T) {
	return func(t *testing.T) {
		vmtest.RunGoTestsInVM(t, packages,
			vmtest.WithVMOpt(
				vmtest.WithSharedDir("ovmf/keys"),
				vmtest.WithQEMUFn(
					qemu.WithVMTimeout(time.Minute),
					qemu.WithQEMUCommand("qemu-system-x86_64 -enable-kvm"),
					qemu.WithKernel("bzImage"),
					qemu.ArbitraryArgs(
						"-m", "1G", "-machine", "type=q35,smm=on",
						"-drive", fmt.Sprintf("if=pflash,format=raw,unit=0,file=%s,readonly=on", vm.secboot),
						"-drive", fmt.Sprintf("if=pflash,format=raw,unit=1,file=%s", vm.ovmf),
					),
				)),
		)
	}
}

var (
	errOK      = errors.New("OK")
	errFAIL    = errors.New("FAIL")
	startupnsh = `
@echo -off
echo Starting UEFI application...
fs0:
HelloWorld.efi.signed
`
)

// Signs HelloWorld.efi and attempts to run it within tianocore
func (v *VMTest) RunKernelTests(packages ...string) func(t *testing.T) {
	return func(t *testing.T) {
		dir := t.TempDir()

		// Get some signing keys
		dbPem, _ := os.ReadFile("ovmf/keys/db/db.pem")
		dbKey, _ := os.ReadFile("ovmf/keys/db/db.key")
		key, _ := util.ReadKey(dbKey)
		cert, _ := util.ReadCert(dbPem)

		// Sign HelloWorld.efi binary
		peFile, _ := os.Open("binaries/HelloWorld.efi")
		file, err := authenticode.Parse(peFile)
		if err != nil {
			t.Fatalf("failed authenticode.Parse: %v", err)
		}
		_, err = file.Sign(key, cert)
		if err != nil {
			t.Fatalf("failed PECOFFBinary.Sign: %v", err)
		}

		os.WriteFile(filepath.Join(dir, "HelloWorld.efi.signed"), file.Bytes(), 0o755)
		os.WriteFile(filepath.Join(dir, "startup.nsh"), []byte(startupnsh), 0o755)

		vm := vmtest.StartVM(t,
			vmtest.WithArch(qemu.ArchAMD64),
			vmtest.WithQEMUFn(
				qemu.WithQEMUCommand("qemu-system-x86_64"),
				qemu.WithVMTimeout(time.Minute),
				qemu.WithKernel(""),
				qemu.ReadOnlyDirectory(dir),
				qemu.ArbitraryArgs(
					// Disabled iPXE boot
					"-net", "none",
					"-machine", "type=q35,smm=on",
					"-drive", fmt.Sprintf("if=pflash,format=raw,unit=0,file=%s,readonly", v.secboot),
					"-drive", fmt.Sprintf("if=pflash,format=raw,unit=1,file=%s", v.ovmf)),
				func() qemu.Fn {
					return func(alloc *qemu.IDAllocator, opts *qemu.Options) error {
						opts.KernelArgs = ""
						return nil
					}
				}(),
			),
		)

		go vm.Wait()

		_, err = vm.Console.Expect(
			expect.String("Access Denied").Then(func(buf *bytes.Buffer) error {
				return errFAIL
			}),
			expect.String("HelloWorld").Then(func(buf *bytes.Buffer) error {
				return errOK
			}),
		)

		if errors.Is(err, errFAIL) {
			t.Fatalf("failed signature validation")
		}
	}
}

// Sets up the test by making a copy of the OVMF files from the system
func WithVM(t *testing.T, fn func(*VMTest)) {
	t.Helper()
	dir := t.TempDir()
	vm := VMTest{
		ovmf:    path.Join(dir, "OVMF_VARS.fd"),
		secboot: path.Join(dir, "OVMF_CODE.secboot.fd"),
	}
	CopyFile("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd", vm.ovmf)
	CopyFile("/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd", vm.secboot)
	fn(&vm)
}

func TestSecureBoot(t *testing.T) {
	os.Setenv("VMTEST_QEMU", "qemu-system-x86_64")

	WithVM(t, func(vm *VMTest) {
		t.Run("Enroll keys", vm.RunTests("github.com/foxboron/go-uefi/tests/tests/enroll_keys"))
		t.Run("Secure Boot Enabled", vm.RunTests("github.com/foxboron/go-uefi/tests/tests/secure_boot_enabled"))
		t.Run("Boot signed kernel", vm.RunKernelTests())
	})
}
