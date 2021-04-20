package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"golang.org/x/crypto/ssh"
)

type TestVM struct {
	qemu *vmtest.Qemu
	conn *ssh.Client
	sess *ssh.Session
}

type TestConfig struct {
	Shared string
	Ovmf   string
}

func StartOVMF(conf TestConfig) *vmtest.Qemu {
	params := []string{
		"-machine", "type=q35,smm=on,accel=kvm",
		"-boot", "order=c,menu=on,strict=on",
		"-net", "none",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-global", "ICH9-LPC.disable_s3=1",
		"-drive", "if=pflash,format=raw,unit=0,file=/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd,readonly",
		"-drive", "if=pflash,format=raw,unit=1,file=ovmf/OVMF_VARS.fd",
	}
	if conf.Shared != "" {
		params = append(params, "-drive", fmt.Sprintf("file=fat:rw:%s", conf.Shared))
	}
	opts := vmtest.QemuOptions{
		Params:  params,
		Verbose: false, //testing.Verbose(),
		Timeout: 50 * time.Second,
	}
	// Run QEMU instance
	ovmf, err := vmtest.NewQemu(&opts)
	if err != nil {
		panic(err)
	}
	ovmf.ConsoleExpect("Shell>")
	return ovmf
}

// TODO: Wire this up with 9p instead of ssh
func StartVM() *TestVM {
	if !CopyFile("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd", "OVMF_VARS.fd") {
		panic("Could not find OVMF_CODE.secboot.fd")
	}
	params := []string{
		"-machine", "type=q35,smm=on,accel=kvm",
		"-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
		"-device", "virtio-net-pci,netdev=net0",
		"-nic", "user,model=virtio-net-pci",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-global", "ICH9-LPC.disable_s3=1",
		"-drive", "if=pflash,format=raw,unit=0,file=/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd,readonly",
		"-drive", "if=pflash,format=raw,unit=1,file=OVMF_VARS.fd",
		"-m", "8G",
		"-smp", "2",
	}
	params = append(params, "-enable-kvm", "-cpu", "host")
	opts := vmtest.QemuOptions{
		OperatingSystem: vmtest.OS_LINUX,
		Kernel:          "bzImage",
		Params:          params,
		Disks:           []vmtest.QemuDisk{{"rootfs.cow", "qcow2"}},
		Append:          []string{"root=/dev/sda", "rw"},
		Verbose:         false, //testing.Verbose()
		Timeout:         50 * time.Second,
	}
	// Run QEMU instance
	qemu, err := vmtest.NewQemu(&opts)
	if err != nil {
		panic(err)
	}

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", "localhost:10022", config)
	if err != nil {
		panic(err)
	}

	sess, err := conn.NewSession()
	if err != nil {
		panic(err)
	}

	return &TestVM{qemu, conn, sess}
}

func (t *TestVM) Run(command string) (ret string, err error) {
	output, err := t.sess.CombinedOutput(command)
	return string(output), err
}

func (t *TestVM) Close() {
	t.sess.Close()
	t.conn.Close()
	t.qemu.Shutdown()
}

func (t *TestVM) CopyFile(path string) {
	cmd := exec.Command("scp", "-P10022", path, "root@localhost:/")
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func (tvm *TestVM) RunTest(path string) func(t *testing.T) {
	return func(t *testing.T) {
		if err := exec.Command("go", "test", "-c", path).Run(); err != nil {
			t.Fail()
		}
		testName := fmt.Sprintf("%s%s", filepath.Base(path), ".test")
		tvm.CopyFile(testName)
		ret, err := tvm.Run(fmt.Sprintf("/%s -test.v", testName))
		t.Logf("\n%s", ret)
		if err != nil {
			t.Fail()
		}
	}
}

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
	return true
}
