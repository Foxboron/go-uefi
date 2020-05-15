#!/bin/bash

rm OVMF_VARS.fd || true
mkdir -p ./shared || true

cp /usr/share/edk2-ovmf/x64/OVMF_VARS.fd .

qemu-system-x86_64 -enable-kvm -boot order=c,menu=on -m 3G -cpu host \
	-machine type=q35,smm=on,accel=kvm \
	-global driver=cfi.pflash01,property=secure,value=on \
	-global ICH9-LPC.disable_s3=1 \
	-drive if=pflash,format=raw,unit=0,file=/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd,readonly \
	-drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
	-drive file="$HOME/Downloads/archlinux-2020.01.01-x86_64.iso",media=cdrom,readonly=on \
	-device virtio-net-pci,netdev=net0 \
	-netdev user,id=net0 \
	-fsdev local,id=test_dev,path=./shared,security_model=none \
	-device virtio-9p-pci,fsdev=test_dev,mount_tag=shared
