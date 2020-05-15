Integration tests
=================

This directory contains some sources for tests, along with a qemu setup intended
for future integration tests. It starts a qemu VM with the appropriate OVMF
microcode. Currently assumes you have archiso downloaded.

## Star the VM

```
$ bash ./start-qemu.sh
```


## Mount shared into VM

```
$ mount -t 9p -o trans=virtio shared /mnt
```


Compile binaries and/or test binaries and run on the VM.
