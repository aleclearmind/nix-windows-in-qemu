# Cook Windows images for QEMU

This nix flake cooks Windows images that can be run with QEMU.
It aims to produce images that are ready to use, without bloat, Windows Updates and Windows Defender.

Right now this flake builds Windows 11 23H2 (Enterprise Evaluation). The goal is to support many versions of Windows, including historical ones.

Being the build deterministic, whatever is produced here, will be reproducible until the end of time (or until Microsoft stops distributing the ISOs).

## Things you need to know

To build the image:

```
$ nix build .
$ mkdir test-vm
$ cd test-vm
$ ../result/bin/prepare-windows-vm
$ ls windows-vm
image.qcow2  start  stop  windows.conf
$ cd windows-vm
$ ./start
```

Other facts:

* Username: `user`
* Password: `password`
* Image size: 6.8 GB (you'll need more to build the image though).
* Time to build the image: less than 30' on my machine.
* This not for production use. It's for when you need to try something quickly on Windows and you don't want any noise. Just a clean (not updated), Windows installation.

## Features

* Installation is performed in a nix derivation. No Internet, all the inputs are collected ahead of time. The output is reasonably deterministic.
* Installation has QEMU Guest Additions, [VirtIO drivers](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/?C=M;O=D) and the [SPICE](https://www.spice-space.org/) agent.
* Windows Update is disabled.
* Windows Defender is disabled.
* Search Indexer is disabled.
* Various debloating using [Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat).
* Some useful software is preinstalled: the [SysinternalsSuite](https://learn.microsoft.com/en-us/sysinternals/), Firefox, Google Chrome, [Notepad++](https://github.com/notepad-plus-plus/notepad-plus-plus), [Git for Windows](https://github.com/git-for-windows/git), [Chocolatey](https://github.com/chocolatey/choco), [Everything](https://www.voidtools.com/), [SystemInformer](https://systeminformer.sourceforge.io/) (was: Process Hacker), [Dependency Walker](https://www.dependencywalker.com), [Dependencies](https://github.com/lucasg/Dependencies).
* Free space is zeroed out to get a smaller final image.

## FAQ

* **Why not VirtualBox?**
  I love QEMU, once you invoke it with the right incantations, it's the best. Thanks to [`quickemu`](https://github.com/quickemu-project/quickemu), the incantations are not that hard nowadays. Also, apparently the VirtualBox kernel driver is (used to be?) [quite bad](https://lkml.org/lkml/2011/10/6/317).
* **Why not libvirt?**
  I love QEMU. Libvirt feels like extra layers of XML to get to the command line of QEMU I actually want to run.

## TODO

* [ ] Add support for more recent Windows 11 versions.
* [ ] Implement `./mount` using `qemu-nbd`.
* [ ] Get rid of packer, we probably can do without at this point.
* [ ] Disable more auto-updates, in particular Chrome and Edge.
* [ ] Get Microsoft to make versioned releases of `SysinternalsSuite.zip`.
* [ ] Figure out a way to test things.
* [ ] Add support for older Windows versions.

## Credits

The following projects have been useful:

* [`proactivelabs/packer-windows`](https://github.com/proactivelabs/packer-windows/)
* [`quickemu-project/quickemu`](https://github.com/quickemu-project/quickemu)
* [Christoph Schneegans's `autounattend.xml` generator](https://schneegans.de/windows/unattend-generator/)
