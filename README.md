# vping

Virtual network interface kernel module that replies to ICMP echo requests on
an IPv4 address configured via procfs.

## Build

```sh
make
```

Produces `vping.ko` in the project directory.

## Load / unload

```sh
sudo insmod vping.ko
dmesg | tail
sudo rmmod vping
```

At this stage loading the module just prints `vping: loaded` to the kernel log.

## Clean

```sh
make clean
```
