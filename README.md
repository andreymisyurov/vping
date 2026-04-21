# vping

`vping` is an out-of-tree Linux kernel module that creates a virtual network
interface (`vping0`) and replies to `ping` for an IPv4 address configured via
`/proc/vping`.

Current architecture:
- `lower_if` (module parameter) is required.
- ARP + ICMP echo are intercepted via `rx_handler` on that lower interface.
- Replies are transmitted via `vping0` and forwarded to `lower_if` from
  `ndo_start_xmit`.

## Build

```sh
make
```

This produces `vping.ko` in the project directory.

## Load

```sh
sudo insmod vping.ko lower_if=enp0s8 ip=192.168.56.201
dmesg | tail -n 20
```

Parameters:
- `lower_if` - required lower device name for RX interception.
- `ip` - optional initial IPv4 value.

## Runtime setup

```sh
sudo ip link set vping0 up
```

Set/change address at runtime:

```sh
echo -n 192.168.56.202 | sudo tee /proc/vping
cat /proc/vping
```

## Test

Ping from another machine in the same L2 segment/subnet as `lower_if`:

```sh
ping 192.168.56.202
```

## Unload

```sh
sudo rmmod vping
```

## Clean

```sh
make clean
```

## Notes

- Non-unicast IPv4 values are rejected by the `/proc/vping` write handler.
- `netdev_rx_handler_register()` can fail if `lower_if` already has an
  `rx_handler` (bridge/bond/macvlan setups).
- Self-ping from the same VM may fail in this version because handling is bound
  to RX path on `lower_if`; expected test path is from another host.
