# socks-libevent
Socks server implementation based on libevent.

Socks server works without creating additional processes or threads. Based on events and non-blocking io.
## Compilation
```
make
```
## Usage
```
socks_server_libevent [-hps] [--bind-ip <ip>|-bind-ipv6 <ipv6>]
    -h, --help               display this help and exit
        --bind-ip <ip>       bind to IP address <ip> (default: 127.0.0.1)
        --bind-ipv6 <ipv6>   bind to IPv6 address <ipv6>
    -p, --port <port>        bind to <port> (default: 1080)
    -s, --size <size>        assing two transfer buffers of <size> bytes
                             for every client (default: 64K)
```
