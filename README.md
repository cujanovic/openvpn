### Build OpenVPN with specific OpenSSL version
Tested on:
- Ubuntu 16.04("xenial"), Ubuntu 18.04("bionic"), Ubuntu 19.04("disco")
- Debian 8 ("jessie"), Debian 9 ("stretch"), Debian 10 ("buster")
- CentOS 7, CentOS 8
- Fedora 30, Fedora 31
- OpenVPN version 2.4.x for clients
- OpenSSL versions: 1.0.2x and 1.1.1x(preferred one) for clients

Example usage:

`./openvpn.sh OPENVPN-VERSION OPENSSL-VERSION`

`./openvpn.sh 2.4.8 1.1.1d`

OpenVPN server(UDP) example config file - `example-server.conf`

OpenVPN client(UDP) example config file - `example-client.conf`
