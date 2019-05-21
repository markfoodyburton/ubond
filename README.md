=========================================
UBOND - Usermode Bonding
=========================================
[![Build Status](https://travis-ci.org/zehome/UBOND.svg?branch=master)](https://travis-ci.org/zehome/UBOND)
[![Coverity Status](https://scan.coverity.com/projects/4405/badge.svg)](https://scan.coverity.com/projects/4405)

author: Mark Burton (from original code by Laurent Coustet <ed arobase zehome.com>)

Take a look at the official documentation on [Read The Docs](http://ubond.readthedocs.org/en/latest/)

Introduction
============
UBOND will do its best to achieve the following tasks:

  * Bond your internet links to increase bandwidth (unlimited)
  * Secure your internet connection by actively monitoring
    your links and removing the faulty ones, without loosing
    your TCP connections.
  * Secure your internet connection to the aggregation server using
    strong cryptography.
  * Scriptable automation and monitoring.

Quick install
=============

Install debian package
----------------------
```sh
sudo apt-key adv --keyserver pgp.mit.edu --recv 3324C952
echo "deb http://debian.ubond.fr unstable/" >/etc/apt/sources.list.d/ubond.list
sudo apt-get update
sudo apt-get install ubond
```

Install FreeBSD port
--------------------
```sh
pkg install git libev libsodium
git clone --branch freebsd https://github.com/zehome/UBOND ubond
cd ubond
make
```

Install "static" package
------------------------
This is usefull on old systems. For example, for debian
```
wget https://github.com/zehome/UBOND/releases/download/2.3.1/ubond_static_ev_4.22_libsodium_1.0.10.tar.gz
tar -C / -xpzf ubond_static_ev_4.22_libsodium_1.0.10.tar.gz
adduser --quiet --system --no-create-home --home /var/run/ubond --shell /usr/sbin/nologin ubond
chmod +x /etc/init.d/ubond
insserv ubond
```

Build from source
-----------------
```sh
# Debian
$ sudo apt-get install build-essential make autoconf libev-dev libsodium-dev libpcap-dev
# OR ArchLinux
$ sudo pacman -S base-devel git libev libsodium
$ ./autogen.sh
$ ./configure
$ make
$ make install
```

Build debian package
--------------------
```sh
$ sudo apt-get install build-essential make autoconf
$ dpkg-buildpackage -us -uc -rfakeroot
```

Generating a static binary
--------------------------
```sh
apt-get install flex bison build-essential
UBOND_VERSION=2.3.0
EV_VERSION=4.22
LIBSODIUM_VERSION=1.0.8
PCAP_VERSION=1.7.4
wget http://dist.schmorp.de/libev/libev-${EV_VERSION}.tar.gz
wget https://github.com/jedisct1/libsodium/releases/download/1.0.8/libsodium-${LIBSODIUM_VERSION}.tar.gz
wget http://www.tcpdump.org/release/libpcap-${PCAP_VERSION}.tar.gz
tar xzf libev-${EV_VERSION}.tar.gz
tar xzf libsodium-${LIBSODIUM_VERSION}.tar.gz
tar xzf libpcap-${PCAP_VERSION}.tar.gz

echo libev
(cd libev-${EV_VERSION}
./configure --enable-static --disable-shared --prefix $HOME/libev/
make -j4 install)

echo libsodium
(cd libsodium-${LIBSODIUM_VERSION}
./configure --enable-static --disable-shared --prefix=$HOME/libsodium/
make -j4 install)

echo libpcap
(cd libpcap-${LIBPCAP_VERSION}
./configure --disable-shared --prefix $HOME/libpcap/
make -j4 install)

wget https://github.com/zehome/UBOND/releases/download/${UBOND_VERSION}/ubond-${UBOND_VERSION}.tar.gz
tar xzf ubond-${UBOND_VERSION}.tar.gz
cd ubond-${UBOND_VERSION}
libpcap_LIBS="-L${HOME}/libpcap/lib -lpcap" libpcap_CFLAGS="-I${HOME}/libpcap/include" libsodium_LIBS="-L${HOME}/libsodium/lib -lsodium" libsodium_CFLAGS=-I${HOME}/libsodium/include libev_LIBS="-L${HOME}/libev/lib -lev" libev_CFLAGS=-I${HOME}/libev/include ./configure --enable-filters LDFLAGS="-Wl,-Bdynamic" --prefix=${HOME}/ubond/
make install
```

Dependencies
============
  - libev
  - libsodium
  - libpcap (optional)

Security
========

Privilege separation
--------------------
UBOND uses privilege separation to keep high privileges operations
away from the core routing stuff.

Code running as root is very minimalist and highly readable to
avoid risks as much as possible.

Read more about [privilege separation](http://en.wikipedia.org/wiki/Privilege_separation)

Cryptography
------------
  * Encryption: Salsa20 stream cipher
  * Authentication: Poly1305 MAC

Read more on [salsa20](http://cr.yp.to/salsa20.html) and [libsodium](http://doc.libsodium.org/).


Principle of operations
=======================
**TODO**

Compatibility
=============
Linux, OpenBSD, FreeBSD, OSX

Windows is *NOT* supported, but UBOND runs on routers, so you can
benefit from UBOND on *ANY* operating system of course.

Contributors
============
  * Laurent Coustet, author and maintainer
  * Philippe Pepiot, contributor (privilege separation, bugfix)
  * Ghislain Lévèque, contributor (weight round robin)
  * Fabien Dupont, contributor (bugfix)
  * Thomas Soëte, contributor (bugfix)
  * Frank Denis, contributor (documentation)
  * Nicolas Braud-Santoni, contributor (documentation)
  * Stuart Henderson, contributor (OpenBSD port/package)
  * Olivier Cochard-Labbé, contributor (FreeBSD/OpenBSD fib routing)
  * Michael Stapelberg, contributor (documentation)
  * Mark Burton, contributor (Reorder buffer re-write)

LICENSE
=======
See LICENSE file.

Documentation
=============
Documentation is available on [Read The Docs](http://ubond.readthedocs.org/en/latest/).  
The manpage is also authored in Markdown, and converted using [ronn](http://rtomayko.github.com/ronn/).
