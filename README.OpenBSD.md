Building ubond on OpenBSD
=========================

Since OpenBSD 5.9
=================
In OpenBSD 5.9 and later, thanks yo Stuart Henderson @sthen,
you can install ubond like any other OpenBSD package:

```sh
pkg_add ubond
/etc/rc.d/ubond start
```

Install requirements
====================
```sh
pkg_add git autoconf automake libev libsodium
```
.. note: For OpenBSD 5.6 and older, you need to build libsodium
         from source, because the version provided is too old.

Manual build
============

```sh
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.15
export CPPFLAGS="-I/usr/local/include $CPPFLAGS"
export LDFLAGS="-L/usr/local/lib $LDFLAGS"
git clone https://github.com/zehome/UBOND ubond
cd ubond
./autogen.sh
./configure
make
doas make install
```

Manual installation
===================
```sh
doas make install
doas mkdir /etc/ubond
doas cp /usr/local/share/doc/ubond/ubond.rc /etc/rc.d/ubond
doas cp /usr/local/share/doc/ubond/ubond.conf /etc/ubond/
doas cp /usr/local/share/doc/ubond/ubond_updown.sh /etc/ubond/
doas chown -R root:wheel /etc/ubond
doas chmod 660 /etc/ubond/ubond.conf
doas chmod 700 /etc/ubond/ubond_updown.sh /etc/rc.d/ubond

# Create a system user for ubond
doas groupadd _ubond
doas useradd -c "ubond Daemon" -d /var/empty -s /sbin/nologin -L daemon -g _ubond _ubond
```

Edit **/etc/ubond/ubond.conf** for your needs.

Run
===

```sh
doas ubond -c /etc/ubond/ubond.conf --user _ubond
# or using rc.d:
doas /etc/rc.d/ubond start
```

Don't forget you get the super easy way to configure source-routing
with ubond on OpenBSD. Just create your routing tables with route(8) -T
then use **bindfib** in ubond.conf.
