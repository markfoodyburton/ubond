=========================
Building ubond on OpenBSD
=========================

Install since OpenBSD 5.9
=========================

ubond is part of OpenBSD port system since OpenBSD 5.9. You can install
it as a package:

.. code-block:: sh

    pkg_add ubond


Installing requirements
=======================

.. code-block:: sh

    pkg_add git autoconf automake libev libsodium

Building ubond
==============

.. code-block:: sh

    export AUTOCONF_VERSION=2.69
    export AUTOMAKE_VERSION=1.14
    export CPPFLAGS="-I/usr/local/include $CPPFLAGS"
    export LDFLAGS="-L/usr/local/lib $LDFLAGS"
    git clone https://github.com/zehome/UBOND ubond
    cd ubond
    ./autogen.sh
    ./configure
    make

Configuration
=============
Example configuration files for OpenBSD are located in **/usr/local/share/examples/ubond/**.
