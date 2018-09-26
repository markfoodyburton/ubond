=========================
Fequently Asked Questions
=========================

How much ubond costs
====================
Free. ubond is licenced under the open source BSD licence.

Troubleshooting
===============

ubond does not launch
---------------------
Launch ubond manually in debug mode:
.. code-block:: sh

    ubond --user _ubond -c /etc/ubond.conf --debug -Dprotocol -v

Check your permissions:
.. code-block:: sh

    chmod 0600 /etc/ubond/ubond.conf
    chmod 0700 /etc/ubond/ubond_updown.sh
    chown root /etc/ubond/ubond.conf /etc/ubond/ubond_updown.sh

ubond does not create the tunnel interface
------------------------------------------
Follow `ubond does not launch`_.

