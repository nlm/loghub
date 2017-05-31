loghub
======

Syslog Forwarding Hub

Sources
-------

  - udp/ip
  - tcp/ip

Destinations
------------

  - udp/ip
  - tcp/ip
  - systemd-journald

Install
-------

This script only uses Python3 stdlib (except for systemd-related functions),
so it can be run as-is

If you need systemd-journal support:

    apt-get install libsystemd-dev
    pip install git+https://github.com/systemd/python-systemd
    pip install git+https://github.com/easypost/syslog-rfc5424-parser

PyInstaller Build
-----------------

If you want to build a standalone binary with with pyinstaller:

    pip install pyinstaller
    pyinstaller -F loghub.py

