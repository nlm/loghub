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

Build
-----

If you need systemd-journal support:

    apt-get install libsystemd-dev
    pip install git+https://github.com/systemd/python-systemd
    pip install git+https://github.com/easypost/syslog-rfc5424-parser

If you want a standalone binary with with pyinstaller:

    pip install pyinstaller
    pyinstaller -F loghub.py

