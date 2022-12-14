#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

RELEASE="9.0_2020Q4"

sudo -s
unset PROMPT_COMMAND
export PATH="/sbin:/usr/pkg/sbin:/usr/pkg/bin:$PATH"
export PKG_PATH="http://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/${RELEASE}/All/"
pkg_delete curl
pkg_add git python27 python38 py38-virtualenv py27-sqlite3 py38-sqlite3 py38-expat rust mozilla-rootcerts-openssl
git clone https://github.com/secdev/scapy
cd scapy
virtualenv-3.8 venv
. venv/bin/activate
pip install tox
chown -R vagrant:vagrant ../scapy/
