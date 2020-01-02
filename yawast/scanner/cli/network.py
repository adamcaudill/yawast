#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from typing import Optional

from yawast.external.spinner import Spinner
from yawast.reporting import reporter
from yawast.scanner.plugins.dns import basic
from yawast.scanner.plugins.network import port_scan
from yawast.scanner.session import Session
from yawast.shared import output


def scan(session: Session):
    if session.args.ports:
        _check_open_ports(session.domain, session.url)


def _check_open_ports(domain: str, url: str, file: Optional[str] = None):
    try:
        output.empty()
        output.norm("Open Ports:")

        ips = basic.get_ips(domain)

        for ip in ips:
            with Spinner():
                res = port_scan.check_open_ports(url, ip, file)

            if len(res) > 0:
                reporter.display_results(res, "\t")
    except Exception as error:
        output.error(f"Error checking for open ports: {str(error)}")
