#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import json
import os
import socket
from multiprocessing.dummy import Pool, Manager
from typing import List, Optional

import pkg_resources

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.result import Result
from yawast.shared import output


def check_open_ports(url: str, ip: str, path: Optional[str] = None) -> List[Result]:
    results = []

    # create processing pool
    pool = Pool(os.cpu_count() * 2)
    mgr = Manager()
    queue = mgr.Queue()

    # read the data in from the data directory
    if path is None:
        file_path = pkg_resources.resource_filename(
            "yawast", "resources/common_ports.json"
        )
    else:
        file_path = path

    with open(file_path) as json_file:
        data = json.load(json_file)

    for rec in data:
        pool.apply_async(_is_port_open, (url, ip, rec, queue))

    pool.close()
    pool.join()

    while not queue.empty():
        val = queue.get()
        if val is not None:
            results.append(val)

    return results


def _is_port_open(url: str, ip: str, rec, queue):
    sock = socket.socket()
    port = rec["port"]

    # set a timeout - this has a huge speed impact
    sock.settimeout(0.75)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    connected = False
    try:
        connected = sock.connect_ex((ip, port)) == 0
        sock.close()
    except Exception:
        # this shouldn't happen, but just in case
        output.debug_exception()

    if connected:
        queue.put(
            Result(
                f"Open Port: IP: {ip} - Port: {port} (Assigned Service: {rec['name']} - {rec['desc']})",
                Vulnerabilities.NETWORK_OPEN_PORT,
                url,
                {"ip": ip, "port": port},
            )
        )
