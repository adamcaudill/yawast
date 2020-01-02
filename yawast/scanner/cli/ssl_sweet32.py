#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from nassl.ssl_client import OpenSslVersionEnum
from sslyze import server_connectivity_tester
from sslyze.plugins.openssl_cipher_suites_plugin import OPENSSL_TO_RFC_NAMES_MAPPING
from sslyze.utils import (
    ssl_connection_configurator,
    ssl_connection,
    http_response_parser,
)
from validator_collection import checkers

from yawast.reporting import reporter, issue
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.dns import basic
from yawast.scanner.session import Session
from yawast.shared import output, utils, network


def scan(session: Session):
    ips = basic.get_ips(session.domain)

    for ip in ips:
        conn = None
        count = 0

        try:
            count = 0

            conn_tester = server_connectivity_tester.ServerConnectivityTester(
                hostname=session.domain, port=utils.get_port(session.url), ip_address=ip
            )

            output.norm(
                f"TLS Session Request Limit: Checking number of requests accepted using 3DES suites "
                f"(IP: {conn_tester.ip_address}:{conn_tester.port})"
            )

            server_info = conn_tester.perform()
            conn = ssl_connection_configurator.SslConnectionConfigurator.get_connection(
                ssl_version=OpenSslVersionEnum.SSLV23,
                server_info=server_info,
                should_use_legacy_openssl=True,
                openssl_cipher_string="3DES",
                should_ignore_client_auth=True,
                ssl_verify_locations=None,
            )

            conn.connect()

            req = (
                "HEAD / HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "User-Agent: {user_agent}\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n".format(
                    host=session.domain, user_agent=network.YAWAST_UA
                )
            )

            ossl_name = conn.ssl_client.get_current_cipher_name()
            name = OPENSSL_TO_RFC_NAMES_MAPPING[OpenSslVersionEnum.TLSV1].get(
                ossl_name, ossl_name
            )
            print("       ", end="", flush=True)
            print(f"(using {name})", end="", flush=True)
            for i in range(0, 10000):
                conn.ssl_client.write(req)
                http_response_parser.HttpResponseParser.parse_from_ssl_connection(
                    conn.ssl_client
                )
                count += 1

                if i % 20:
                    print(".", end="", flush=True)

            output.empty()
            reporter.display(
                f"\tTLS Session Request Limit: Connection not terminated after {count} requests; "
                f"possibly vulnerable to SWEET32",
                issue.Issue(Vulnerabilities.TLS_SWEET32, session.url, {}),
            )

        except ssl_connection.SslHandshakeRejected as error:
            output.debug_exception()

            output.empty()
            output.norm(f"\tServer rejected our connection ({str(error)})")

            output.empty()
        except IOError as error:
            output.debug_exception()

            output.empty()
            if count > 0:
                output.norm(
                    f"\tTLS Session Request Limit: Connection terminated after {count} requests ({str(error)})"
                )
            else:
                output.norm(
                    "\tTLS Session Request Limit: Server does not support 3DES cipher suites"
                )

            output.empty()
        except server_connectivity_tester.ServerConnectivityError as error:
            output.debug_exception()

            output.empty()

            if checkers.is_ipv6(ip):
                output.error(
                    "\tError connecting to IPv6 IP. Please ensure that your system is configured properly."
                )

            output.error(f"\tConnection failed ({str(error)})")
            output.empty()
        finally:
            if conn is not None:
                conn.close()

        output.empty()
