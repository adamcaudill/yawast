#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from typing import List, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sslyze import server_connectivity_tester, synchronous_scanner, __version__
from sslyze.plugins import (
    certificate_info_plugin,
    openssl_cipher_suites_plugin,
    compression_plugin,
    fallback_scsv_plugin,
    heartbleed_plugin,
    openssl_ccs_injection_plugin,
    session_renegotiation_plugin,
    session_resumption_plugin,
    robot_plugin,
    early_data_plugin,
)
from validator_collection import checkers

from yawast.reporting import reporter, issue
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.dns import basic
from yawast.scanner.plugins.ssl import cert_info
from yawast.scanner.session import Session
from yawast.shared import output, utils


def scan(session: Session):
    output.norm(
        f"Beginning SSL scan using sslyze {__version__} (this could take a minute or two)"
    )
    output.empty()

    ips = basic.get_ips(session.domain)

    for ip in ips:
        try:
            conn_tester = server_connectivity_tester.ServerConnectivityTester(
                hostname=session.domain, port=utils.get_port(session.url), ip_address=ip
            )

            output.norm(f"IP: {conn_tester.ip_address}:{conn_tester.port}")
            server_info = conn_tester.perform()

            scanner = synchronous_scanner.SynchronousScanner()

            cinfo = scanner.run_scan_command(
                server_info, certificate_info_plugin.CertificateInfoScanCommand()
            )
            cinfo = cast(certificate_info_plugin.CertificateInfoScanResult, cinfo)

            # print info on the server cert
            _get_leaf_cert_info(cinfo.verified_certificate_chain[0])

            # get all but the first element
            _get_cert_chain(cinfo.verified_certificate_chain[1:], session.url)

            # list the root stores this is trusted by
            trust = ""
            for t in _get_trusted_root_stores(cinfo):
                trust += f"{t} (trusted) "

            output.norm(f"\tRoot Stores: {trust}")

            output.empty()

            # get info for the various versions of SSL/TLS
            output.norm("\tCipher Suite Support:")

            sslv2 = scanner.run_scan_command(
                server_info, openssl_cipher_suites_plugin.Sslv20ScanCommand()
            )
            sslv2 = cast(openssl_cipher_suites_plugin.CipherSuiteScanResult, sslv2)

            _get_suite_info("SSLv2", sslv2, session.url)

            sslv3 = scanner.run_scan_command(
                server_info, openssl_cipher_suites_plugin.Sslv30ScanCommand()
            )
            sslv3 = cast(openssl_cipher_suites_plugin.CipherSuiteScanResult, sslv3)

            _get_suite_info("SSLv3", sslv3, session.url)

            tls10 = scanner.run_scan_command(
                server_info, openssl_cipher_suites_plugin.Tlsv10ScanCommand()
            )
            tls10 = cast(openssl_cipher_suites_plugin.CipherSuiteScanResult, tls10)

            _get_suite_info("TLSv1.0", tls10, session.url)

            tls11 = scanner.run_scan_command(
                server_info, openssl_cipher_suites_plugin.Tlsv11ScanCommand()
            )
            tls11 = cast(openssl_cipher_suites_plugin.CipherSuiteScanResult, tls11)

            _get_suite_info("TLSv1.1", tls11, session.url)

            tls12 = scanner.run_scan_command(
                server_info, openssl_cipher_suites_plugin.Tlsv12ScanCommand()
            )
            tls12 = cast(openssl_cipher_suites_plugin.CipherSuiteScanResult, tls12)

            _get_suite_info("TLSv1.2", tls12, session.url)

            tls13 = scanner.run_scan_command(
                server_info, openssl_cipher_suites_plugin.Tlsv13ScanCommand()
            )
            tls13 = cast(openssl_cipher_suites_plugin.CipherSuiteScanResult, tls13)

            _get_suite_info("TLSv1.3", tls13, session.url)

            output.empty()

            # check compression
            compression = scanner.run_scan_command(
                server_info, compression_plugin.CompressionScanCommand()
            )
            compression = cast(compression_plugin.CompressionScanResult, compression)

            if compression.compression_name is not None:
                reporter.display(
                    f"\tCompression: {compression.compression_name}",
                    issue.Issue(
                        Vulnerabilities.TLS_COMPRESSION_ENABLED, session.url, {}
                    ),
                )
            else:
                output.norm("\tCompression: None")

            # check TLS_FALLBACK_SCSV
            fallback = scanner.run_scan_command(
                server_info, fallback_scsv_plugin.FallbackScsvScanCommand()
            )
            fallback = cast(fallback_scsv_plugin.FallbackScsvScanResult, fallback)

            if fallback.supports_fallback_scsv:
                output.norm("\tDowngrade Prevention: Yes")
            else:
                reporter.display(
                    "\tDowngrade Prevention: No",
                    issue.Issue(
                        Vulnerabilities.TLS_FALLBACK_SCSV_MISSING, session.url, {}
                    ),
                )

            # check Heartbleed
            heartbleed = scanner.run_scan_command(
                server_info, heartbleed_plugin.HeartbleedScanCommand()
            )
            heartbleed = cast(heartbleed_plugin.HeartbleedScanResult, heartbleed)

            if heartbleed.is_vulnerable_to_heartbleed:
                reporter.display(
                    "\tHeartbleed: Vulnerable",
                    issue.Issue(Vulnerabilities.TLS_HEARTBLEED, session.url, {}),
                )
            else:
                output.norm("\tHeartbleed: No")

            # check OpenSSL CCS injection vulnerability (CVE-2014-0224)
            openssl_ccs = scanner.run_scan_command(
                server_info,
                openssl_ccs_injection_plugin.OpenSslCcsInjectionScanCommand(),
            )
            openssl_ccs = cast(
                openssl_ccs_injection_plugin.OpenSslCcsInjectionScanResult, openssl_ccs
            )

            if openssl_ccs.is_vulnerable_to_ccs_injection:
                reporter.display(
                    "\tOpenSSL CCS (CVE-2014-0224): Vulnerable",
                    issue.Issue(
                        Vulnerabilities.TLS_OPENSSL_CVE_2014_0224, session.url, {}
                    ),
                )
            else:
                output.norm("\tOpenSSL CCS (CVE-2014-0224): No")

            # check SessionRenegotiation
            sr = scanner.run_scan_command(
                server_info,
                session_renegotiation_plugin.SessionRenegotiationScanCommand(),
            )
            sr = cast(session_renegotiation_plugin.SessionRenegotiationScanResult, sr)

            if sr.accepts_client_renegotiation:
                output.norm(
                    "\tSecure Renegotiation: client-initiated renegotiation supported"
                )

            if sr.supports_secure_renegotiation:
                output.norm("\tSecure Renegotiation: secure renegotiation supported")

            # check SessionResumption
            resump = scanner.run_scan_command(
                server_info,
                session_resumption_plugin.SessionResumptionSupportScanCommand(),
            )
            resump = cast(
                session_resumption_plugin.SessionResumptionSupportScanResult, resump
            )

            output.norm(
                f"\tSession Resumption Tickets Supported: {resump.is_ticket_resumption_supported}"
            )

            output.norm(
                f"\tSession Resumption: {resump.successful_resumptions_nb} of "
                f"{resump.attempted_resumptions_nb} successful"
            )

            # check ROBOT
            robot = scanner.run_scan_command(
                server_info, robot_plugin.RobotScanCommand()
            )
            robot = cast(robot_plugin.RobotScanResult, robot)

            if (
                robot.robot_result_enum
                == robot_plugin.RobotScanResultEnum.VULNERABLE_WEAK_ORACLE
            ):
                reporter.display(
                    "\tROBOT: Vulnerable - Not Exploitable",
                    issue.Issue(Vulnerabilities.TLS_ROBOT_ORACLE_WEAK, session.url, {}),
                )
            elif (
                robot.robot_result_enum
                == robot_plugin.RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
            ):
                reporter.display(
                    "\tROBOT: Vulnerable - Exploitable",
                    issue.Issue(
                        Vulnerabilities.TLS_ROBOT_ORACLE_STRONG, session.url, {}
                    ),
                )
            elif (
                robot.robot_result_enum
                == robot_plugin.RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS
            ):
                output.error("\tROBOT: Test Failed (Inconsistent Results)")
            else:
                output.norm("\tROBOT: No")

            # check TLS 1.3 Early Data
            ed = scanner.run_scan_command(
                server_info, early_data_plugin.EarlyDataScanCommand()
            )
            ed = cast(early_data_plugin.EarlyDataScanResult, ed)

            if ed.is_early_data_supported:
                output.info("\tTLS 1.3 0-RTT Support: Yes")
            else:
                output.norm("\tTLS 1.3 0-RTT Support: No")

            if cinfo.ocsp_response_status is not None:
                output.norm("\tOCSP Stapling: Yes")
            else:
                reporter.display(
                    "\tOCSP Stapling: No",
                    issue.Issue(
                        Vulnerabilities.TLS_OCSP_STAPLE_MISSING, session.url, {}
                    ),
                )

            output.empty()

        except server_connectivity_tester.ServerConnectivityError as error:
            output.debug_exception()

            if checkers.is_ipv6(ip):
                output.error(
                    "\tError connecting to IPv6 IP. Please ensure that your system is configured properly."
                )

            output.error(f"\tConnection failed ({str(error)})")
            output.empty()
        except Exception as error:
            output.debug_exception()

            output.error(f"Error performing TLS scan: #{str(error)}")


def _get_leaf_cert_info(cert: x509.Certificate):
    output.norm("Certificate Information:")

    output.norm(f"\tSubject: {cert.subject.rfc4514_string()}")
    output.norm(f'\tCommon Names: {" ".join(cert_info.get_common_names(cert))}')

    output.norm("\tAlternative names:")
    alt_names = cert_info.get_alt_names(cert)
    for name in alt_names:
        output.norm(f"\t\t{name}")

    output.norm(f'\tNot Before: {cert.not_valid_before.isoformat(" ")}')
    output.norm(f'\tNot After: {cert.not_valid_after.isoformat(" ")}')

    output.norm(f"\tKey: {cert.signature_algorithm_oid._name}")

    # TODO: Public Key Hash

    serial = format(cert.serial_number, "02x")
    output.norm(f"\tSerial: {serial}")

    output.norm(f"\tIssuer: {cert.issuer.rfc4514_string()}")

    output.norm(f"\tOCSP Must Staple: {cert_info.get_must_staple(cert)}")

    output.empty()

    exts = cert_info.format_extensions(cert)
    for ext in exts:
        output.norm(f"\tExtensions: {ext}")

    output.empty()

    scts = cert_info.get_scts(cert)
    for sct in scts:
        output.norm(
            f'\tSCT: {cert_info.get_ct_log_name(sct[1])} - {sct[2].isoformat(" ")}'
        )

    output.empty()

    cert_hash = bytes.hex(cert.fingerprint(hashes.SHA1()))
    output.norm(f"\tFingerprint: {cert_hash}")
    output.norm(f"\t\thttps://censys.io/certificates?q={cert_hash}")
    output.norm(f"\t\thttps://crt.sh/?q={cert_hash}")

    output.empty()


def _get_cert_chain(chain: List[x509.Certificate], url: str):
    if len(chain) > 0:
        output.norm("\tCertificate Chain:")

        for cert in chain:
            output.norm(f"\t\tSubject: {cert.subject.rfc4514_string()}")
            output.norm(f"\t\t Signature: {cert.signature_algorithm_oid._name}")

            fp = bytes.hex(cert.fingerprint(hashes.SHA256()))
            if cert_info.check_symantec_root(fp):
                reporter.display(
                    "\t\t Untrusted Symantec Root",
                    issue.Issue(
                        Vulnerabilities.TLS_SYMANTEC_ROOT, url, {"fingerprint": fp}
                    ),
                )

            output.norm(
                f"\t\t https://crt.sh/?q={bytes.hex(cert.fingerprint(hashes.SHA1()))}"
            )

        output.empty()


def _get_trusted_root_stores(
    result: certificate_info_plugin.CertificateInfoScanResult
) -> List[str]:
    trusted = []

    for res in result.path_validation_result_list:
        if res.was_validation_successful:
            trusted.append(res.trust_store.name)

    return trusted


def _get_suite_info(
    proto: str, result: openssl_cipher_suites_plugin.CipherSuiteScanResult, url: str
):
    output.norm(f"\t\t{proto}:")

    if len(result.accepted_cipher_list) > 0:
        for suite in result.accepted_cipher_list:
            name = openssl_cipher_suites_plugin.OPENSSL_TO_RFC_NAMES_MAPPING[
                suite.ssl_version
            ].get(suite.openssl_name, suite.openssl_name)

            if _is_cipher_suite_secure(suite, name):
                if "CBC" in name:
                    output.info(f"\t\t  {name.ljust(50)} - {suite.key_size}-bits")

                    reporter.register(
                        issue.Issue(
                            Vulnerabilities.TLS_CBC_CIPHER_SUITE, url, {"cipher": name}
                        )
                    )
                else:
                    output.norm(f"\t\t  {name.ljust(50)} - {suite.key_size}-bits")
            else:
                output.vuln(f"\t\t  {name.ljust(50)} - {suite.key_size}-bits")

                reporter.register(
                    issue.Issue(
                        Vulnerabilities.TLS_INSECURE_CIPHER_SUITE, url, {"cipher": name}
                    )
                )

        output.norm(f"\t\t  ({len(result.rejected_cipher_list)} suites rejected)")
    else:
        output.norm(f"\t\t  (all suites ({len(result.rejected_cipher_list)}) rejected)")


def _is_cipher_suite_secure(
    suite: openssl_cipher_suites_plugin.AcceptedCipherSuite, name: str
) -> bool:
    ret = True

    if suite.is_anonymous:
        ret = False

    if "RC4" in name:
        ret = False

    if "DES" in name:
        ret = False

    if suite.key_size is not None:
        if suite.key_size < 128:
            ret = False

    return ret
