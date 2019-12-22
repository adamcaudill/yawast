#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import sys
from time import sleep
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from yawast.reporting import reporter, issue
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.ssl import cert_info
from yawast.scanner.plugins.ssl_labs import api
from yawast.scanner.session import Session
from yawast.shared import output


def scan(session: Session):
    tty = sys.stdout.isatty()

    output.norm("Beginning SSL Labs scan (this could take a minute or two)")
    output.empty()

    # list the messages from SSL Labs - this is required as part of the ToS
    messages = api.get_info_message()
    for msg in messages:
        output.norm("[SSL Labs] {msg}".format(msg=msg))

    api.start_scan(session.domain)
    status = ""

    error_count = 0
    completed: List[str] = []
    body = None

    while status != "READY" and status != "ERROR":
        sleep(5)

        try:
            status, body = api.check_scan(session.domain)
        except Exception:
            # if we find ourselves here, we want to try a couple more times before we give up for good
            output.debug_exception()

            if error_count > 3:
                raise
            else:
                error_count += 1

        if tty:
            # clear the current line
            sys.stdout.write("\r\033[K")

            # display the current status
            if "endpoints" in body:
                msg = ""

                for ep in body["endpoints"]:
                    if (
                        ep["statusMessage"] == "Ready"
                        and ep["ipAddress"] not in completed
                    ):
                        completed.append(ep["ipAddress"])

                        sys.stdout.write(
                            f'\r       Status - {ep["ipAddress"]}: {ep["statusMessage"]}\n\r'
                        )
                    elif (
                        ep["statusMessage"] != "Pending"
                        and ep["statusMessage"] != "Ready"
                    ):
                        # get the completion percentage
                        pct = "--"
                        if "progress" in ep:
                            pct = ep["progress"]

                        sm = "unknown"
                        if "statusDetailsMessage" in ep:
                            sm = ep["statusDetailsMessage"]

                        msg = f'\r       Status - {ep["ipAddress"]}: {ep["statusMessage"]} ({sm}) - {pct}%'

                        break

                if msg != "":
                    sys.stdout.write(msg)
                else:
                    sys.stdout.write(f"\r       Status: Working...")
            elif "status" in body:
                sys.stdout.write(f'\r       Status: {body["status"]}')
            else:
                sys.stdout.write(f"\r       Status: Working...")

            # flush the buffer, to make sure it's actually written
            sys.stdout.flush()
        else:
            print(".", end="", flush=True)

    output.empty()
    output.empty()

    reporter.register_data("ssl_labs_results", body)

    # HACK: this needs to be refactored, once we have a better way to do it. This is awful.
    # (from a separation of duties perspective. this should happen in the plugin)
    if body["status"] == "ERROR":
        raise ValueError(f"SSL Labs Error: {body['status']}: {body['statusMessage']}")
    elif "endpoints" in body:
        for ep in body["endpoints"]:
            if ep["statusMessage"] == "Ready":
                output.norm(f'IP: {ep["ipAddress"]} - Grade: {ep["grade"]}')

                _get_cert_info(body, ep, session.url)
                _get_protocol_info(ep, session.url)
                _get_vulnerability_info(ep, session.url)
            else:
                output.error(
                    f'Error getting information for IP: {ep["ipAddress"]}: {ep["statusMessage"]}'
                )
                output.empty()
    else:
        output.debug(f"Invalid response received: {body}")
        output.error("Invalid response received: Endpoint data not found.")
        output.empty()

        raise ValueError(f"SSL Labs Error: {body['status']}")


def _get_cert_info(body, ep, url):
    # get the ChainCert info for the server cert - needed for extra details
    cert = None
    x509_cert = None

    for c in body["certs"]:
        if c["id"] == ep["details"]["certChains"][0]["certIds"][0]:
            cert = c
            x509_cert = x509.load_pem_x509_certificate(
                bytes(cert["raw"], "utf_8"), default_backend()
            )

    output.norm("Certificate Information:")

    if cert["issues"] > 0:
        output.warn("\tCertificate Has Issues - Not Valid")

        if cert["issues"] & 1 != 0:
            reporter.display(
                "\tCertificate Issue: no chain of trust",
                issue.Issue(Vulnerabilities.TLS_CERT_NO_TRUST, url, {"cert": cert}),
            )

        if cert["issues"] & (1 << 1) != 0:
            reporter.display(
                "\tCertificate Issue: certificate not yet valid",
                issue.Issue(
                    Vulnerabilities.TLS_CERT_NOT_YET_VALID, url, {"cert": cert}
                ),
            )

        if cert["issues"] & (1 << 2) != 0:
            reporter.display(
                "\tCertificate Issue: certificate expired",
                issue.Issue(Vulnerabilities.TLS_CERT_EXPIRED, url, {"cert": cert}),
            )

        if cert["issues"] & (1 << 3) != 0:
            reporter.display(
                "\tCertificate Issue: hostname mismatch",
                issue.Issue(
                    Vulnerabilities.TLS_CERT_HOSTNAME_MISMATCH, url, {"cert": cert}
                ),
            )

        if cert["issues"] & (1 << 4) != 0:
            reporter.display(
                "\tCertificate Issue: revoked",
                issue.Issue(Vulnerabilities.TLS_CERT_REVOKED, url, {"cert": cert}),
            )

        if cert["issues"] & (1 << 5) != 0:
            reporter.display(
                "\tCertificate Issue: bad common name",
                issue.Issue(
                    Vulnerabilities.TLS_CERT_BAD_COMMON_NAME, url, {"cert": cert}
                ),
            )

        if cert["issues"] & (1 << 6) != 0:
            reporter.display(
                "\tCertificate Issue: self-signed",
                issue.Issue(Vulnerabilities.TLS_CERT_SELF_SIGNED, url, {"cert": cert}),
            )

        if cert["issues"] & (1 << 7) != 0:
            reporter.display(
                "\tCertificate Issue: blacklisted",
                issue.Issue(Vulnerabilities.TLS_CERT_BLACKLISTED, url, {"cert": cert}),
            )

        if cert["issues"] & (1 << 8) != 0:
            reporter.display(
                "\tCertificate Issue: insecure signature",
                issue.Issue(
                    Vulnerabilities.TLS_CERT_INSECURE_SIGNATURE, url, {"cert": cert}
                ),
            )

        if cert["issues"] & (1 << 9) != 0:
            reporter.display(
                "\tCertificate Issue: insecure key",
                issue.Issue(Vulnerabilities.TLS_CERT_INSECURE_KEY, url, {"cert": cert}),
            )

        output.empty()

    output.norm(f'\tSubject: {cert["subject"]}')
    output.norm(f'\tCommon Names: {" ".join(cert["commonNames"])}')

    output.norm("\tAlternative names:")
    for name in cert["altNames"]:
        output.norm(f"\t\t{name}")

    output.norm(f'\tNot Before: {x509_cert.not_valid_before.isoformat(" ")}')
    output.norm(f'\tNot After: {x509_cert.not_valid_after.isoformat(" ")}')

    if cert["keyAlg"] == "EC":
        output.norm(
            f'\tKey: {cert["keyAlg"]} {cert["keySize"]} (RSA equivalent: {cert["keyStrength"]})'
        )
    else:
        if cert["keySize"] < 2048:
            output.vuln(f'\tKey: {cert["keyAlg"]} {cert["keySize"]}')
        else:
            output.norm(f'\tKey: {cert["keyAlg"]} {cert["keySize"]}')

    # TODO: Public Key Hash

    serial = format(x509_cert.serial_number, "02x")
    output.norm(f"\tSerial: {serial}")

    output.norm(f'\tIssuer: {cert["issuerSubject"]}')

    if "validationType" in cert:
        if cert["validationType"] == "E":
            output.norm("\tExtended Validation: Yes")
        elif cert["validationType"] == "D":
            output.norm("\tExtended Validation: No (Domain Control)")
        else:
            output.norm(f'\tExtended Validation: No ({cert["validationType"]})')

    if cert["sct"]:
        # check the first bit, SCT in cert
        if ep["details"]["hasSct"] & 1 != 0:
            output.norm("\tCertificate Transparency: SCT in certificate")

        # check second bit, SCT in stapled OSCP response
        if ep["details"]["hasSct"] & (1 << 1) != 0:
            output.norm("\tCertificate Transparency: SCT in the stapled OCSP response")

        # check third bit, SCT in the TLS extension
        if ep["details"]["hasSct"] & (1 << 2) != 0:
            output.norm(
                "\tCertificate Transparency: SCT in the TLS extension (ServerHello)"
            )
    else:
        output.norm("\tCertificate Transparency: No")

    output.norm(f'\tOCSP Must Staple: {cert["mustStaple"]}')

    if cert["revocationInfo"] & 1 != 0:
        output.norm("\tRevocation information: CRL information available")

    if cert["revocationInfo"] & (1 << 1) != 0:
        output.norm("\tRevocation information: OCSP information available")

    if cert["revocationStatus"] == 0:
        output.norm("\tRevocation Status: not checked")
    elif cert["revocationStatus"] == 1:
        output.vuln('\tRevocation Status: certificate revoked"')
    elif cert["revocationStatus"] == 2:
        output.norm("\tRevocation Status: certificate not revoked")
    elif cert["revocationStatus"] == 3:
        output.warn("\tRevocation Status: revocation check error")
    elif cert["revocationStatus"] == 4:
        output.warn("\tRevocation Status: no revocation information")
    elif cert["revocationStatus"] == 5:
        output.error("\tRevocation Status: SSL Labs internal error")
    else:
        output.error(
            f'\tRevocation Status: Unknown response ({cert["revocationStatus"]})'
        )

    if "crlRevocationStatus" in cert:
        if cert["crlRevocationStatus"] == 0:
            output.norm("\tCRL Revocation Status: not checked")
        elif cert["crlRevocationStatus"] == 1:
            output.vuln('\tCRL Revocation Status: certificate revoked"')
        elif cert["crlRevocationStatus"] == 2:
            output.norm("\tCRL Revocation Status: certificate not revoked")
        elif cert["crlRevocationStatus"] == 3:
            output.warn("\tCRL Revocation Status: revocation check error")
        elif cert["crlRevocationStatus"] == 4:
            output.warn("\tCRL Revocation Status: no revocation information")
        elif cert["crlRevocationStatus"] == 5:
            output.error("\tCRL Revocation Status: SSL Labs internal error")
        else:
            output.error(
                f'\tCRL Revocation Status: Unknown response ({cert["crlRevocationStatus"]})'
            )
    else:
        output.norm("\tCRL Revocation Status: Not Provided")

    if "ocspRevocationStatus" in cert:
        if cert["ocspRevocationStatus"] == 0:
            output.norm("\tOCSP Revocation Status: not checked")
        elif cert["ocspRevocationStatus"] == 1:
            output.vuln('\tOCSP Revocation Status: certificate revoked"')
        elif cert["ocspRevocationStatus"] == 2:
            output.norm("\tOCSP Revocation Status: certificate not revoked")
        elif cert["ocspRevocationStatus"] == 3:
            output.warn("\tOCSP Revocation Status: revocation check error")
        elif cert["ocspRevocationStatus"] == 4:
            output.warn("\tOCSP Revocation Status: no revocation information")
        elif cert["ocspRevocationStatus"] == 5:
            output.error("\tOCSP Revocation Status: SSL Labs internal error")
        else:
            output.error(
                f'\tOCSP Revocation Status: Unknown response ({cert["ocspRevocationStatus"]})'
            )
    else:
        output.norm("\tOCSP Revocation Status: Not Provided")

    output.empty()

    exts = cert_info.format_extensions(x509_cert)
    for ext in exts:
        output.norm(f"\tExtensions: {ext}")

    output.empty()

    scts = cert_info.get_scts(x509_cert)
    for sct in scts:
        output.norm(
            f'\tSCT: {cert_info.get_ct_log_name(sct[1])} - {sct[2].isoformat(" ")}'
        )

    output.empty()

    cert_hash = bytes.hex(x509_cert.fingerprint(hashes.SHA1()))
    output.norm(f"\tFingerprint: {cert_hash}")
    output.norm(f"\t\thttps://censys.io/certificates?q={cert_hash}")
    output.norm(f"\t\thttps://crt.sh/?q={cert_hash}")

    output.empty()

    output.norm("\tCertificate Chains:")
    for chain in ep["details"]["certChains"]:
        path_count = 0

        # build list of trust paths
        trust_paths = {}
        for path in chain["trustPaths"]:
            trusts = None

            # in practice, it seems there is only only per path, but just in case
            for trust in path["trust"]:

                if trust["isTrusted"]:
                    trust_line = f'{trust["rootStore"]} (trusted)'
                else:
                    trust_line = f'{trust["rootStore"]} ({trust["trustErrorMessage"]})'

                if trusts is None:
                    trusts = trust_line
                else:
                    trusts += f" {trust_line}"

            if trust_paths.get(tuple(path["certIds"])) is not None:
                trust_paths[tuple(path["certIds"])] += f" {trusts}"
            else:
                trust_paths[tuple(path["certIds"])] = trusts

        # process each of the trust paths
        for key in trust_paths.keys():
            path_count += 1

            output.norm(f"\t  Path {path_count}:")
            output.norm(f"\t   Root Stores: {trust_paths[key]}")

            if chain["issues"] & (1 << 1) != 0:
                output.warn("\tCertificate Chain Issue: incomplete chain")

            if chain["issues"] & (1 << 2) != 0:
                output.warn(
                    "\tCertificate Chain Issue: chain contains unrelated/duplicate certificates"
                )

            if chain["issues"] & (1 << 3) != 0:
                output.warn("\tCertificate Chain Issue: incorrect order")

            if chain["issues"] & (1 << 4) != 0:
                output.warn("\tCertificate Chain Issue: contains anchor")

            if cert["issues"] & (1 << 5) != 0:
                output.warn("\tCertificate Chain Issue: untrusted")

            for path_cert in key:
                for c in body["certs"]:
                    if c["id"] == path_cert:
                        output.norm(f'\t\t{c["subject"]}')
                        output.norm(
                            f'\t\t Signature: {c["sigAlg"]}  Key: {c["keyAlg"]}-{c["keySize"]}'
                        )

                        if cert_info.check_symantec_root(c["sha256Hash"]):
                            reporter.display(
                                "\t\t Untrusted Symantec Root",
                                issue.Issue(
                                    Vulnerabilities.TLS_SYMANTEC_ROOT,
                                    url,
                                    {"fingerprint": c["sha1Hash"]},
                                ),
                            )

                        output.norm(f'\t\t  https://crt.sh/?q={c["sha1Hash"]}')

                        if c["sha256Hash"] not in chain["certIds"]:
                            output.norm("\t\t  (provided by server)")

    output.empty()


def _get_protocol_info(ep, url):
    output.norm("Configuration Information:")
    output.norm("\tProtocol Support:")

    # check protocols
    protos = {}
    tls13_enabled = False

    for proto in ep["details"]["protocols"]:
        if proto["name"] == "SSL":
            # show a vuln for SSLvX

            reporter.display(
                f'\t\t{proto["name"]} {proto["version"]}',
                issue.Issue(
                    Vulnerabilities.TLS_LEGACY_SSL_ENABLED, url, {"ip": ep["ipAddress"]}
                ),
            )
        elif proto["name"] == "TLS" and proto["version"] == "1.0":
            # show a warn for TLSv1.0

            reporter.display(
                f'\t\t{proto["name"]} {proto["version"]}',
                issue.Issue(
                    Vulnerabilities.TLS_VERSION_1_0_ENABLED,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        elif proto["name"] == "TLS" and proto["version"] == "1.3":
            # capture TLS 1.3 status
            tls13_enabled = True

            output.norm(f'\t\t{proto["name"]} {proto["version"]}')
        else:
            output.norm(f'\t\t{proto["name"]} {proto["version"]}')

        protos[proto["id"]] = f'{proto["name"]} {proto["version"]}'

    if not tls13_enabled:
        reporter.display(
            "\t\tTLS 1.3 Is Not Enabled",
            issue.Issue(
                Vulnerabilities.TLS_VERSION_1_3_NOT_ENABLED,
                url,
                {"ip": ep["ipAddress"]},
            ),
        )

    output.empty()

    if "namedGroups" in ep["details"]:
        output.norm("\tNamed Group Support:")

        for group in ep["details"]["namedGroups"]["list"]:
            output.norm(f'\t\t{group["name"]} {group["bits"]}')

        output.empty()

    if "suites" in ep["details"]:
        output.norm("\tCipher Suite Support:")

        for proto_suites in ep["details"]["suites"]:
            output.norm(f'\t\t{protos[proto_suites["protocol"]]}')

            for suite in proto_suites["list"]:
                ke = _get_key_exchange(suite)

                strength = suite["cipherStrength"]

                if "3DES" in suite["name"]:
                    # in this case, the effective strength is only 112 bits,
                    #  which is what we want to report. So override SSL Labs
                    strength = 112

                if ke is not None:
                    suite_info = f'{suite["name"].ljust(50)} - {strength}-bits - {ke}'
                else:
                    suite_info = f'{suite["name"].ljust(50)} - {strength}-bits'

                if _is_cipher_suite_secure(suite):
                    if "CBC" in suite["name"]:
                        output.info(f"\t\t  {suite_info}")

                        reporter.register(
                            issue.Issue(
                                Vulnerabilities.TLS_CBC_CIPHER_SUITE,
                                url,
                                {"cipher": suite_info},
                            )
                        )
                    else:
                        output.norm(f"\t\t  {suite_info}")
                else:
                    output.vuln(f"\t\t  {suite_info}")

                    reporter.register(
                        issue.Issue(
                            Vulnerabilities.TLS_INSECURE_CIPHER_SUITE,
                            url,
                            {"cipher": suite_info},
                        )
                    )

    output.empty()

    _get_simulations(ep, protos)


def _get_key_exchange(suite, is_sim: Optional[bool] = False):
    ke = None

    if "kxType" in suite:
        if "namedGroupBits" in suite:
            ke = (
                f'{suite["kxType"]}-{suite["namedGroupBits"]} / '
                f'{suite["namedGroupName"]} ({suite["kxStrength"]} equivalent)'
            )
        else:
            if is_sim:
                if suite["kxType"] == "DH" and "dhBits" in suite:
                    ke = f'{suite["kxType"]}-{suite["dhBits"]}'
                else:
                    ke = f'{suite["kxType"]}-{suite["kxStrength"]}'
            else:
                ke = f'{suite["kxType"]}-{suite["kxStrength"]}'

    return ke


def _is_cipher_suite_secure(suite):
    secure = True

    # check for weak DH
    if "kxStrength" in suite and suite["kxStrength"] < 2048:
        secure = False

    # check for RC4
    if "RC4" in suite["name"]:
        secure = False

    # check for weak suites
    if suite["cipherStrength"] < 128:
        secure = False

    return secure


def _get_simulations(ep, protos):
    if ep["details"]["sims"]["results"] is not None:
        output.norm("\tHandshake Simulation:")

        for sim in ep["details"]["sims"]["results"]:
            name = f'{sim["client"]["name"]} {sim["client"]["version"]}'

            if "platform" in sim["client"]:
                name += f' / {sim["client"]["platform"]}'

            name = name.ljust(28)

            if sim["errorCode"] == 0:
                protocol = protos[sim["protocolId"]]
                ke = _get_key_exchange(sim, True)

                if ke is not None:
                    suite_name = f'{sim["suiteName"]} - {ke}'
                else:
                    suite_name = f'{sim["suiteName"]}'

                output.norm(f"\t\t{name} - {protocol} - {suite_name}")
            else:
                output.info(f"\t\t{name} - Simulation Failed")

        output.empty()


def _get_vulnerability_info(ep, url):
    output.norm("\tProtocol & Vulnerability Information:")

    if "sniRequired" in ep["details"]:
        if ep["details"]["sniRequired"]:
            output.info("\t\tSNI Required: Yes")
        else:
            output.norm("\t\tSNI Required: No")

    if "drownVulnerable" in ep["details"]:
        if ep["details"]["drownVulnerable"]:
            output.vuln("\t\tDROWN: Vulnerable")

            servers = ""
            for dh in ep["details"]["drownHosts"]:
                servers += f'({dh["ip"]}:{dh["port"]} - {dh["status"]}) '
                output.norm(f'\t\t\t{dh["ip"]}:{dh["port"]} - {dh["status"]}')
                output.norm(f'\t\t\t  https://test.drownattack.com/?site={dh["ip"]}')

            reporter.register(
                issue.Issue(
                    Vulnerabilities.TLS_DROWN,
                    url,
                    {"servers": servers, "ip": ep["ipAddress"]},
                )
            )
        else:
            output.norm("\t\tDROWN: No")
    else:
        output.error("\t\tDROWN: Information Not Received")

    if "zeroRTTEnabled" in ep["details"]:
        if ep["details"]["zeroRTTEnabled"] == -2:
            output.error("\t\tTLS 1.3 0-RTT Support: Test Failed")
        elif ep["details"]["zeroRTTEnabled"] == -1:
            output.norm("\t\tTLS 1.3 0-RTT Support: Test Not Performed")
        elif ep["details"]["zeroRTTEnabled"] == 0:
            output.norm("\t\tTLS 1.3 0-RTT Support: No")
        elif ep["details"]["zeroRTTEnabled"] == 1:
            reporter.display(
                "\t\tTLS 1.3 0-RTT Support: Yes",
                issue.Issue(
                    Vulnerabilities.TLS_VERSION_1_3_EARLY_DATA_ENABLED,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.error(
                f'\t\tTLS 1.3 0-RTT Support: Unknown ({ep["details"]["zeroRTTEnabled"]})'
            )
    else:
        output.error("\t\tTLS 1.3 0-RTT Support: Information Not Received")

    if "renegSupport" in ep["details"]:
        if ep["details"]["renegSupport"] & 1 != 0:
            reporter.display(
                "\t\tSecure Renegotiation: insecure client-initiated renegotiation supported",
                issue.Issue(
                    Vulnerabilities.TLS_INSECURE_RENEG, url, {"ip": ep["ipAddress"]}
                ),
            )

        if ep["details"]["renegSupport"] & (1 << 1) != 0:
            output.norm("\t\tSecure Renegotiation: secure renegotiation supported")

        if ep["details"]["renegSupport"] & (1 << 2) != 0:
            output.norm(
                "\t\tSecure Renegotiation: secure client-initiated renegotiation supported"
            )

        if ep["details"]["renegSupport"] & (1 << 3) != 0:
            output.norm(
                '\t\tSecure Renegotiation: server requires secure renegotiation support"'
            )
    else:
        output.error("\t\tSecure Renegotiation: Information Not Received")

    if "poodle" in ep["details"]:
        if ep["details"]["poodle"]:
            reporter.display(
                "\t\tPOODLE (SSL): Vulnerable",
                issue.Issue(
                    Vulnerabilities.TLS_LEGACY_SSL_POODLE, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.norm("\t\tPOODLE (SSL): No")
    else:
        output.error("\t\tPOODLE (SSL): Information Not Received")

    if "zombiePoodle" in ep["details"]:
        if ep["details"]["zombiePoodle"] == -1:
            output.error("\t\tZombie POODLE: Test Failed")
        elif ep["details"]["zombiePoodle"] == 0:
            output.error("\t\tZombie POODLE: Test Failed (Unknown)")
        elif ep["details"]["zombiePoodle"] == 1:
            output.norm("\t\tZombie POODLE: No")
        elif ep["details"]["zombiePoodle"] == 2:
            reporter.display(
                "\t\tZombie POODLE: Vulnerable - Not Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_ZOMBIE_POODLE_NE, url, {"ip": ep["ipAddress"]}
                ),
            )
        elif ep["details"]["zombiePoodle"] == 3:
            output.vuln("\t\tZombie POODLE: Vulnerable - Exploitable")
            reporter.display(
                "\t\tZombie POODLE: Vulnerable - Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_ZOMBIE_POODLE, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.error(
                f'\t\tZombie POODLE: Unknown Response ({ep["details"]["zombiePoodle"]})'
            )
    else:
        output.error("\t\tZombie POODLE: Information Not Received")

    if "goldenDoodle" in ep["details"]:
        if ep["details"]["goldenDoodle"] == -1:
            output.error("\t\tGOLDENDOODLE: Test Failed")
        elif ep["details"]["goldenDoodle"] == 0:
            output.error("\t\tGOLDENDOODLE: Test Failed (Unknown)")
        elif ep["details"]["goldenDoodle"] == 1:
            output.norm("\t\tGOLDENDOODLE: No")
        elif ep["details"]["goldenDoodle"] == 4:
            reporter.display(
                "\t\tGOLDENDOODLE: Vulnerable - Not Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_GOLDENDOODLE_NE, url, {"ip": ep["ipAddress"]}
                ),
            )
        elif ep["details"]["goldenDoodle"] == 5:
            reporter.display(
                "\t\tGOLDENDOODLE: Vulnerable - Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_GOLDENDOODLE, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.error(
                f't\tGOLDENDOODLE: Unknown Response ({ep["details"]["goldenDoodle"]})'
            )
    else:
        output.error("\t\tGOLDENDOODLE: Information Not Received")

    if "zeroLengthPaddingOracle" in ep["details"]:
        if ep["details"]["zeroLengthPaddingOracle"] == -1:
            output.error(
                "\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Test Failed"
            )
        elif ep["details"]["zeroLengthPaddingOracle"] == 0:
            output.error(
                "\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Test Failed (Unknown)"
            )
        elif ep["details"]["zeroLengthPaddingOracle"] == 1:
            output.norm("\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): No")
        elif ep["details"]["zeroLengthPaddingOracle"] == 6:
            reporter.display(
                "\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Vulnerable - Not Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_OPENSSL_CVE_2019_1559_NE,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        elif ep["details"]["zeroLengthPaddingOracle"] == 7:
            reporter.display(
                "\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Vulnerable - Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_OPENSSL_CVE_2019_1559,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.error(
                f"\t\tOpenSSL 0-Length Padding Oracle (CVE-2019-1559): Unknown Response"
                f' ({ep["details"]["zeroLengthPaddingOracle"]})'
            )
    else:
        output.error(
            "OpenSSL 0-Length Padding Oracle (CVE-2019-1559): Information Not Received"
        )

    if "sleepingPoodle" in ep["details"]:
        if ep["details"]["sleepingPoodle"] == -1:
            output.error("\t\tSleeping POODLE: Test Failed")
        elif ep["details"]["sleepingPoodle"] == 0:
            output.error("\t\tSleeping POODLE: Test Failed (Unknown)")
        elif ep["details"]["sleepingPoodle"] == 1:
            output.norm("\t\tSleeping POODLE: No")
        elif ep["details"]["sleepingPoodle"] == 10:
            reporter.display(
                "\t\tSleeping POODLE: Vulnerable - Not Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_SLEEPING_POODLE_NE, url, {"ip": ep["ipAddress"]}
                ),
            )
        elif ep["details"]["sleepingPoodle"] == 11:
            output.vuln("\t\tSleeping POODLE: Vulnerable - Exploitable")
            reporter.display(
                "\t\tSleeping POODLE: Vulnerable - Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_SLEEPING_POODLE, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.error(
                f'\t\tSleeping POODLE: Unknown Response ({ep["details"]["sleepingPoodle"]})'
            )
    else:
        output.error("\t\tSleeping POODLE: Information Not Received")

    if "poodleTls" in ep["details"]:
        if ep["details"]["poodleTls"] == -3:
            output.info("\t\tPOODLE (TLS): Inconclusive (Timeout)")
        elif ep["details"]["poodleTls"] == -2:
            output.info("\t\tPOODLE (TLS): TLS Not Supported")
        elif ep["details"]["poodleTls"] == -1:
            output.error("\t\tPOODLE (TLS): Test Failed")
        elif ep["details"]["poodleTls"] == 0:
            output.error("\t\tPOODLE (TLS): Test Failed (Unknown)")
        elif ep["details"]["poodleTls"] == 1:
            output.norm("\t\tPOODLE (TLS): No")
        elif ep["details"]["poodleTls"] == 2:
            reporter.display(
                "\t\tPOODLE (TLS): Vulnerable",
                issue.Issue(Vulnerabilities.TLS_POODLE, url, {"ip": ep["ipAddress"]}),
            )
        else:
            output.error(
                f'\t\tPOODLE (TLS): Unknown Response ({ep["details"]["poodleTls"]})'
            )
    else:
        output.error("\t\tPOODLE (TLS): Information Not Received")

    if "fallbackScsv" in ep["details"]:
        if ep["details"]["fallbackScsv"]:
            output.norm("\t\tDowngrade Prevention: Yes")
        else:
            reporter.display(
                "\t\tDowngrade Prevention: No",
                issue.Issue(
                    Vulnerabilities.TLS_FALLBACK_SCSV_MISSING,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
    else:
        output.error("\t\tDowngrade Prevention: Information Not Received")

    if "compressionMethods" in ep["details"]:
        if ep["details"]["compressionMethods"] & 1 != 0:
            reporter.display(
                "\t\tCompression: DEFLATE",
                issue.Issue(
                    Vulnerabilities.TLS_COMPRESSION_ENABLED,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.norm("\t\tCompression: No")
    else:
        output.error("\t\tCompression: Information Not Received")

    if "heartbeat" in ep["details"]:
        if ep["details"]["heartbeat"]:
            reporter.display(
                "\t\tHeartbeat: Enabled",
                issue.Issue(
                    Vulnerabilities.TLS_HEARTBEAT_ENABLED, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.norm("\t\tHeartbeat: Disabled")
    else:
        output.error("\t\tHeartbeat: Information Not Received")

    if "heartbleed" in ep["details"]:
        if ep["details"]["heartbleed"]:
            reporter.display(
                "\t\tHeartbleed: Vulnerable",
                issue.Issue(
                    Vulnerabilities.TLS_HEARTBLEEDL, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.norm("\t\tHeartbleed: No")
    else:
        output.error("\t\tHeartbleed: Information Not Received")

    if "ticketbleed" in ep["details"]:
        if ep["details"]["ticketbleed"] == -1:
            output.error("\t\tTicketbleed (CVE-2016-9244): Test Failed")
        elif ep["details"]["ticketbleed"] == 0:
            output.error("\t\tTicketbleed (CVE-2016-9244): Test Failed (Unknown)")
        elif ep["details"]["ticketbleed"] == 1:
            output.norm("\t\tTicketbleed (CVE-2016-9244): No")
        elif ep["details"]["ticketbleed"] == 2:
            reporter.display(
                "\t\tTicketbleed (CVE-2016-9244): Vulnerable",
                issue.Issue(
                    Vulnerabilities.TLS_TICKETBLEED, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.error(
                f'\t\tTicketbleed (CVE-2016-9244): Unknown Response ({ep["details"]["ticketbleed"]})'
            )
    else:
        output.error("\t\tTicketbleed (CVE-2016-9244): Information Not Received")

    if "openSslCcs" in ep["details"]:
        if ep["details"]["openSslCcs"] == -1:
            output.error("\t\tOpenSSL CCS (CVE-2014-0224): Test Failed")
        elif ep["details"]["openSslCcs"] == 0:
            output.error("\t\tOpenSSL CCS (CVE-2014-0224): Test Failed (Unknown)")
        elif ep["details"]["openSslCcs"] == 1:
            output.norm("\t\tOpenSSL CCS (CVE-2014-0224): No")
        elif ep["details"]["openSslCcs"] == 2:
            reporter.display(
                "\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable - Not Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_OPENSSL_CVE_2014_0224_NE,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        elif ep["details"]["openSslCcs"] == 3:
            output.vuln("\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable")
            reporter.display(
                "\t\tOpenSSL CCS (CVE-2014-0224): Vulnerable",
                issue.Issue(
                    Vulnerabilities.TLS_OPENSSL_CVE_2014_0224,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.error(
                f'\t\tOpenSSL CCS (CVE-2014-0224): Unknown Response ({ep["details"]["openSslCcs"]})'
            )
    else:
        output.error("\t\tOpenSSL CCS (CVE-2014-0224): Information Not Received")

    if "openSSLLuckyMinus20" in ep["details"]:
        if ep["details"]["openSSLLuckyMinus20"] == -1:
            output.error("\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed")
        elif ep["details"]["openSSLLuckyMinus20"] == 0:
            output.error(
                "\t\tOpenSSL Padding Oracle (CVE-2016-2107): Test Failed (Unknown)"
            )
        elif ep["details"]["openSSLLuckyMinus20"] == 1:
            output.norm("\t\tOpenSSL Padding Oracle (CVE-2016-2107): No")
        elif ep["details"]["openSSLLuckyMinus20"] == 2:
            reporter.display(
                "\t\tOpenSSL Padding Oracle (CVE-2016-2107): Vulnerable",
                issue.Issue(
                    Vulnerabilities.TLS_OPENSSL_CVE_2016_2107,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.error(
                f"\t\tOpenSSL Padding Oracle (CVE-2016-2107): Unknown Response "
                f'({ep["details"]["openSSLLuckyMinus20"]})'
            )
    else:
        output.error(
            "\t\tOpenSSL Padding Oracle (CVE-2016-2107): Information Not Received"
        )

    if "bleichenbacher" in ep["details"]:
        if ep["details"]["bleichenbacher"] == -1:
            output.error("\t\tROBOT: Test Failed")
        elif ep["details"]["bleichenbacher"] == 0:
            output.error("\t\tROBOT: Test Failed (Unknown)")
        elif ep["details"]["bleichenbacher"] == 1:
            output.norm("\t\tROBOT: No")
        elif ep["details"]["bleichenbacher"] == 2:
            reporter.display(
                "\t\tROBOT: Vulnerable - Not Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_ROBOT_ORACLE_WEAK, url, {"ip": ep["ipAddress"]}
                ),
            )
        elif ep["details"]["bleichenbacher"] == 3:
            reporter.display(
                "\t\tROBOT: Vulnerable - Exploitable",
                issue.Issue(
                    Vulnerabilities.TLS_ROBOT_ORACLE_STRONG,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        elif ep["details"]["bleichenbacher"] == 4:
            output.norm("\t\tROBOT: Unknown - Inconsistent Results")
        else:
            output.error(
                f'\t\tROBOT: Unknown Response ({ep["details"]["bleichenbacher"]})'
            )
    else:
        output.error("\t\tROBOT: Information Not Received")

    if "forwardSecrecy" in ep["details"]:
        if ep["details"]["forwardSecrecy"] & (1 << 2) != 0:
            output.norm("\t\tForward Secrecy: Yes (all simulated clients)")
        elif ep["details"]["forwardSecrecy"] & (1 << 1) != 0:
            output.info("\t\tForward Secrecy: Yes (modern clients)")
        elif ep["details"]["forwardSecrecy"] & 1 != 0:
            reporter.display(
                "\t\tForward Secrecy: Yes (limited support)",
                issue.Issue(
                    Vulnerabilities.TLS_LIMITED_FORWARD_SECRECY,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.vuln("\t\tForward Secrecy: No")
    else:
        output.error("\t\tForward Secrecy: Information Not Received")

    if "supportsAead" in ep["details"]:
        if ep["details"]["supportsAead"]:
            output.norm("\t\tAEAD Cipher Suites Supported: Yes")
        else:
            reporter.display(
                "\t\tAEAD Cipher Suites Supported: No",
                issue.Issue(
                    Vulnerabilities.TLS_NO_AEAD_SUPPORT, url, {"ip": ep["ipAddress"]}
                ),
            )
    else:
        output.error("\t\tAEAD Cipher Suites Supported: Information Not Received")

    if "supportsCBC" in ep["details"]:
        if ep["details"]["supportsCBC"]:
            output.info("\t\tCBC Cipher Suites Supported: Yes")
        else:
            output.norm("\t\tCBC Cipher Suites Supported: No")
    else:
        output.error("\t\tCBC Cipher Suites Supported: Information Not Received")

    if "alpnProtocols" in ep["details"]:
        output.norm(f'\t\tALPN: {ep["details"]["alpnProtocols"]}')

    if "npnProtocols" in ep["details"]:
        output.norm(f'\t\tNPN: {ep["details"]["npnProtocols"]}')

    if "sessionResumption" in ep["details"]:
        if ep["details"]["sessionResumption"] == 0:
            output.norm("\t\tSession Resumption: Not Enabled / Empty Tickets")
        elif ep["details"]["sessionResumption"] == 1:
            output.norm("\t\tSession Resumption: Enabled / No Resumption")
        elif ep["details"]["sessionResumption"] == 2:
            reporter.display(
                "\t\tSession Resumption: Enabled",
                issue.Issue(
                    Vulnerabilities.TLS_SESSION_RESP_ENABLED,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.error(
                f'\t\tSession Resumption: Unknown Response ({ep["details"]["sessionResumption"]})'
            )
    else:
        output.error("\t\tSession Resumption: Information Not Received")

    if "ocspStapling" in ep["details"]:
        if ep["details"]["ocspStapling"]:
            output.norm("\t\tOCSP Stapling: Yes")
        else:
            reporter.display(
                "\t\tOCSP Stapling: No",
                issue.Issue(
                    Vulnerabilities.TLS_OCSP_STAPLE_MISSING,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
    else:
        output.error("\t\tOCSP Stapling: Information Not Received")

    if "miscIntolerance" in ep["details"]:
        if ep["details"]["miscIntolerance"] & 1 != 0:
            output.info("\t\tTLS Extension Intolerance: Yes")

        if ep["details"]["miscIntolerance"] & (1 << 1) != 0:
            output.warn("\t\tLong Handshake Intolerance: Yes")

        if ep["details"]["miscIntolerance"] & (1 << 2) != 0:
            output.warn("\t\tLong Handshake Intolerance: Workaround Success")

    if "protocolIntolerance" in ep["details"]:
        if ep["details"]["protocolIntolerance"] & 1 != 0:
            output.warn("\t\tProtocol Intolerance: TLS 1.0")

        if ep["details"]["protocolIntolerance"] & (1 << 1) != 0:
            output.warn("\t\tProtocol Intolerance: TLS 1.1")

        if ep["details"]["protocolIntolerance"] & (1 << 2) != 0:
            output.warn("\t\tProtocol Intolerance: TLS 1.2")

        if ep["details"]["protocolIntolerance"] & (1 << 3) != 0:
            output.warn("\t\tProtocol Intolerance: TLS 1.3")

        if ep["details"]["protocolIntolerance"] & (1 << 4) != 0:
            output.warn("\t\tProtocol Intolerance: TLS 1.152")

        if ep["details"]["protocolIntolerance"] & (1 << 5) != 0:
            output.warn("\t\tProtocol Intolerance: TLS 2.152")

    if "freak" in ep["details"]:
        if ep["details"]["freak"]:
            reporter.display(
                "\t\tFREAK: Vulnerable (512-bit key exchange supported)",
                issue.Issue(Vulnerabilities.TLS_FREAK, url, {"ip": ep["ipAddress"]}),
            )
        else:
            output.norm("\t\tFREAK: No")
    else:
        output.error("\t\tFREAK: Information Not Received")

    if "logjam" in ep["details"]:
        if ep["details"]["logjam"]:
            reporter.display(
                "\t\tLogjam: Vulnerable",
                issue.Issue(Vulnerabilities.TLS_LOGJAM, url, {"ip": ep["ipAddress"]}),
            )
        else:
            output.norm("\t\tLogjam: No")
    else:
        output.error("\t\tLogjam: Information Not Received")

    if "dhUsesKnownPrimes" in ep["details"]:
        if ep["details"]["dhUsesKnownPrimes"] == 0:
            output.norm("\t\tUses common DH primes: No")
        elif ep["details"]["dhUsesKnownPrimes"] == 1:
            output.warn("\t\tUses common DH primes: Yes (not weak)")
            reporter.display(
                "\t\tUses common DH primes: Yes (weak)",
                issue.Issue(
                    Vulnerabilities.TLS_DH_KNOWN_PRIMES_STRONG,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        elif ep["details"]["dhUsesKnownPrimes"] == 2:
            reporter.display(
                "\t\tUses common DH primes: Yes (weak)",
                issue.Issue(
                    Vulnerabilities.TLS_DH_KNOWN_PRIMES_WEAK,
                    url,
                    {"ip": ep["ipAddress"]},
                ),
            )
        else:
            output.error(
                f'\t\tUses common DH primes: Unknown Response ({ep["details"]["dhUsesKnownPrimes"]})'
            )

    if "dhYsReuse" in ep["details"]:
        if ep["details"]["dhYsReuse"]:
            reporter.display(
                "\t\tDH public server param (Ys) reuse: Yes",
                issue.Issue(
                    Vulnerabilities.TLS_DH_PARAM_REUSE, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.norm("\t\tDH public server param (Ys) reuse: No")

    if "ecdhParameterReuse" in ep["details"]:
        if ep["details"]["ecdhParameterReuse"]:
            reporter.display(
                "\t\tECDH Public Server Param Reuse: Yes",
                issue.Issue(
                    Vulnerabilities.TLS_ECDH_PARAM_REUSE, url, {"ip": ep["ipAddress"]}
                ),
            )
        else:
            output.norm("\t\tECDH Public Server Param Reuse: No")

    output.empty()
