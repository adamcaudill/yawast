#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import ipaddress
import socket
from typing import Tuple

from publicsuffixlist import PublicSuffixList

from yawast.external.spinner import Spinner
from yawast.reporting import reporter, issue
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.dns import basic
from yawast.scanner.plugins.dns import caa
from yawast.scanner.plugins.dns import dnssec
from yawast.scanner.plugins.dns import network_info
from yawast.scanner.plugins.dns import srv
from yawast.scanner.plugins.dns import subdomains
from yawast.scanner.session import Session
from yawast.shared import utils, output


def scan(session: Session):
    reporter.register_data("url", session.url)
    reporter.register_data("domain", session.domain)

    # check to see if this is an IP, if so, bail out
    if utils.is_ip(session.domain):
        return

    output.empty()
    output.norm("DNS Information:")

    # get the root domain, by looking up via the PSL
    psl = PublicSuffixList()
    root_domain = psl.privatesuffix(session.domain)
    reporter.register_data("root_domain", root_domain)

    # IP Addresses for the domain we are scanning
    ips = basic.get_ips(session.domain)
    reporter.register_data("ip", ips)
    for ip in ips:
        output.norm("\t%s (%s)" % (ip, basic.get_host(str(ip))))

        addr = ipaddress.ip_address(str(ip))

        if not addr.is_private:
            ni = network_info.network_info(str(ip))
            output.norm("\t\t%s" % ni)

            if addr.version == 4:
                output.norm("\t\thttps://www.shodan.io/host/%s" % ip)
                output.norm("\t\thttps://censys.io/ipv4/%s" % ip)
            else:
                output.norm("\t\thttps://www.shodan.io/host/%s" % str(ip).lower())

        output.empty()

    # TXT records for the domain we are scanning
    try:
        txt = basic.get_text(session.domain)
        reporter.register_data("dns_txt", {session.domain: txt})
        for rec in txt:
            output.norm("\tTXT: %s" % rec)
    except Exception as err:
        output.error(f"Error getting TXT records: {str(err)}")

    # TXT records for the root domain
    try:
        if root_domain != session.domain:
            txt = basic.get_text(root_domain)
            reporter.register_data("dns_txt", {root_domain: txt})
            for rec in txt:
                output.norm("\tTXT (%s): %s" % (root_domain, rec))
    except Exception as err:
        output.error(f"Error getting TXT (root) records: {str(err)}")

    output.empty()

    # MX records for the domain we are scanning
    try:
        mx = basic.get_mx(session.domain)
        reporter.register_data("dns_mx", {session.domain: mx})
        for rec in mx:
            server_ip, ni = _get_ip_info(rec[0])

            info = "%s (%s) - %s (%s)" % (rec[0], rec[1], server_ip, ni)
            output.norm("\tMX: %s" % info)
    except Exception as err:
        output.error(f"Error getting MX records: {str(err)}")

    try:
        # MX records for the root domain
        if root_domain != session.domain:
            mx = basic.get_mx(root_domain)
            reporter.register_data("dns_mx", {root_domain: mx})
            for rec in mx:
                server_ip, ni = _get_ip_info(rec[0])

                info = "%s (%s) - %s (%s)" % (rec[0], rec[1], server_ip, ni)
                output.norm("\tMX (%s): %s" % (root_domain, info))
    except Exception as err:
        output.error(f"Error getting MX (root) records: {str(err)}")

    output.empty()

    # NS records for the root domain
    try:
        ns = basic.get_ns(root_domain)
        reporter.register_data("dns_ns", {root_domain: ns})
        for rec in ns:
            server_ip, ni = _get_ip_info(rec)

            info = "%s - %s (%s)" % (rec, server_ip, ni)
            output.norm("\tNS: %s" % info)
    except Exception as err:
        output.error(f"Error getting NS records: {str(err)}")

    output.empty()

    if session.args.srv:
        try:
            output.norm("Searching for SRV records, this will take a minute...")
            output.empty()

            with Spinner():
                srv_records = srv.find_srv_records(root_domain)
                reporter.register_data("dns_srv", srv_records)

            for rec in srv_records:
                server_ip, ni = _get_ip_info(rec[1])

                info = "%s: %s:%s - %s (%s)" % (rec[0], rec[1], rec[2], server_ip, ni)
                output.norm("\tSRV: %s" % info)

                output.empty()
        except Exception as err:
            output.error(f"Error getting SRV records: {str(err)}")

    if session.args.subdomains:
        try:
            output.norm("Searching for sub-domains, this will take a few minutes...")
            output.empty()

            with Spinner():
                sds = subdomains.find_subdomains(root_domain)
                reporter.register_data("dns_subdomains", sds)

            for rec in sds:
                info = ""

                if rec[0] == "CNAME":
                    server_ip, ni = _get_ip_info(rec[2])

                    info = "(CNAME) %s -> %s - %s (%s)" % (
                        rec[1],
                        rec[2],
                        server_ip,
                        ni,
                    )
                elif rec[0] == "A":
                    ni = network_info.network_info(rec[2])
                    info = "(A) %s: %s (%s)" % (rec[1], rec[2], ni)
                elif rec[0] == "AAAA":
                    ni = network_info.network_info(rec[2])
                    info = "(AAAA) %s: %s (%s)" % (rec[1], rec[2], ni)

                output.norm("\tSubdomain: %s" % info)
        except Exception as err:
            output.error(f"Error getting subdomain records: {str(err)}")

        output.empty()

    try:
        caa_count = 0
        carec = caa.get_caa(session.domain)
        reporter.register_data("dns_caa", carec)
        for rec in carec:
            curr = rec[0]

            if rec[1] == "CNAME":
                output.norm("\tCAA (%s): CNAME Found: -> %s" % (curr, rec[2]))
            elif rec[1] == "CAA":
                if len(rec[2]) > 0:
                    for line in rec[2]:
                        output.norm('\tCAA (%s): "%s"' % (curr, line))
                        caa_count += 1
                else:
                    output.norm("\tCAA (%s): No Records Found" % curr)

        # notify the user if there's an issue
        if caa_count == 0:
            reporter.display(
                "\tCAA: Domain does not have protection from CAA",
                issue.Issue(
                    Vulnerabilities.DNS_CAA_MISSING, session.url, {"caa_records": carec}
                ),
            )
    except Exception as err:
        output.error(f"Error getting CAA records: {str(err)}")

    output.empty()

    try:
        dk = dnssec.get_dnskey(session.domain)
        reporter.register_data("dns_dnskey", dk)
        if len(dk) > 0:
            for rec in dk:
                output.norm(
                    "\tDNSKEY: Algorithm: '%s' - Flags: '%s' - Key Length: %s"
                    % (rec[2], rec[0], len(rec[3]) * 8)
                )
        else:
            reporter.display(
                "\tDNSKEY: Domain does not use DNSSEC",
                issue.Issue(Vulnerabilities.DNS_DNSSEC_NOT_ENABLED, session.url, {}),
            )
    except Exception as err:
        output.error(f"Error getting DNSKEY records: {str(err)}")

    output.empty()


def _get_ip_info(ip: str) -> Tuple[str, str]:
    try:
        server_ip = socket.gethostbyname(ip)
        ni = network_info.network_info(str(server_ip))
    except Exception:
        server_ip = "(Unavailable)"
        ni = "(Unavailable)"

        output.debug_exception()

    return server_ip, ni
