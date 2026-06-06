from pathlib import Path

from osint_recon.config import Config
from osint_recon.providers.abuseipdb import AbuseIPDBProvider
from osint_recon.providers.crtsh import CrtshProvider
from osint_recon.providers.dnsx import DnsxProvider
from osint_recon.providers.etherscan import EtherscanProvider
from osint_recon.providers.gau import GauProvider
from osint_recon.providers.httpx import HttpxProvider
from osint_recon.providers.netlas import NetlasProvider
from osint_recon.providers.rdap import RdapProvider
from osint_recon.providers.shodan import ShodanProvider
from osint_recon.providers.subfinder import SubfinderProvider
from osint_recon.providers.tlsx import TlsxProvider
from osint_recon.providers.urlscan import UrlscanProvider
from osint_recon.providers.virustotal import VirusTotalProvider

CFG = Config(Path("/nonexistent"), {})


def test_rdap_parse_domain():
    raw = {
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "IANA"]],
                ],
            }
        ],
        "nameservers": [{"ldhName": "a.iana-servers.net"}],
        "status": ["active"],
    }
    texts = [f.finding for f in RdapProvider(CFG).parse(raw, "example.com", "domain")]
    assert any("registration" in t for t in texts)
    assert any("Registrar: IANA" in t for t in texts)
    assert any("Nameservers:" in t for t in texts)


def test_virustotal_parse_malicious_is_high_risk():
    raw = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}}
    findings = VirusTotalProvider(CFG).parse(raw, "1.2.3.4", "ip")
    assert findings[0].risk_level == "high"
    assert "malicious=3" in findings[0].finding


def test_abuseipdb_parse_score_risk():
    raw = {
        "data": {
            "abuseConfidenceScore": 75,
            "totalReports": 12,
            "isp": "Example",
            "countryCode": "US",
        }
    }
    findings = AbuseIPDBProvider(CFG).parse(raw, "1.2.3.4", "ip")
    assert findings[0].risk_level == "high"
    assert "score=75%" in findings[0].finding


def test_shodan_parse_ports_and_vulns():
    raw = {
        "ports": [443, 80],
        "org": "ACME",
        "hostnames": ["h.example.com"],
        "data": [{"port": 443, "transport": "tcp", "product": "nginx"}],
        "vulns": ["CVE-2021-1234"],
    }
    texts = [f.finding for f in ShodanProvider(CFG).parse(raw, "1.2.3.4", "ip")]
    assert any("Open ports: 80, 443" in t for t in texts)
    assert any("CVE-2021-1234" in t for t in texts)


def test_crtsh_parse_dedups_subdomains():
    raw = [
        {"name_value": "example.com\n*.example.com\nwww.example.com"},
        {"name_value": "www.example.com"},
    ]
    findings = CrtshProvider(CFG).parse(raw, "example.com", "domain")
    assert findings[0].selector == "ct_summary"
    assert "www.example.com" in [f.selector for f in findings[1:]]


def test_urlscan_parse_total():
    raw = {
        "total": 2,
        "results": [
            {
                "page": {"url": "https://example.com/"},
                "task": {"url": "https://submitted.example/"},
                "result": "u",
                "_id": "abc",
            }
        ],
    }
    provider = UrlscanProvider(CFG)
    findings = provider.parse(raw, "example.com", "domain")
    assert "2 existing urlscan result(s)" in findings[0].finding
    assert "Final page: https://example.com/" in findings[1].finding
    assert "submitted URL: https://submitted.example/" in findings[1].finding
    assert provider.source_url("example.com", "domain").endswith("q=page.domain%3Aexample.com")


def test_supports_respects_key_and_artifact_type():
    assert VirusTotalProvider(CFG).supports("domain") is False  # no key configured
    assert RdapProvider(CFG).supports("domain") is True  # keyless
    assert RdapProvider(CFG).supports("hash") is False  # unsupported type


def test_etherscan_parse_balance():
    raw = {
        "balance": {"status": "1", "message": "OK", "result": "1500000000000000000"},
        "transactions": {"status": "0", "message": "No transactions found", "result": []},
    }
    addr = "0x0000000000000000000000000000000000000000"
    findings = EtherscanProvider(CFG).parse(raw, addr, "evm_address")
    assert len(findings) == 1
    assert findings[0].finding == "Balance: 1.5 ETH"
    assert findings[0].selector == "balance"
    assert findings[0].confidence == "high"


def test_etherscan_parse_empty():
    findings = EtherscanProvider(CFG).parse(
        {}, "0x0000000000000000000000000000000000000000", "evm_address"
    )
    assert findings == []


def test_netlas_parse_ip():
    """Netlas host response yields host summary, ports, service detail, and tags."""
    raw = {
        "ip": "1.2.3.4",
        "hostname": "vps.example.com",
        "isp": "Example ISP",
        "asn": {"asn": 12345, "name": "Example AS"},
        "geo": {"country": "US"},
        "ports": [22, 80, 443],
        "data": [
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"},
            {"port": 80, "transport": "tcp", "product": "Apache httpd"},
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9"},
        ],
        "hostnames": ["www.example.com", "mail.example.com"],
        "tags": ["cdn", "cloud", "web"],
        "last_updated": "2024-01-15T12:00:00Z",
    }
    provider = NetlasProvider(CFG)
    findings = provider.parse(raw, "1.2.3.4", "ip")

    assert len(findings) >= 4
    texts = [f.finding for f in findings]
    selectors = [f.selector for f in findings]

    assert any("IP: 1.2.3.4" in t for t in texts)
    assert any("hostname: vps.example.com" in t for t in texts)
    assert any("ISP: Example ISP" in t for t in texts)
    assert any("AS12345" in t for t in texts)

    assert any("Open ports: 22, 80, 443" in t for t in texts)

    assert any("tcp/443 nginx 1.18.0" in t for t in texts)

    assert "hostnames" in selectors

    assert "tags" in selectors
    assert any("cdn" in t for t in texts)

    assert "last_seen" in selectors


def test_netlas_parse_empty():
    """Empty dict returns [] for both ip and domain artifact types."""
    provider = NetlasProvider(CFG)
    assert provider.parse({}, "1.2.3.4", "ip") == []
    assert provider.parse({}, "example.com", "domain") == []


def test_subfinder_parse():
    raw = [
        {"host": "mail.example.com", "source": "crtsh"},
        {"host": "www.example.com", "source": "hackertarget"},
        {"host": "api.example.com", "source": "alienvault"},
    ]
    findings = SubfinderProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 4
    assert findings[0].selector == "subfinder_summary"
    assert findings[0].confidence == "high"
    assert "3 subdomain(s)" in findings[0].finding
    selectors = [f.selector for f in findings[1:]]
    assert "mail.example.com" in selectors
    assert "www.example.com" in selectors
    assert "api.example.com" in selectors
    texts = [f.finding for f in findings]
    assert any("Subdomain (via crtsh): mail.example.com" in t for t in texts)


def test_subfinder_parse_dedup():
    """Duplicate hosts across sources are merged."""
    raw = [
        {"host": "www.example.com", "source": "crtsh"},
        {"host": "www.example.com", "source": "hackertarget"},
    ]
    findings = SubfinderProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 2  # summary + 1 unique subdomain
    assert findings[0].selector == "subfinder_summary"
    assert "1 subdomain(s)" in findings[0].finding


def test_subfinder_parse_empty():
    findings = SubfinderProvider(CFG).parse([], "example.com", "domain")
    assert findings == []


def test_subfinder_parse_not_list():
    findings = SubfinderProvider(CFG).parse({"error": "nope"}, "example.com", "domain")
    assert findings == []


def test_dnsx_parse():
    raw = [
        {
            "host": "example.com",
            "resolver": ["1.1.1.1:53"],
            "a": ["93.184.216.34"],
            "cname": ["www.example.com"],
            "mx": ["mail.example.com"],
            "ns": ["ns1.example.com", "ns2.example.com"],
            "txt": ["v=spf1 include:_spf.example.com ~all"],
        }
    ]
    findings = DnsxProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 7
    assert findings[0].selector == "dnsx_summary"
    assert findings[0].confidence == "high"
    assert "6 DNS record(s)" in findings[0].finding

    texts = [f.finding for f in findings]
    selectors = [f.selector for f in findings]
    assert any("A: example.com -> 93.184.216.34" in t for t in texts)
    assert "a" in selectors
    assert any("CNAME: example.com -> www.example.com" in t for t in texts)
    assert "cname" in selectors
    assert any("MX: example.com -> mail.example.com" in t for t in texts)
    assert "mx" in selectors
    assert any("NS: example.com -> ns1.example.com" in t for t in texts)
    assert any("NS: example.com -> ns2.example.com" in t for t in texts)
    assert "ns" in selectors
    assert any("TXT: example.com -> v=spf1 include:_spf.example.com ~all" in t for t in texts)
    assert "txt" in selectors


def test_dnsx_parse_aaaa():
    """AAAA (IPv6) records are parsed."""
    raw = [
        {
            "host": "example.com",
            "resolver": ["1.1.1.1:53"],
            "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
        }
    ]
    findings = DnsxProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 2  # summary + AAAA
    assert "AAAA: example.com -> 2606:2800:220:1:248:1893:25c8:1946" in findings[1].finding


def test_dnsx_parse_long_txt():
    """TXT records over 120 chars are truncated in the display."""
    long_txt = "a" * 200
    raw = [
        {
            "host": "example.com",
            "resolver": ["1.1.1.1:53"],
            "txt": [long_txt],
        }
    ]
    findings = DnsxProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 2
    assert "..." in findings[1].finding
    assert len(findings[1].finding) < 150  # truncated


def test_dnsx_parse_empty():
    findings = DnsxProvider(CFG).parse([], "example.com", "domain")
    assert findings == []


def test_dnsx_parse_not_list():
    findings = DnsxProvider(CFG).parse({"error": "nope"}, "example.com", "domain")
    assert findings == []


def test_httpx_parse():
    """JSONL with 2 HTTP responses (one with tech, one without)."""
    raw = [
        {
            "url": "https://example.com",
            "host": "example.com",
            "status_code": 200,
            "title": "Example Domain",
            "tech": ["nginx", "jquery"],
            "cdn": "cloudflare",
        },
        {
            "url": "https://mail.example.com",
            "host": "mail.example.com",
            "status_code": 301,
            "title": "",
            "tech": [],
            "cdn": "",
        },
    ]
    findings = HttpxProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 3
    assert findings[0].selector == "httpx_summary"
    assert findings[0].confidence == "high"
    assert "2 probed, 2 live" in findings[0].finding
    texts = [f.finding for f in findings]
    assert any("https://example.com [200] Example Domain" in t for t in texts)
    assert any("tech: nginx, jquery" in t for t in texts)
    assert any("CDN: cloudflare" in t for t in texts)
    assert any("https://mail.example.com [301]" in t for t in texts)
    selectors = [f.selector for f in findings[1:]]
    assert "https://example.com" in selectors
    assert "https://mail.example.com" in selectors


def test_httpx_parse_empty():
    """Empty response returns []."""
    findings = HttpxProvider(CFG).parse([], "example.com", "domain")
    assert findings == []

    findings = HttpxProvider(CFG).parse({}, "example.com", "domain")
    assert findings == []


def test_httpx_parse_jsonl_string():
    """parse handles a list of dicts (as produced by fetch() after JSONL conversion)."""
    raw = [
        {
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example",
            "tech": ["nginx"],
            "cdn": "",
        },
        {
            "url": "https://www.example.com",
            "status_code": 200,
            "title": "WWW",
            "tech": [],
            "cdn": "cloudflare",
        },
    ]
    findings = HttpxProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 3  # summary + 2 entries
    assert "2 probed, 2 live" in findings[0].finding
    assert any("cloudflare" in f.finding for f in findings)
    assert any("Example" in f.finding for f in findings)


def test_tlsx_parse():
    """TLS JSON with SANs and cert dates."""
    raw = {
        "host": "example.com",
        "port": "443",
        "subject_cn": "*.example.com",
        "subject_an": ["example.com", "api.example.com", "www.example.com"],
        "issuer_cn": "Cloudflare Inc ECC CA-3",
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2026-01-01T00:00:00Z",
        "expired": False,
    }
    findings = TlsxProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) == 5

    texts = [f.finding for f in findings]
    selectors = [f.selector for f in findings]

    assert any("CN=*.example.com" in t for t in texts)
    assert any("issuer=Cloudflare Inc ECC CA-3" in t for t in texts)
    assert any("expires=2026-01-01T00:00:00Z" in t for t in texts)

    assert any("TLS SAN: api.example.com" in t for t in texts)
    assert any("TLS SAN: www.example.com" in t for t in texts)

    assert "cert_lifetime" in selectors
    assert any("Cert valid: 2025-01-01T00:00:00Z to 2026-01-01T00:00:00Z" in t for t in texts)


def test_tlsx_parse_expired():
    """Expired cert yields high risk."""
    raw = {
        "host": "old.example.com",
        "port": "443",
        "subject_cn": "old.example.com",
        "subject_an": ["old.example.com"],
        "issuer_cn": "Let's Encrypt",
        "not_before": "2023-01-01T00:00:00Z",
        "not_after": "2024-01-01T00:00:00Z",
        "expired": True,
    }
    findings = TlsxProvider(CFG).parse(raw, "old.example.com", "domain")
    assert len(findings) >= 1
    assert findings[0].risk_level == "high"
    assert "EXPIRED" in findings[0].finding


def test_tlsx_parse_empty():
    """Empty response returns []."""
    findings = TlsxProvider(CFG).parse({}, "example.com", "domain")
    assert findings == []

    findings = TlsxProvider(CFG).parse({"error": "timeout"}, "example.com", "domain")
    assert findings == []


def test_gau_parse():
    """Historical URLs are emitted as findings."""
    raw = {
        "urls": [
            "https://example.com/admin",
            "https://dev.example.com/.env",
            "https://example.com/login",
        ],
        "total": 3,
    }
    findings = GauProvider(CFG).parse(raw, "example.com", "domain")
    assert len(findings) >= 2  # summary + at least 1 URL
    assert findings[0].selector == "gau_summary"
    assert "3 historical URL" in findings[0].finding
    urls = [f.finding for f in findings[1:]]
    assert any("admin" in u for u in urls)


def test_gau_parse_empty():
    """Empty response returns []."""
    assert GauProvider(CFG).parse({}, "example.com", "domain") == []
    assert GauProvider(CFG).parse({"urls": [], "total": 0}, "example.com", "domain") == []


def test_shodan_search_parse():
    """Shodan search results produce summary + per-match findings."""
    from osint_recon.providers.shodan import ShodanProvider as SP

    raw = {
        "total": 1500,
        "matches": [
            {
                "ip_str": "1.2.3.4",
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "org": "Example Corp",
                "hostnames": ["www.example.com"],
            },
            {
                "ip_str": "5.6.7.8",
                "port": 80,
                "transport": "tcp",
                "product": "Apache",
                "org": "Another Corp",
                "hostnames": [],
            },
        ],
    }
    provider = SP(CFG)
    findings = provider._parse_search(raw, 'org:"Example Corp"')
    assert len(findings) == 3  # summary + 2 matches
    assert findings[0].selector == "search_summary"
    assert "1500 total" in findings[0].finding
    assert "1.2.3.4:443/tcp" in findings[1].finding
    assert "nginx" in findings[1].finding
    assert "5.6.7.8:80/tcp" in findings[2].finding


def test_shodan_search_parse_empty():
    """Empty search results return []."""
    from osint_recon.providers.shodan import ShodanProvider as SP

    assert SP(CFG)._parse_search({}, 'org:"nobody"') == []
    assert SP(CFG)._parse_search({"total": 0, "matches": []}, 'org:"nobody"') == []
