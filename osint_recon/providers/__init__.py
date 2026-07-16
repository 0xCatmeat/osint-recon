from __future__ import annotations

from osint_recon.config import Config
from osint_recon.providers.abuseipdb import AbuseIPDBProvider
from osint_recon.providers.base import Provider
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

PROVIDER_CLASSES: list[type[Provider]] = [
    ShodanProvider,
    NetlasProvider,
    UrlscanProvider,
    VirusTotalProvider,
    AbuseIPDBProvider,
    EtherscanProvider,
    RdapProvider,
    CrtshProvider,
    SubfinderProvider,
    DnsxProvider,
    HttpxProvider,
    TlsxProvider,
    GauProvider,
]


def all_providers(config: Config) -> list[Provider]:
    return [cls(config) for cls in PROVIDER_CLASSES]
