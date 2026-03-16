"""Tests for F13B - NS Provider Identification."""

import pytest

from app.checker.ns_provider import identify_ns_provider


class TestIdentifyNsProvider:
    """F13B: NS Provider Identification from nameserver hostnames."""

    # ---- Exact pattern matches ----

    def test_cloudflare(self):
        result = identify_ns_provider(["art.ns.cloudflare.com", "beth.ns.cloudflare.com"])
        assert result["ns_provider"] == "Cloudflare"
        assert result["confidence"] == "exact"

    def test_aws_route53(self):
        result = identify_ns_provider([
            "ns-1234.awsdns-56.org",
            "ns-789.awsdns-01.co.uk",
        ])
        assert result["ns_provider"] == "AWS Route53"
        assert result["confidence"] == "exact"

    def test_google_cloud_dns(self):
        result = identify_ns_provider([
            "ns-cloud-a1.googledomains.com",
            "ns-cloud-b2.googledomains.com",
        ])
        assert result["ns_provider"] == "Google Cloud DNS"
        assert result["confidence"] == "exact"

    def test_azure_dns(self):
        result = identify_ns_provider([
            "ns1-01.azure-dns.com",
            "ns2-01.azure-dns.net",
        ])
        assert result["ns_provider"] == "Azure DNS"
        assert result["confidence"] == "exact"

    def test_godaddy(self):
        result = identify_ns_provider([
            "ns51.domaincontrol.com",
            "ns52.domaincontrol.com",
        ])
        assert result["ns_provider"] == "GoDaddy"
        assert result["confidence"] == "exact"

    def test_namecheap(self):
        result = identify_ns_provider([
            "dns1.registrar-servers.com",
            "dns2.registrar-servers.com",
        ])
        assert result["ns_provider"] == "Namecheap"
        assert result["confidence"] == "exact"

    def test_ovh(self):
        result = identify_ns_provider(["dns11.ovh.net", "ns11.ovh.net"])
        assert result["ns_provider"] == "OVH"
        assert result["confidence"] == "exact"

    def test_gandi(self):
        result = identify_ns_provider(["ns1.gandi.net", "ns2.gandi.net"])
        assert result["ns_provider"] == "Gandi"
        assert result["confidence"] == "exact"

    def test_ns1(self):
        result = identify_ns_provider(["dns1.p01.nsone.net", "dns2.p01.nsone.net"])
        assert result["ns_provider"] == "NS1"
        assert result["confidence"] == "exact"

    def test_hetzner(self):
        result = identify_ns_provider(["hydrogen.ns.hetzner.com", "helium.ns.hetzner.com"])
        assert result["ns_provider"] == "Hetzner"
        assert result["confidence"] == "exact"

    def test_digitalocean(self):
        result = identify_ns_provider(["ns1.digitalocean.com", "ns2.digitalocean.com"])
        assert result["ns_provider"] == "DigitalOcean"
        assert result["confidence"] == "exact"

    def test_netlify(self):
        result = identify_ns_provider(["dns1.p04.netlify.com", "dns2.p04.netlify.com"])
        assert result["ns_provider"] == "Netlify"
        assert result["confidence"] == "exact"

    def test_vercel(self):
        result = identify_ns_provider(["dns1.vercel-dns.com", "dns2.vercel-dns.com"])
        assert result["ns_provider"] == "Vercel"
        assert result["confidence"] == "exact"

    def test_squarespace(self):
        result = identify_ns_provider(["ns1.squarespace-dns.com", "ns2.squarespace-dns.com"])
        assert result["ns_provider"] == "Squarespace"
        assert result["confidence"] == "exact"

    def test_wix(self):
        result = identify_ns_provider(["ns1.wixdns.net", "ns2.wixdns.net"])
        assert result["ns_provider"] == "Wix"
        assert result["confidence"] == "exact"

    def test_rebel_ca(self):
        result = identify_ns_provider(["ns1.rebel.com", "ns2.rebel.com"])
        assert result["ns_provider"] == "Rebel.ca"
        assert result["confidence"] == "exact"

    def test_ionos(self):
        result = identify_ns_provider(["ns1.ui-dns.com", "ns2.ui-dns.org"])
        assert result["ns_provider"] == "IONOS"
        assert result["confidence"] == "exact"

    def test_porkbun(self):
        result = identify_ns_provider(["maceio.porkbun.com", "fortaleza.porkbun.com"])
        assert result["ns_provider"] == "Porkbun"
        assert result["confidence"] == "exact"

    # ---- Normalization ----

    def test_trailing_dot_stripped(self):
        result = identify_ns_provider(["art.ns.cloudflare.com.", "beth.ns.cloudflare.com."])
        assert result["ns_provider"] == "Cloudflare"

    def test_case_insensitive(self):
        result = identify_ns_provider(["ART.NS.CLOUDFLARE.COM", "BETH.NS.CLOUDFLARE.COM"])
        assert result["ns_provider"] == "Cloudflare"

    def test_hostnames_normalized_in_result(self):
        result = identify_ns_provider(["ART.NS.CLOUDFLARE.COM."])
        assert result["ns_hostnames"] == ["art.ns.cloudflare.com"]

    # ---- Majority vote ----

    def test_majority_wins(self):
        """When NS hostnames point to different providers, majority wins."""
        result = identify_ns_provider([
            "ns1.cloudflare.com",
            "ns2.cloudflare.com",
            "ns1.digitalocean.com",  # odd one out
        ])
        assert result["ns_provider"] == "Cloudflare"

    # ---- Inferred fallback ----

    def test_unknown_provider_inferred(self):
        result = identify_ns_provider(["ns1.unknownhost.org", "ns2.unknownhost.org"])
        assert result["ns_provider"] == "unknownhost.org"
        assert result["confidence"] == "inferred"

    # ---- Empty / None ----

    def test_empty_list(self):
        result = identify_ns_provider([])
        assert result["ns_provider"] is None
        assert result["ns_hostnames"] == []
        assert result["confidence"] is None

    def test_none_entries_filtered(self):
        result = identify_ns_provider(["", "  ", "ns1.cloudflare.com"])
        assert result["ns_provider"] == "Cloudflare"

    def test_all_empty_strings(self):
        result = identify_ns_provider(["", "  "])
        assert result["ns_provider"] is None

    # ---- Wild West / GoDaddy subsidiary ----

    def test_wild_west_domains(self):
        result = identify_ns_provider(["ns1.wildwestdomains.com", "ns2.wildwestdomains.com"])
        assert result["ns_provider"] == "Wild West Domains"
        assert result["confidence"] == "exact"
