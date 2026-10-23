"""Firewall mitigation helpers used by the edge NIDS runtime.

The implementation is intentionally lightweight so it can be exercised in
unit tests without requiring a real iptables installation.
"""

import ipaddress
import random
import shlex
import subprocess
from collections.abc import Iterable


class ActiveMitigationEngine:
    """Track and apply IP blocking actions for the firewall."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.blocked_ips = set()

    @staticmethod
    def _normalize_ip(ip_address: str) -> str:
        """Return a canonical IP string or raise ValueError for invalid input."""
        if not isinstance(ip_address, str):
            raise ValueError("ip_address must be a string")

        value = ip_address.strip()
        ipaddress.ip_address(value)
        return value

    def block_ip(self, ip_address: str) -> bool:
        """Block an IP address and record it as blocked."""
        try:
            normalized_ip = self._normalize_ip(ip_address)
        except ValueError:
            return False

        if normalized_ip in self.blocked_ips:
            return True

        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", normalized_ip, "-j", "DROP"]
        command_string = " ".join(shlex.quote(part) for part in cmd)

        if self.dry_run:
            print(f"[DRY-RUN] Executed command: {command_string}")
        else:
            subprocess.run(cmd, check=True)

        self.blocked_ips.add(normalized_ip)
        return True

    def block_ips(self, ip_addresses: Iterable[str]) -> list[str]:
        """Block multiple IPs and return the subset that was accepted for blocking."""
        blocked = []
        for ip_address in ip_addresses:
            if ip_address is None:
                continue
            try:
                normalized = self._normalize_ip(ip_address)
            except ValueError:
                continue
            if self.block_ip(normalized):
                blocked.append(normalized)
        return blocked

    @staticmethod
    def extract_ips(signature_matches: Iterable[dict]) -> list[str]:
        """Return all src/dst IPs from signature matches without duplicates."""
        candidate_ips = []
        seen = set()
        for match in signature_matches:
            if not isinstance(match, dict):
                continue
            for key in ("src_ip", "dst_ip"):
                ip_value = match.get(key)
                if not ip_value:
                    continue
                ip_text = str(ip_value)
                if ip_text not in seen:
                    seen.add(ip_text)
                    candidate_ips.append(ip_text)
        return candidate_ips

    def block_signature_ips(self, signature_matches: Iterable[dict]) -> list[str]:
        """Extract suspicious src/dst IPs from signature matches and block them."""
        return self.block_ips(self.extract_ips(signature_matches))

    def auto_block_packets(self, packets: Iterable[dict], signature_engine) -> list[str]:
        """Inspect packets and block unique source IPs only when signatures match."""
        if not callable(getattr(signature_engine, "inspect_all", None)):
            raise TypeError("signature_engine must provide an inspect_all(packet) method")

        suspicious_sources = []
        for packet in packets:
            if not isinstance(packet, dict):
                continue
            matches = signature_engine.inspect_all(packet)
            if not matches:
                continue
            source_ip = packet.get("src_ip")
            if source_ip:
                suspicious_sources.append(str(source_ip))
        return self.block_ips(dict.fromkeys(suspicious_sources))

    def auto_block_packet(self, packet: dict, signature_engine) -> list[str]:
        """Inspect one packet and block its source only if a signature matches."""
        return self.auto_block_packets((packet,), signature_engine)

    def auto_block_matches(self, packet: dict, signature_engine) -> list[str]:
        """Compatibility alias for signature-driven blocking of one packet."""
        return self.auto_block_packet(packet, signature_engine)


def run_demo() -> list[str]:
    """Print ten randomly selected example IPs and simulate blocking them."""
    from signature_engine import SignatureDetectionEngine

    rng = random.SystemRandom()
    example_networks = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    example_ips = [
        str(address)
        for network in example_networks
        for address in ipaddress.ip_network(network).hosts()
    ]
    selected_ips = rng.sample(example_ips, 10)
    packets = [
        {
            "protocol": "tcp",
            "src_port": 23,
            "src_ip": ip_address,
            "dst_ip": "198.51.100.20",
        }
        for ip_address in selected_ips
    ]
    mitigator = ActiveMitigationEngine(dry_run=True)
    blocked_ips = mitigator.auto_block_packets(packets, SignatureDetectionEngine())

    print(f"Blocked IPs ({len(blocked_ips)}):")
    for ip_address in blocked_ips:
        print(ip_address)
    return blocked_ips


if __name__ == '__main__':
    run_demo()
