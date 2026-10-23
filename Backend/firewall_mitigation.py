"""Firewall mitigation helpers used by the edge NIDS runtime.

The implementation is intentionally lightweight so it can be exercised in
unit tests without requiring a real iptables installation.
"""

import ipaddress
import shlex
import subprocess
from collections.abc import Iterable


class ActiveMitigationEngine:
    """Track and apply IP blocking actions for the firewall."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.blocked_ips = set()

    def auto_block_packet(self, packet: dict) -> list[str]:
        """Automatically block any IPs present on a suspicious packet."""
        if not isinstance(packet, dict):
            return []
        candidate_ips = []
        for key in ("src_ip", "dst_ip"):
            value = packet.get(key)
            if value:
                candidate_ips.append(str(value))
        return self.block_ips(candidate_ips)

    def auto_block_matches(self, packet: dict, signature_engine=None) -> list[str]:
        """Use a signature engine to decide which IPs should be blocked."""
        if not isinstance(packet, dict):
            return []

        if signature_engine is not None and hasattr(signature_engine, "inspect_all"):
            matches = signature_engine.inspect_all(packet)
            if matches:
                blocked = self.block_signature_ips(matches)
                if blocked:
                    return blocked

        return self.auto_block_packet(packet)

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

    def auto_block_packet(self, packet: dict) -> list[str]:
        """Automatically block any source/destination IPs found in a packet alert payload."""
        if not isinstance(packet, dict):
            return []
        candidate_ips = []
        for key in ("src_ip", "dst_ip"):
            value = packet.get(key)
            if value:
                candidate_ips.append(str(value))
        return self.block_ips(candidate_ips)


if __name__ == '__main__':
    mitigator = ActiveMitigationEngine(dry_run=True)
    mitigator.block_ips(["192.168.1.105", "10.0.0.7", "203.0.113.42"])
