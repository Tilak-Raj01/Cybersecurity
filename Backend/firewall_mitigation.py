"""Firewall mitigation helpers used by the edge NIDS runtime.

The implementation is intentionally lightweight so it can be exercised in
unit tests without requiring a real iptables installation.
"""

import ipaddress
import shlex
import subprocess


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


if __name__ == '__main__':
    mitigator = ActiveMitigationEngine(dry_run=True)
    mitigator.block_ip("192.168.1.105")
