"""Firewall mitigation helpers used by the edge NIDS runtime.

The implementation is intentionally lightweight so it can be exercised in
unit tests without requiring a real iptables installation.
"""

import subprocess


class ActiveMitigationEngine:  # pylint: disable=too-few-public-methods
    """Track and apply IP blocking actions for the firewall."""

    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.blocked_ips = set()

    def block_ip(self, ip_address: str) -> bool:
        """Block an IP address and record it as blocked."""
        if ip_address in self.blocked_ips:
            return True

        cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        if self.dry_run:
            print(f"[DRY-RUN] Executed command: {cmd}")
        else:
            subprocess.run(cmd, shell=True, check=True)

        self.blocked_ips.add(ip_address)
        return True

if __name__ == '__main__':
    mitigator = ActiveMitigationEngine(dry_run=True)
    mitigator.block_ip("192.168.1.105")
