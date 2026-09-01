"""iptables-based killswitch: only allow loopback + Tor's SOCKS/control ports out.
Requires sudo. Linux only. Review the rules before relying on this."""
import subprocess

RULES_ON = [
    ["iptables", "-F", "OUTPUT"],
    ["iptables", "-P", "OUTPUT", "DROP"],
    ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "9050", "-j", "ACCEPT"],
    ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "9051", "-j", "ACCEPT"],
]

RULES_OFF = [
    ["iptables", "-F", "OUTPUT"],
    ["iptables", "-P", "OUTPUT", "ACCEPT"],
]


def enable():
    for rule in RULES_ON:
        subprocess.run(rule, check=True)


def disable():
    for rule in RULES_OFF:
        subprocess.run(rule, check=True)
