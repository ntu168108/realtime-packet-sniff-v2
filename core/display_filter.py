"""
Display filter (post-decode, not BPF). Pure stdlib.
"""
import re


class DisplayFilter:
    """
    Simple Wireshark-style display filter (post-decode, not BPF).
    Grammar:  expr  := term ( "and" term | "or" term | "not" term )*
               term := "src" "host" IP | "dst" "host" IP | "host" IP
                    |  "port" N | "src" "port" N | "dst" "port" N
                    |  "tcp" | "udp" | "icmp" | "ipv6" | "arp"
                    |  "(" expr ")"
    """

    def __init__(self, expr: str):
        self.tokens = self._tokenize(expr.lower())
        self.pos = 0
        self._d = None  # set per match()

    @staticmethod
    def _tokenize(expr: str):
        # Split on whitespace, keep parens as their own tokens
        return re.findall(r"\([^()]*\)|[^\s()]+", expr)

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _eat(self):
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def match(self, decoded) -> bool:
        # Reset parser state per match so a filter is reusable
        self.pos = 0
        self._d = decoded
        try:
            return self._parse_or()
        except Exception:
            return True  # fail-open on parse error

    def _parse_or(self):
        left = self._parse_and()
        while self._peek() == "or":
            self._eat()
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self):
        left = self._parse_not()
        while self._peek() == "and":
            self._eat()
            right = self._parse_not()
            left = left and right
        return left

    def _parse_not(self):
        if self._peek() == "not":
            self._eat()
            return not self._parse_atom()
        return self._parse_atom()

    def _parse_atom(self):
        t = self._peek()
        if t == "(":
            self._eat()
            v = self._parse_or()
            if self._peek() == ")":
                self._eat()
            return v
        if t is None:
            return True
        self._eat()
        nxt = self._peek()
        if t in ("src", "dst") and nxt == "host":
            self._eat()
            ip = self._eat()
            if t == "src":
                return self._d.src_addr == ip
            return self._d.dst_addr == ip
        if t == "host":
            ip = self._eat()
            return self._d.src_addr == ip or self._d.dst_addr == ip
        if t in ("src", "dst") and nxt == "port":
            self._eat()
            port = int(self._eat())
            if t == "src":
                return self._d.src_port == port
            return self._d.dst_port == port
        if t == "port":
            port = int(self._eat())
            return self._d.src_port == port or self._d.dst_port == port
        if t in ("tcp", "udp", "icmp", "icmpv6", "arp", "igmp",
                 "ipv4", "ipv6", "dns", "http", "tls", "quic",
                 "dhcp", "ntp"):
            proto = (self._d.protocol_name or "").lower()
            return proto == t or proto.split("/")[0] == t
        return True
