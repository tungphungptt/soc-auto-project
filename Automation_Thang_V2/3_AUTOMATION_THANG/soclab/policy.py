import ipaddress
from .common import APIError, ip, number


class Policy:
    def __init__(self, data):
        self.data = data
        self.protected = [ipaddress.ip_network(x) for x in data["protected_networks"]]
        self.targets = [ipaddress.ip_network(x) for x in data["auto_block_source_networks"]]
        if not self.protected or not self.targets:
            raise ValueError("Protected and auto-block scope must be explicitly configured")
        self.ttl = number(data["block_ttl_seconds"], "TTL", 1, 3600, True)
        self.ai_weight = number(data["ai_weight"], "ai_weight", 0, 1)
        self.alert_threshold = number(data["alert_threshold"], "alert_threshold", 0, 100)
        self.block_threshold = number(data["block_threshold"], "block_threshold", 0, 100)
        self.ai_threshold = number(data["min_ai_score_to_block"], "AI threshold", 0, 1)
        self.min_severity = number(data["min_severity_to_block"], "severity", 0, 15, True)
        if self.alert_threshold >= self.block_threshold:
            raise ValueError("alert_threshold must be below block_threshold")
        number(data["max_event_age_seconds"], "event age", 1, 86400, True)
        number(data["max_future_skew_seconds"], "clock skew", 0, 300, True)
        number(data["max_active_blocks"], "block limit", 1, 10000, True)

    def guard(self, value):
        addr = ipaddress.ip_address(ip(value))
        # These can never be action targets, regardless of the allowlist.
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return "special_address"
        if addr == ipaddress.ip_address("255.255.255.255"):
            return "broadcast_address"
        if any(addr in net for net in self.protected):
            return "protected_ip"
        for net in self.targets:
            if addr in net:
                if net.version == 4 and net.prefixlen <= 30 and addr in (net.network_address, net.broadcast_address):
                    return "network_or_broadcast_address"
                return None
        return "outside_enforcement_scope"

    def decide(self, event, score):
        number(score, "anomaly_score", 0, 1)
        risk = 100 * (self.ai_weight * score + (1-self.ai_weight) * event["severity"] / 15)
        base = {"risk_score": round(risk, 2), "anomaly_score": score,
                "policy_version": self.data["version"], "src_ip": event["src_ip"]}
        guard = self.guard(event["src_ip"])
        # Safety checks run even if the event is otherwise low risk.
        if guard:
            return dict(base, decision="REVIEW" if risk >= self.alert_threshold else "OBSERVE", reason=guard)
        if (risk >= self.block_threshold and score >= self.ai_threshold
                and event["severity"] >= self.min_severity
                and event["event_type"] in self.data["auto_block_event_types"]):
            return dict(base, decision="BLOCK", reason="combined_thresholds_met")
        return dict(base, decision="REVIEW" if risk >= self.alert_threshold else "OBSERVE",
                    reason="insufficient_block_evidence")
