from .schema import event
from .common import APIError


class MockAI:
    """Deterministic contract test double. This is NOT a trained ML model."""
    def predict(self, raw):
        e = event(raw)
        f = e["features"]
        if any(x is None for x in f.values()):
            raise APIError(422, "Mock AI needs explicit observed or synthetic counters")
        score = round(min(0.99, max(0.10, f["failed_logins_60s"] / 20,
                                  f["unique_dst_ports_60s"] / 50)), 4)
        return {"event_id": e["event_id"], "anomaly_score": score,
                "score_semantics": "higher_is_more_anomalous_0_1",
                "model_version": "mock-deterministic-v1", "is_mock": True}
