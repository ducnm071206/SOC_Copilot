import pytest
from soc_copilot import config
from soc_copilot.retrieval import retrieve, RetrievalError

DOCS = {i: {"id": i, "document": f"doc {i}", "metadata": {}}
        for i in ("sop_general", "sop_ssh", "sop_web")}


class FakeStore:
    def __init__(self, hits): self.hits = hits
    def query(self, text, n_results=3): return self.hits[:n_results]
    def get_sop(self, i): return DOCS.get(i)
    def all_sops(self): return list(DOCS.values())


ALERT = {"rule": {"id": "5710", "level": 5, "description": "ssh failed"}}
HITS = [{"id": "sop_ssh", "distance": 0.20}, {"id": "sop_web", "distance": 0.50},
        {"id": "sop_general", "distance": 0.60}]


def test_rag_top1_under_threshold():
    r = retrieve(ALERT, FakeStore(HITS), "rag", threshold=0.45)
    assert r.sop_id == "sop_ssh" and not r.used_fallback
    assert round(r.margin, 2) == 0.30 and len(r.alternatives) == 2


def test_rag_over_threshold_falls_back():
    r = retrieve(ALERT, FakeStore([dict(HITS[0], distance=0.9)] + HITS[1:]), "rag", 0.45)
    assert r.sop_id == "sop_general" and r.used_fallback


def test_rule_map_hit_and_fallback():
    rm = {"5710": "sop_ssh"}
    assert retrieve(ALERT, FakeStore([]), "rule_map", rule_map=rm).sop_id == "sop_ssh"
    other = {"rule": {"id": "999"}}
    r = retrieve(other, FakeStore([]), "rule_map", rule_map=rm)
    assert r.sop_id == "sop_general" and r.used_fallback and r.distance is None


def test_full_context_has_all_docs():
    r = retrieve(ALERT, FakeStore([]), "full_context")
    assert r.sop_id is None and len(r.sop_docs) == 3


def test_missing_fallback_raises():
    store = FakeStore([dict(HITS[0], distance=0.9)])
    store.get_sop = lambda i: None
    with pytest.raises(RetrievalError):
        retrieve(ALERT, store, "rag", 0.45)


def test_bad_mode():
    with pytest.raises(RetrievalError):
        retrieve(ALERT, FakeStore([]), "xyz")
