import hashlib
import pytest

pytest.importorskip("chromadb")
from soc_copilot.sop_store import (SopStore, SopStoreError, EmbedModelMismatch,
                                   load_sops)


class HashEF:
    """Embedding giả, xác định, không cần tải model."""
    def __call__(self, input):
        out = []
        for t in input:
            h = hashlib.sha256(t.encode()).digest()
            out.append([b / 255.0 + 0.01 for b in h[:16]])
        return out

    def name(self):
        return "hash_ef"


def write_sop(d, sid, body="Nội dung SOP.", title=None):
    (d / f"{sid}.md").write_text(
        f"---\nid: {sid}\ntitle: {title or sid}\ncategory: c\n"
        f"default_severity: Medium\n---\n{body}\n", encoding="utf-8")


@pytest.fixture
def env(tmp_path):
    sops = tmp_path / "sops"
    sops.mkdir()
    write_sop(sops, "a")
    write_sop(sops, "b")
    return sops, tmp_path / "chroma"


def store(env, model="m1"):
    sops, chroma = env
    return SopStore(chroma_path=chroma, sop_dir=sops,
                    embedding_function=HashEF(), embed_model=model)


def test_sync_twice_no_change(env):
    s = store(env)
    r1 = s.sync()
    assert sorted(r1["added"]) == ["a", "b"]
    r2 = s.sync()
    assert r2["added"] == r2["updated"] == r2["removed"] == []
    assert s.count() == 2


def test_removed_file_disappears(env):
    s = store(env)
    s.sync()
    (env[0] / "b.md").unlink()
    r = s.sync()
    assert r["removed"] == ["b"] and s.get_sop("b") is None and s.count() == 1


def test_changed_file_updated(env):
    s = store(env)
    s.sync()
    write_sop(env[0], "a", body="Nội dung mới")
    assert s.sync()["updated"] == ["a"]
    assert "Nội dung mới" in s.get_sop("a")["document"]


def test_embed_model_mismatch(env):
    store(env, "m1").sync()
    with pytest.raises(EmbedModelMismatch):
        store(env, "m2")


def test_query_returns_distance(env):
    s = store(env)
    s.sync()
    r = s.query("bất kỳ", n_results=3)
    assert len(r) == 2 and all("distance" in x for x in r)


def test_empty_dir_refuses_to_wipe(env):
    s = store(env)
    s.sync()
    for f in env[0].glob("*.md"):
        f.unlink()
    with pytest.raises(SopStoreError):
        s.sync()
    assert s.count() == 2


def test_bad_front_matter(tmp_path):
    (tmp_path / "x.md").write_text("không có front matter", encoding="utf-8")
    with pytest.raises(SopStoreError):
        load_sops(tmp_path)


def test_duplicate_id(tmp_path):
    write_sop(tmp_path, "a")
    (tmp_path / "a2.md").write_text(
        "---\nid: a\ntitle: t\ncategory: c\ndefault_severity: Low\n---\nx\n")
    with pytest.raises(SopStoreError):
        load_sops(tmp_path)
