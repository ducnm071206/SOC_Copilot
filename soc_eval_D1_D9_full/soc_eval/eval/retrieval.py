#!/usr/bin/env python3
"""
Module truy xuat ngu canh (retrieval) cho D4/E1: "3 che do truy xuat x model 3b
(RAG co hon rule_map va full_context khong)".

3 che do:
  - "none":         khong co ngu canh SOP nao them, chi co alert. (baseline)
  - "rule_map":     tra cuu truc tiep theo rule.id trong data/sop/rule_map.json
                     (nhanh, khong can embedding, nhung chi dung neu rule.id da
                     duoc anh xa san).
  - "full_context":  nhet TOAN BO data/sop/full_sop.md vao prompt (don gian nhat,
                     nhung ton token/context window nhat khi SOP dai).
  - "rag":          truy xuat top-k doan lien quan nhat tu SOP bang tim kiem ngu
                     nghia (embedding similarity).

QUAN TRONG - RAG hien tai dung TF-IDF/keyword overlap (thu vien chuan Python,
khong can tai model) lam **fallback mac dinh**, VI moi truong chay script nay
KHONG co ket noi mang toi HuggingFace/internet de tai embedding model that
(vd paraphrase-multilingual-MiniLM-L12-v2 nhu E3 de cap). Day CHI la ban thay
the tam de test duoc pipeline end-to-end ngay hom nay.

Khi ban chay tren may that (co Ollama va model embedding, vd `ollama pull
nomic-embed-text` hoac model embedding tieng Viet/da ngon ngu khac), hay dung
class `OllamaEmbeddingRAG` (goi that toi Ollama /api/embeddings) thay cho
`TfidfRAG` - xem huong dan trong docstring cua tung class ben duoi. Day chinh
la cho E3 se so sanh: embedding tieng Anh mac dinh vs
paraphrase-multilingual-MiniLM-L12-v2, KHONG phai TF-IDF (TF-IDF chi la fallback
de co the chay thu ngay, khong phai mot trong hai lua chon cua E3).
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9_ÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚĂĐĨŨƠàáâãèéêìíòóôõùúăđĩũơƯĂẠẢẤẦẨẪẬẮẰẲẴẶẸẺẼỀỀỂưăạảấầẩẫậắằẳẵặẹẻẽềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]+",
                      text.lower())


def load_full_sop(path: Path) -> str:
    if not path.exists():
        return "[LOI: khong tim thay file SOP tai " + str(path) + " - dung placeholder rong]"
    return path.read_text(encoding="utf-8")


def load_rule_map(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def split_into_chunks(full_sop_text: str, max_chars: int = 500) -> list[str]:
    """Chia SOP thanh cac doan nho (theo dong trong '##') de RAG truy xuat tung phan,
    thay vi nhet nguyen van ban dai."""
    raw_sections = re.split(r"\n(?=#{1,3} )", full_sop_text)
    chunks = []
    for sec in raw_sections:
        sec = sec.strip()
        if not sec:
            continue
        if len(sec) <= max_chars:
            chunks.append(sec)
        else:
            for i in range(0, len(sec), max_chars):
                chunks.append(sec[i:i + max_chars])
    return chunks


class TfidfRAG:
    """RAG FALLBACK dung TF-IDF/keyword overlap don gian (KHONG phai embedding
    ngu nghia that). Chi dung de test pipeline khi chua co embedding model.
    KHONG dung ket qua cua class nay de bao cao cho thi nghiem E3."""

    def __init__(self, chunks: list[str]):
        self.chunks = chunks
        self.doc_tokens = [_tokenize(c) for c in chunks]
        df = Counter()
        for toks in self.doc_tokens:
            for t in set(toks):
                df[t] += 1
        n_docs = max(len(chunks), 1)
        self.idf = {t: math.log((n_docs + 1) / (dfc + 1)) + 1 for t, dfc in df.items()}

    def _vector(self, tokens: list[str]) -> Counter:
        tf = Counter(tokens)
        return Counter({t: c * self.idf.get(t, 1.0) for t, c in tf.items()})

    @staticmethod
    def _cosine(a: Counter, b: Counter) -> float:
        common = set(a) & set(b)
        num = sum(a[t] * b[t] for t in common)
        denom_a = math.sqrt(sum(v * v for v in a.values())) or 1.0
        denom_b = math.sqrt(sum(v * v for v in b.values())) or 1.0
        return num / (denom_a * denom_b)

    def top_k(self, query: str, k: int = 3) -> list[str]:
        if not self.chunks:
            return []
        q_vec = self._vector(_tokenize(query))
        scored = []
        for i, toks in enumerate(self.doc_tokens):
            d_vec = self._vector(toks)
            scored.append((self._cosine(q_vec, d_vec), i))
        scored.sort(key=lambda x: -x[0])
        return [self.chunks[i] for _, i in scored[:k] if _]


class OllamaEmbeddingRAG:
    """RAG THAT dung Ollama /api/embeddings - DUNG CLASS NAY khi chay tren may
    that co Ollama va da `ollama pull <embedding-model>`.

    Vi du dung (thay TfidfRAG bang class nay trong build_retrieval_backend()):

        import requests
        class OllamaEmbeddingRAG:
            def __init__(self, chunks, model="nomic-embed-text", host="http://localhost:11434"):
                self.chunks = chunks
                self.model = model
                self.host = host
                self.chunk_vecs = [self._embed(c) for c in chunks]

            def _embed(self, text):
                r = requests.post(f"{self.host}/api/embeddings",
                                   json={"model": self.model, "prompt": text}, timeout=60)
                r.raise_for_status()
                return r.json()["embedding"]

            def top_k(self, query, k=3):
                import numpy as np
                qv = np.array(self._embed(query))
                sims = [ (float(np.dot(qv, np.array(v)) / (np.linalg.norm(qv)*np.linalg.norm(v)+1e-9)), i)
                         for i, v in enumerate(self.chunk_vecs) ]
                sims.sort(key=lambda x: -x[0])
                return [self.chunks[i] for _, i in sims[:k]]

    Day KHONG duoc cai san trong repo nay vi moi truong chay/test hien tai khong
    co Ollama that de goi. Copy doan tren vao file nay va cai `requests`, `numpy`
    tren may that khi can dung that.
    """
    pass


def alert_to_query_text(alert: dict) -> str:
    """Chuyen 1 alert thanh 1 chuoi query ngan de tim SOP lien quan (dung cho RAG)."""
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    parts = [
        rule.get("description", ""),
        " ".join(rule.get("groups", []) or []),
        data.get("url", "") or "",
        data.get("command", "") or "",
        alert.get("full_log", "")[:300],
    ]
    return " ".join(p for p in parts if p)


def get_context(alert: dict, mode: str, sop_dir: Path, rag_k: int = 3) -> str:
    """Tra ve chuoi ngu canh SOP se duoc nhet vao prompt, tuy theo `mode`."""
    if mode == "none":
        return ""

    rule_id = (alert.get("rule", {}) or {}).get("id", "")

    if mode == "rule_map":
        rule_map = load_rule_map(sop_dir / "rule_map.json")
        snippet = rule_map.get(rule_id)
        if snippet:
            return f"[SOP - rule_map cho rule {rule_id}]\n{snippet}"
        return f"[SOP - khong co muc rule_map cho rule {rule_id}. Can bo sung vao data/sop/rule_map.json.]"

    if mode == "full_context":
        return load_full_sop(sop_dir / "full_sop.md")

    if mode == "rag":
        full_sop = load_full_sop(sop_dir / "full_sop.md")
        chunks = split_into_chunks(full_sop)
        rag = TfidfRAG(chunks)  # xem OllamaEmbeddingRAG de dung ban that
        query = alert_to_query_text(alert)
        top_chunks = rag.top_k(query, k=rag_k)
        header = ("[SOP - RAG (TF-IDF FALLBACK, chua phai embedding ngu nghia that - "
                   "xem docstring OllamaEmbeddingRAG de nang cap) - top "
                   f"{len(top_chunks)} doan lien quan nhat]\n")
        return header + "\n---\n".join(top_chunks)

    raise ValueError(f"Che do retrieval khong hop le: {mode!r} (chi nhan 'none'/'rule_map'/'full_context'/'rag')")
