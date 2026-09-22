"""soc_copilot/storage.py: lưu lịch sử phân tích bằng SQLite (chỉ dùng thư viện chuẩn).

Người sở hữu: Tài (T7). Không phụ thuộc vào code của Bình, ngoại trừ việc *tuỳ chọn*
đọc `config.DB_PATH` nếu module `soc_copilot.config` tồn tại.

Nguyên tắc:
  * Mở kết nối theo từng lời gọi (Streamlit chạy nhiều luồng, kết nối sqlite không dùng chung giữa luồng).
  * Mọi truy vấn dùng tham số (?), tên cột/thứ tự sắp xếp lấy từ danh sách cố định: không nối chuỗi từ dữ liệu vào SQL.
  * Migration bằng PRAGMA user_version.
  * Xuất CSV có chống "CSV injection" (ô bắt đầu bằng = + - @ bị thêm dấu ' phía trước).
"""
from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

SCHEMA_VERSION = 1

STATUSES = ("new", "confirmed", "false_positive", "resolved")
PRIORITIES = ("P1", "P2", "P3", "P4")

_DDL_V1 = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    rule_id         TEXT,
    srcip           TEXT,
    attack_type     TEXT,
    severity        TEXT,
    rule_severity   TEXT,
    sop_id          TEXT,
    distance        REAL,
    action          TEXT,
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new','confirmed','false_positive','resolved')),
    status_ts       TEXT,
    confirmed_ts    TEXT,
    resolved_ts     TEXT,
    priority        TEXT CHECK (priority IS NULL OR priority IN ('P1','P2','P3','P4')),
    model           TEXT,
    prompt_version  TEXT,
    retrieval_mode  TEXT,
    latency_s       REAL,
    alert_json      TEXT NOT NULL,
    result_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_ts     ON analyses(ts);
CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);
CREATE INDEX IF NOT EXISTS idx_analyses_rule   ON analyses(rule_id);
"""

_MIGRATIONS = {0: _DDL_V1}   # chỉ số = phiên bản hiện tại -> câu lệnh nâng lên phiên bản kế tiếp

# Cột được phép lọc / xuất
_LIST_COLUMNS = (
    "id", "ts", "rule_id", "srcip", "attack_type", "severity", "rule_severity", "sop_id",
    "distance", "action", "status", "status_ts", "confirmed_ts", "resolved_ts", "priority",
    "model", "prompt_version", "retrieval_mode", "latency_s",
)

_READY: set[str] = set()


# --------------------------------------------------------------------------- tiện ích
def default_path() -> str:
    """Đường dẫn DB: config.DB_PATH (nếu có) > biến môi trường SOC_COPILOT_DB > soc_copilot.db."""
    try:  # pragma: no cover - phụ thuộc repo của Bình
        from . import config  # type: ignore
        p = getattr(config, "DB_PATH", None)
        if p:
            return str(p)
    except Exception:
        pass
    return os.environ.get("SOC_COPILOT_DB", "soc_copilot.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _g(obj: Any, *keys: str, default: Any = None) -> Any:
    """Lấy giá trị lồng nhau, chịu được dữ liệu không phải dict."""
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def _s(v: Any, limit: int = 300) -> Optional[str]:
    if v is None:
        return None
    return str(v)[:limit]


def _f(v: Any) -> Optional[float]:
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


def _unwrap(alert: Any) -> dict:
    if isinstance(alert, dict) and isinstance(alert.get("_source"), dict):
        return alert["_source"]
    return alert if isinstance(alert, dict) else {}


@contextmanager
def _conn(path: Optional[str] = None):
    p = str(path or default_path())
    _ensure(p)
    con = sqlite3.connect(p, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _ensure(path: str) -> None:
    if path in _READY and os.path.exists(path):
        return
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    try:
        try:
            con.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        ver = con.execute("PRAGMA user_version").fetchone()[0]
        if ver > SCHEMA_VERSION:
            raise RuntimeError(
                f"CSDL có phiên bản {ver} mới hơn code ({SCHEMA_VERSION}). Hãy cập nhật code hoặc dùng file CSDL khác."
            )
        for v in range(ver, SCHEMA_VERSION):
            con.executescript(_MIGRATIONS[v])
            con.execute(f"PRAGMA user_version = {int(v) + 1}")  # int() để chắc chắn không chèn chuỗi
        con.commit()
    finally:
        con.close()
    _READY.add(path)


def init_db(path: Optional[str] = None) -> str:
    """Tạo/nâng cấp CSDL, trả về đường dẫn."""
    p = str(path or default_path())
    _ensure(p)
    return p


# --------------------------------------------------------------------------- ghi
def insert_analysis(alert: dict, result: dict, priority: Optional[str] = None,
                    path: Optional[str] = None) -> int:
    """Lưu một lượt phân tích, trả về id."""
    if priority is not None and priority not in PRIORITIES:
        raise ValueError(f"priority không hợp lệ: {priority!r}")
    a = _unwrap(alert)
    r = result if isinstance(result, dict) else {}
    srcip = r.get("action_target_ip") or _g(r, "alert_summary", "srcip") or _g(a, "data", "srcip")
    row = (
        _now(),
        _s(_g(a, "rule", "id") or _g(r, "alert_summary", "rule_id"), 40),
        _s(srcip, 64),
        _s(r.get("attack_type"), 200),
        _s(r.get("severity"), 20),
        _s(r.get("rule_severity"), 20),
        _s(r.get("sop_id"), 100),
        _f(r.get("sop_distance")),
        _s(r.get("recommended_action"), 30),
        priority,
        _s(_g(r, "meta", "model"), 100),
        _s(_g(r, "meta", "prompt_version"), 40),
        _s(_g(r, "meta", "retrieval_mode"), 30),
        _f(_g(r, "timings", "t_total")),
        json.dumps(alert, ensure_ascii=False, default=str),
        json.dumps(r, ensure_ascii=False, default=str),
    )
    with _conn(path) as con:
        cur = con.execute(
            "INSERT INTO analyses (ts, rule_id, srcip, attack_type, severity, rule_severity, sop_id,"
            " distance, action, priority, model, prompt_version, retrieval_mode, latency_s,"
            " alert_json, result_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
        return int(cur.lastrowid)


def update_status(rec_id: int, status: str, path: Optional[str] = None) -> bool:
    """Đổi trạng thái; ghi mốc thời gian để tính MTTA/MTTR."""
    if status not in STATUSES:
        raise ValueError(f"status không hợp lệ: {status!r}")
    now = _now()
    with _conn(path) as con:
        row = con.execute("SELECT confirmed_ts FROM analyses WHERE id=?", (int(rec_id),)).fetchone()
        if row is None:
            return False
        confirmed_ts = row["confirmed_ts"]
        resolved_ts = None
        if status in ("confirmed", "resolved") and not confirmed_ts:
            confirmed_ts = now
        if status == "resolved":
            resolved_ts = now
        if status in ("new", "false_positive"):
            confirmed_ts = None
        con.execute(
            "UPDATE analyses SET status=?, status_ts=?, confirmed_ts=?, resolved_ts=? WHERE id=?",
            (status, None if status == "new" else now, confirmed_ts, resolved_ts, int(rec_id)))
        return True


def update_priority(rec_id: int, priority: str, path: Optional[str] = None) -> bool:
    if priority not in PRIORITIES:
        raise ValueError(f"priority không hợp lệ: {priority!r}")
    with _conn(path) as con:
        cur = con.execute("UPDATE analyses SET priority=? WHERE id=?", (priority, int(rec_id)))
        return cur.rowcount > 0


def delete_analyses(ids: Iterable[int], path: Optional[str] = None) -> int:
    ids = [int(i) for i in ids]
    n = 0
    with _conn(path) as con:
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            n += con.execute(f"DELETE FROM analyses WHERE id IN ({marks})", chunk).rowcount  # noqa: S608 (chỉ chèn dấu ?)
    return n


def delete_all(path: Optional[str] = None) -> int:
    with _conn(path) as con:
        return con.execute("DELETE FROM analyses").rowcount


# --------------------------------------------------------------------------- đọc
def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _where(status=None, severity=None, rule_id=None, q=None):
    clauses, args = [], []
    if status:
        clauses.append("status = ?"); args.append(status)
    if severity:
        clauses.append("severity = ?"); args.append(severity)
    if rule_id:
        clauses.append("rule_id = ?"); args.append(str(rule_id))
    if q:
        like = f"%{_like_escape(str(q))}%"
        clauses.append("(srcip LIKE ? ESCAPE '\\' OR attack_type LIKE ? ESCAPE '\\' OR sop_id LIKE ? ESCAPE '\\')")
        args += [like, like, like]
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def list_analyses(status=None, severity=None, rule_id=None, q=None,
                  limit: int = 200, offset: int = 0, path: Optional[str] = None) -> list[dict]:
    """Danh sách gọn (không kèm JSON), mới nhất trước."""
    where, args = _where(status, severity, rule_id, q)
    sql = f"SELECT {', '.join(_LIST_COLUMNS)} FROM analyses{where} ORDER BY id DESC LIMIT ? OFFSET ?"  # noqa: S608
    with _conn(path) as con:
        return [dict(r) for r in con.execute(sql, args + [int(limit), int(offset)]).fetchall()]


def count_analyses(status=None, severity=None, rule_id=None, q=None, path: Optional[str] = None) -> int:
    where, args = _where(status, severity, rule_id, q)
    with _conn(path) as con:
        return int(con.execute(f"SELECT COUNT(*) FROM analyses{where}", args).fetchone()[0])  # noqa: S608


def get_analysis(rec_id: int, path: Optional[str] = None) -> Optional[dict]:
    """Bản ghi đầy đủ; `alert` và `result` đã được parse thành dict."""
    with _conn(path) as con:
        row = con.execute("SELECT * FROM analyses WHERE id=?", (int(rec_id),)).fetchone()
    if row is None:
        return None
    d = dict(row)
    for src, dst in (("alert_json", "alert"), ("result_json", "result")):
        try:
            d[dst] = json.loads(d.pop(src))
        except (TypeError, ValueError):
            d[dst] = {}
    return d


def distinct_rule_ids(path: Optional[str] = None) -> list[str]:
    with _conn(path) as con:
        return [r[0] for r in con.execute(
            "SELECT DISTINCT rule_id FROM analyses WHERE rule_id IS NOT NULL ORDER BY rule_id").fetchall()]


def _secs(a: Optional[str], b: Optional[str]) -> Optional[float]:
    try:
        return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()
    except (TypeError, ValueError):
        return None


def kpis(path: Optional[str] = None) -> dict:
    """Số liệu tổng hợp.

    avg_analysis_s : thời gian chạy pipeline trung bình (cái mà bản cũ gọi nhầm là "MTTR")
    mtta_s         : thời gian trung bình từ lúc tạo bản ghi đến lúc analyst xác nhận (MTTA)
    mttr_s         : thời gian trung bình từ lúc tạo bản ghi đến lúc đánh dấu "đã xử lý" (MTTR)
    """
    out = {"total": 0, "new": 0, "confirmed": 0, "false_positive": 0, "resolved": 0,
           "avg_analysis_s": None, "mtta_s": None, "mttr_s": None}
    with _conn(path) as con:
        for r in con.execute("SELECT status, COUNT(*) c FROM analyses GROUP BY status"):
            out[r["status"]] = r["c"]
            out["total"] += r["c"]
        avg = con.execute("SELECT AVG(latency_s) FROM analyses WHERE latency_s IS NOT NULL").fetchone()[0]
        out["avg_analysis_s"] = avg
        acks = [_secs(r["ts"], r["confirmed_ts"]) for r in con.execute(
            "SELECT ts, confirmed_ts FROM analyses WHERE confirmed_ts IS NOT NULL")]
        res = [_secs(r["ts"], r["resolved_ts"]) for r in con.execute(
            "SELECT ts, resolved_ts FROM analyses WHERE resolved_ts IS NOT NULL")]
    acks = [x for x in acks if x is not None]
    res = [x for x in res if x is not None]
    out["mtta_s"] = sum(acks) / len(acks) if acks else None
    out["mttr_s"] = sum(res) / len(res) if res else None
    return out


# --------------------------------------------------------------------------- xuất
def _csv_safe(v: Any) -> Any:
    if isinstance(v, str) and v and v[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def to_csv(rows: list[dict]) -> str:
    """CSV (UTF-8) từ kết quả list_analyses, có chống CSV injection."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(_LIST_COLUMNS)
    for r in rows:
        w.writerow([_csv_safe(r.get(c)) for c in _LIST_COLUMNS])
    return buf.getvalue()
