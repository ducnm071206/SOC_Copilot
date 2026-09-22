"""Test soc_copilot/storage.py (Tài). Chạy: python -m unittest tests.test_storage  (hoặc pytest)."""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from soc_copilot import storage as st  # noqa: E402

ALERT = {"rule": {"id": "5710", "level": 5, "description": "sshd: attempt to login using a non-existent user"},
         "agent": {"name": "siftworkstation"}, "data": {"srcip": "203.0.113.7"}}
RESULT = {"attack_type": "SSH brute force", "severity": "High", "rule_severity": "Medium",
          "sop_id": "sop_ssh_bruteforce", "sop_distance": 0.21, "recommended_action": "BLOCK_IP",
          "action_target_ip": "203.0.113.7", "timings": {"t_total": 3.4},
          "meta": {"model": "qwen2.5:3b", "prompt_version": "v1", "retrieval_mode": "rag"}}


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "sub", "t.db")   # thư mục con chưa tồn tại
        st.init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_version_and_idempotent_init(self):
        st.init_db(self.db)
        st.init_db(self.db)
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], st.SCHEMA_VERSION)
        con.close()

    def test_newer_db_is_rejected(self):
        p = os.path.join(self.tmp.name, "new.db")
        con = sqlite3.connect(p); con.execute("PRAGMA user_version = 99"); con.commit(); con.close()
        st._READY.discard(p)
        with self.assertRaises(RuntimeError):
            st.init_db(p)

    def test_insert_and_get_roundtrip(self):
        i = st.insert_analysis(ALERT, RESULT, priority="P2", path=self.db)
        rec = st.get_analysis(i, path=self.db)
        self.assertEqual(rec["rule_id"], "5710")
        self.assertEqual(rec["srcip"], "203.0.113.7")
        self.assertEqual(rec["severity"], "High")
        self.assertAlmostEqual(rec["distance"], 0.21)
        self.assertEqual(rec["priority"], "P2")
        self.assertEqual(rec["status"], "new")
        self.assertEqual(rec["alert"], ALERT)
        self.assertEqual(rec["result"]["attack_type"], "SSH brute force")

    def test_source_wrapper_is_unwrapped_for_rule_id(self):
        i = st.insert_analysis({"_source": ALERT}, RESULT, path=self.db)
        self.assertEqual(st.get_analysis(i, path=self.db)["rule_id"], "5710")

    def test_hostile_content_roundtrips_as_data(self):
        evil = {"rule": {"id": "31105"}, "data": {"url": "<img src=x onerror=alert(1)>", "srcip": "1.2.3.4"},
                "full_log": "'; DROP TABLE analyses;-- <script>alert(1)</script> \u0111\u1ecbnh"}
        res = dict(RESULT, attack_type="<b>x</b>'; DROP TABLE analyses;--")
        i = st.insert_analysis(evil, res, path=self.db)
        rec = st.get_analysis(i, path=self.db)
        self.assertEqual(rec["alert"]["full_log"], evil["full_log"])
        self.assertEqual(rec["attack_type"], res["attack_type"])
        self.assertEqual(st.count_analyses(path=self.db), 1)   # bảng vẫn còn

    def test_bad_priority_rejected(self):
        with self.assertRaises(ValueError):
            st.insert_analysis(ALERT, RESULT, priority="P9", path=self.db)
        i = st.insert_analysis(ALERT, RESULT, path=self.db)
        with self.assertRaises(ValueError):
            st.update_priority(i, "high", path=self.db)

    def test_status_flow_and_timestamps(self):
        i = st.insert_analysis(ALERT, RESULT, path=self.db)
        self.assertTrue(st.update_status(i, "confirmed", path=self.db))
        r = st.get_analysis(i, path=self.db)
        self.assertEqual(r["status"], "confirmed"); self.assertTrue(r["confirmed_ts"]); self.assertIsNone(r["resolved_ts"])
        st.update_status(i, "resolved", path=self.db)
        r = st.get_analysis(i, path=self.db)
        self.assertTrue(r["resolved_ts"]); self.assertTrue(r["confirmed_ts"])
        st.update_status(i, "false_positive", path=self.db)
        r = st.get_analysis(i, path=self.db)
        self.assertIsNone(r["confirmed_ts"]); self.assertIsNone(r["resolved_ts"])
        st.update_status(i, "new", path=self.db)
        self.assertIsNone(st.get_analysis(i, path=self.db)["status_ts"])
        self.assertFalse(st.update_status(99999, "confirmed", path=self.db))
        with self.assertRaises(ValueError):
            st.update_status(i, "closed", path=self.db)

    def test_update_priority(self):
        i = st.insert_analysis(ALERT, RESULT, path=self.db)
        self.assertTrue(st.update_priority(i, "P1", path=self.db))
        self.assertEqual(st.get_analysis(i, path=self.db)["priority"], "P1")

    def test_filters(self):
        a = st.insert_analysis(ALERT, RESULT, path=self.db)
        b = st.insert_analysis({"rule": {"id": "31103"}, "data": {"srcip": "9.9.9.9"}},
                               dict(RESULT, severity="Critical", attack_type="SQLi", action_target_ip="9.9.9.9"), path=self.db)
        st.update_status(b, "confirmed", path=self.db)
        self.assertEqual([r["id"] for r in st.list_analyses(path=self.db)], [b, a])   # mới nhất trước
        self.assertEqual([r["id"] for r in st.list_analyses(status="confirmed", path=self.db)], [b])
        self.assertEqual([r["id"] for r in st.list_analyses(severity="High", path=self.db)], [a])
        self.assertEqual([r["id"] for r in st.list_analyses(rule_id="31103", path=self.db)], [b])
        self.assertEqual([r["id"] for r in st.list_analyses(q="9.9.9", path=self.db)], [b])
        self.assertEqual(st.count_analyses(q="sql", path=self.db), 1)
        self.assertEqual(st.distinct_rule_ids(path=self.db), ["31103", "5710"])

    def test_filter_values_are_not_sql(self):
        st.insert_analysis(ALERT, RESULT, path=self.db)
        self.assertEqual(st.list_analyses(status="new' OR '1'='1", path=self.db), [])
        self.assertEqual(st.count_analyses(q="%", path=self.db), 0)     # % được escape, không khớp mọi thứ
        self.assertEqual(st.count_analyses(q="s_p", path=self.db), 0)   # "_" là ký tự thật, không phải ký tự đại diện của LIKE
        self.assertEqual(st.count_analyses(q="_ssh", path=self.db), 1)

    def test_delete(self):
        ids = [st.insert_analysis(ALERT, RESULT, path=self.db) for _ in range(3)]
        self.assertEqual(st.delete_analyses(ids[:2], path=self.db), 2)
        self.assertEqual(st.count_analyses(path=self.db), 1)
        self.assertEqual(st.delete_all(path=self.db), 1)
        self.assertEqual(st.count_analyses(path=self.db), 0)

    def test_csv_injection_guard(self):
        rows = [{"id": 1, "attack_type": "=HYPERLINK(\"http://x\")", "srcip": "+1", "sop_id": "@a", "severity": "-1"}]
        text = st.to_csv(rows)
        self.assertIn("'=HYPERLINK", text)
        self.assertIn("'+1", text)
        self.assertIn("'@a", text)
        self.assertIn("'-1", text)
        self.assertTrue(text.startswith("id,ts,rule_id"))

    def test_kpis(self):
        k = st.kpis(path=self.db)
        self.assertEqual(k["total"], 0); self.assertIsNone(k["avg_analysis_s"]); self.assertIsNone(k["mtta_s"])
        a = st.insert_analysis(ALERT, RESULT, path=self.db)
        b = st.insert_analysis(ALERT, dict(RESULT, timings={"t_total": 1.6}), path=self.db)
        st.update_status(a, "confirmed", path=self.db)
        st.update_status(b, "false_positive", path=self.db)
        k = st.kpis(path=self.db)
        self.assertEqual((k["total"], k["confirmed"], k["false_positive"]), (2, 1, 1))
        self.assertAlmostEqual(k["avg_analysis_s"], 2.5)
        self.assertIsNotNone(k["mtta_s"]); self.assertIsNone(k["mttr_s"])
        st.update_status(a, "resolved", path=self.db)
        self.assertIsNotNone(st.kpis(path=self.db)["mttr_s"])

    def test_missing_fields_do_not_crash(self):
        i = st.insert_analysis({}, {}, path=self.db)
        rec = st.get_analysis(i, path=self.db)
        self.assertIsNone(rec["rule_id"]); self.assertIsNone(rec["distance"])


if __name__ == "__main__":
    unittest.main()
