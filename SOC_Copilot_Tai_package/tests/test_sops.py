"""Kiểm tra định dạng kho SOP và rule_map.yaml (T1, T2). Chạy: python -m unittest tests.test_sops"""
import glob
import os
import re
import sys
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HEADINGS = ["Điều kiện áp dụng", "Cách xác minh", "Ngăn chặn", "Bảo toàn chứng cứ",
            "Triệt tiêu", "Phục hồi / Gia cố", "Khi nào leo thang", "Tham chiếu"]
SEVS = {"Low", "Medium", "High", "Critical"}
ALLOWED_PLACEHOLDERS = {"<srcip>", "<user>", "<path>", "<PID>", "<script>"}
ACTIONS = ("BLOCK_IP", "ISOLATE_HOST", "REVIEW_LOG", "NO_ACTION")


def load(path):
    text = open(path, encoding="utf8").read()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert m, f"{path}: thiếu front matter"
    return text, yaml.safe_load(m.group(1)), m.group(2)


def all_paths():
    return sorted(glob.glob(os.path.join(ROOT, "data", "sops", "*.md"))
                  + glob.glob(os.path.join(ROOT, "data", "sops_optional", "*.md")))


class SopFormatTest(unittest.TestCase):
    def test_have_files(self):
        self.assertGreaterEqual(len(glob.glob(os.path.join(ROOT, "data", "sops", "*.md"))), 13)

    def test_each_sop(self):
        ids = set()
        for p in all_paths():
            text, fm, body = load(p)
            name = os.path.basename(p)[:-3]
            with self.subTest(sop=name):
                self.assertEqual(fm["id"], name)
                self.assertNotIn(name, ids); ids.add(name)
                self.assertTrue(str(fm["title"]).strip())
                self.assertTrue(str(fm["category"]).strip())
                self.assertIn(fm["default_severity"], SEVS)
                heads = re.findall(r"^## (.+)$", body, re.M)
                self.assertEqual(heads, HEADINGS)
                self.assertLessEqual(len(text), 1800, "SOP quá dài (ảnh hưởng chế độ full_context và num_ctx)")
                self.assertGreaterEqual(len(body), 600)
                for ph in re.findall(r"<[A-Za-z_]+>", text):
                    self.assertIn(ph, ALLOWED_PLACEHOLDERS)

    def test_no_label_leak_or_bad_advice(self):
        for p in all_paths():
            text = open(p, encoding="utf8").read()
            with self.subTest(sop=p):
                self.assertNotIn("EICAR", text.upper())            # nhãn rò rỉ (xem mục đánh giá vòng tròn)
                self.assertNotIn("rm -f", text)                   # phải bảo toàn chứng cứ trước khi xoá
                self.assertNotRegex(text, r"(?m)^\s*(sudo\s+)?passwd -l")   # không khuyến nghị passwd -l như lệnh khoá

    def test_account_lock_uses_expiredate(self):
        for sid in ("sop_bruteforce_success", "sop_privilege_escalation"):
            text = open(os.path.join(ROOT, "data", "sops", sid + ".md"), encoding="utf8").read()
            self.assertIn("usermod --expiredate 1", text)
            self.assertIn("pkill -KILL -u", text)

    def test_evidence_before_removal_in_fim(self):
        _, _, body = load(os.path.join(ROOT, "data", "sops", "sop_file_integrity.md"))
        sec = dict(zip(HEADINGS, re.split(r"^## .+$", body, flags=re.M)[1:]))
        self.assertIn("sha256sum", sec["Bảo toàn chứng cứ"])
        self.assertIn("cách ly", sec["Triệt tiêu"])

    def test_actions_mentioned_are_valid(self):
        for p in all_paths():
            text = open(p, encoding="utf8").read()
            for tok in re.findall(r"\b[A-Z]+_[A-Z]+\b", text):
                if tok in ("NO_ACTION", "BLOCK_IP", "ISOLATE_HOST", "REVIEW_LOG"):
                    continue
                self.assertNotIn(tok, ("BLOCK_HOST", "ISOLATE_IP"), p)


class RuleMapTest(unittest.TestCase):
    def setUp(self):
        self.rm = yaml.safe_load(open(os.path.join(ROOT, "data", "rule_map.yaml"), encoding="utf8"))
        self.core = {os.path.basename(p)[:-3] for p in glob.glob(os.path.join(ROOT, "data", "sops", "*.md"))}

    def test_structure(self):
        self.assertEqual(self.rm["default"], "sop_general")
        self.assertIn("sop_general", self.core)
        for k, v in self.rm["rules"].items():
            self.assertIsInstance(k, str)
            self.assertTrue(k.isdigit())
            self.assertIn(v, self.core, f"rule {k} trỏ tới SOP không tồn tại: {v}")

    def test_fallback_rules_not_mapped(self):
        for r in ("510", "533", "80730"):          # cố ý để kiểm tra nhánh fallback
            self.assertNotIn(r, self.rm["rules"])

    def test_rule_ids_in_sop_text_match_rule_map(self):
        """Mỗi rule ghi trong 'Điều kiện áp dụng' của SOP phải được rule_map trỏ về đúng SOP đó, và ngược lại."""
        mentioned = {}
        for p in glob.glob(os.path.join(ROOT, "data", "sops", "*.md")):
            _, fm, body = load(p)
            first = re.split(r"^## .+$", body, flags=re.M)[1]
            for grp in re.findall(r"[Rr]ule\s+((?:\d+(?:,\s*)?)+)", first):
                for r in re.findall(r"\d+", grp):
                    mentioned[r] = fm["id"]
        for r, sid in mentioned.items():
            self.assertEqual(self.rm["rules"].get(r), sid, f"rule {r}: SOP ghi {sid}, rule_map ghi {self.rm['rules'].get(r)}")
        for r, sid in self.rm["rules"].items():
            self.assertEqual(mentioned.get(r), sid, f"rule {r} có trong rule_map nhưng SOP {sid} không nhắc tới")


if __name__ == "__main__":
    unittest.main()
