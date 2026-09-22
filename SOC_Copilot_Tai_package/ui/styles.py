"""ui/styles.py: CSS tĩnh. Không nạp font/tài nguyên từ bên ngoài (T9: dữ liệu không rời hạ tầng)."""

CSS = """
html, body, [class*="css"] { font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
code, pre, kbd { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.82rem; font-weight: 600;
         color: #fff; letter-spacing: .2px; white-space: nowrap; }
.sev-low { background: #2e7d32; }      .sev-medium { background: #b26a00; }
.sev-high { background: #d84315; }     .sev-critical { background: #b71c1c; }
.sev-unknown { background: #616161; }
.act-block { background: #b71c1c; }    .act-isolate { background: #6a1b9a; }
.act-review { background: #1565c0; }   .act-none { background: #2e7d32; }   .act-unknown { background: #616161; }
.st-new { background: #455a64; }       .st-confirmed { background: #c62828; }
.st-fp { background: #6d4c41; }        .st-resolved { background: #2e7d32; }
"""
