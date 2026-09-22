"""Streamlit GIẢ tối thiểu để chạy thử giao diện mà không cần cài streamlit (dùng cho test tự động).

Nó KHÔNG thay thế việc chạy thử thật bằng `streamlit run app.py`; nó chỉ ghi lại các lời gọi để kiểm tra
logic (luồng trạng thái, quy tắc escape) và bắt lỗi Python (NameError, sai tham số...).
"""
import sys
import types

CALLS = []          # (tên hàm, args, kwargs)
STATE = {}          # st.session_state
CLICKED = set()     # key của button được coi là "vừa bấm" ở lần chạy kế tiếp
REGISTRY = {}       # key -> (on_click, args)  của lần chạy trước


class Box:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __getattr__(self, name):
        return getattr(_mod, name)


def _rec(name, *a, **k):
    CALLS.append((name, a, k))


def _mk(name):
    def f(*a, **k):
        _rec(name, *a, **k)
    f.__name__ = name
    return f


_mod = types.ModuleType("streamlit")
for _n in ["set_page_config", "markdown", "text", "code", "caption", "error", "warning", "info", "success", "title",
           "header", "subheader", "divider", "dataframe", "table", "json", "metric", "toast", "write"]:
    setattr(_mod, _n, _mk(_n))


def _key(k, label):
    return k if k is not None else f"__auto_{label}"


def selectbox(label, options, index=0, format_func=str, key=None, on_change=None, args=(), **kw):
    options = list(options)
    _rec("selectbox", label, options, key=key, **kw)
    [format_func(o) for o in options]
    k = _key(key, label)
    REGISTRY[k] = (on_change, args)
    v = STATE.get(k) if k in STATE and STATE[k] in options else (options[index] if options else None)
    STATE[k] = v
    return v


def text_area(label, value="", key=None, **kw):
    _rec("text_area", label, key=key)
    return STATE.get(_key(key, label), value)


def text_input(label, value="", key=None, **kw):
    return STATE.get(_key(key, label), value)


def checkbox(label, value=False, key=None, **kw):
    k = _key(key, label)
    return STATE.setdefault(k, value)


def slider(label, mn, mx, value=None, step=None, key=None, **kw):
    k = _key(key, label)
    return STATE.setdefault(k, value)


def file_uploader(label, type=None, key=None, on_change=None, **kw):
    REGISTRY[_key(key, label)] = (on_change, ())
    return STATE.get(_key(key, label))


def button(label, key=None, on_click=None, args=(), disabled=False, **kw):
    k = _key(key, label)
    _rec("button", label, key=k, disabled=disabled)
    REGISTRY[k] = (on_click, args)
    return (k in CLICKED) and not disabled


def download_button(label, data, file_name=None, mime=None, key=None, **kw):
    _rec("download_button", label, data, file_name=file_name, key=key)
    return False


def columns(spec, **kw):
    n = spec if isinstance(spec, int) else len(spec)
    return [Box() for _ in range(n)]


def tabs(labels):
    return [Box() for _ in labels]


def expander(label, expanded=False):
    return Box()


def spinner(text=""):
    return Box()


def cache_data(*a, **k):
    def deco(fn):
        def wrapper(*aa, **kk):
            return fn(*aa, **kk)
        wrapper.clear = lambda: None
        return wrapper
    if a and callable(a[0]):
        return deco(a[0])
    return deco


for _f in (selectbox, text_area, text_input, checkbox, slider, file_uploader, button, download_button,
           columns, tabs, expander, spinner, cache_data):
    setattr(_mod, _f.__name__, _f)
_mod.session_state = STATE
_mod.sidebar = Box()


def install():
    sys.modules["streamlit"] = _mod
    return _mod


def reset():
    CALLS.clear(); STATE.clear(); CLICKED.clear(); REGISTRY.clear()


def click(key):
    """Mô phỏng người dùng bấm nút/đổi widget: chạy callback ngay (như Streamlit), rồi coi button là True ở lần chạy kế."""
    cb, args = REGISTRY.get(key, (None, ()))
    if cb:
        cb(*args)
    CLICKED.add(key)


def new_run():
    """Gọi trước mỗi lần chạy lại script (xoá các lời gọi cũ, giữ session_state)."""
    CALLS.clear()


def end_run():
    CLICKED.clear()
