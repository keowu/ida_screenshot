import html as _html
import re

import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except ImportError:
    HAS_HEXRAYS = False

from PySide6.QtCore import QPoint, QRect, QSize, QSizeF
from PySide6.QtGui import QColor, QPainter, QPixmap, QRegion, QTextDocument
from PySide6.QtWidgets import QApplication, QWidget

def _scale_size(r: QRect, scale: int) -> QSize:
    return QSize(r.width() * scale, r.height() * scale)


def render_widget_img(widget: QWidget, scale: int) -> QPixmap:
    rect = widget.rect()
    img  = QPixmap(_scale_size(rect, scale))
    img.setDevicePixelRatio(scale)
    widget.render(img, QPoint(), QRegion(rect))
    return img

_BG = "#282c34"
_FG = "#abb2bf"

_C_KW      = "#c678dd"
_C_TYPE    = "#e5c07b"
_C_CALL    = "#61afef"
_C_NUM     = "#d19a66"
_C_STR     = "#98c379"
_C_CMT     = "#5c6370"
_C_PREP    = "#c678dd"

_RULES: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r'(//[^\n]*)'),
        f'<span style="color:{_C_CMT}">\\1</span>',
    ),
    (
        re.compile(r'(&quot;(?:[^&]|&(?!quot;))*?&quot;|&#x27;[^&#]*?&#x27;)'),
        f'<span style="color:{_C_STR}">\\1</span>',
    ),
    (
        re.compile(
            r'\b(if|else|while|for|do|switch|case|break|continue|'
            r'return|goto|default)\b'
        ),
        f'<span style="color:{_C_KW}">\\1</span>',
    ),
    (
        re.compile(
            r'\b(const|static|volatile|inline|extern|register|'
            r'typedef|struct|union|enum|sizeof|typeof)\b'
        ),
        f'<span style="color:{_C_KW}">\\1</span>',
    ),
    (
        re.compile(
            r'\b(void|bool|char|short|int|long|float|double|'
            r'unsigned|signed|'
            r'__int8|__int16|__int32|__int64|'
            r'_BOOL\d?|_BYTE|_WORD|_DWORD|_QWORD|_OWORD|'
            r'_UNKNOWN|BOOL|BYTE|WORD|DWORD|QWORD|HANDLE|'
            r'LPVOID|LPCSTR|LPSTR|LPCWSTR|LPWSTR|'
            r'size_t|ssize_t|ptrdiff_t|intptr_t|uintptr_t|'
            r'uint8_t|uint16_t|uint32_t|uint64_t|'
            r'int8_t|int16_t|int32_t|int64_t)\b'
        ),
        f'<span style="color:{_C_TYPE}">\\1</span>',
    ),
    (
        re.compile(r'\b(NULL|nullptr|true|false|TRUE|FALSE)\b'),
        f'<span style="color:{_C_NUM}">\\1</span>',
    ),
    (
        re.compile(
            r'\b(LOBYTE|HIBYTE|LOWORD|HIWORD|LODWORD|HIDWORD|'
            r'BYTE[0-9]|WORD[0-9])\b'
        ),
        f'<span style="color:{_C_PREP}">\\1</span>',
    ),
    (
        re.compile(r'\b(0[xX][0-9A-Fa-f]+(?:LL|ULL|U|L)?)\b'),
        f'<span style="color:{_C_NUM}">\\1</span>',
    ),
    (
        re.compile(r'(?<![0-9A-Fa-fx_])(-?\b\d+(?:LL|ULL|U|L)?\b)'),
        f'<span style="color:{_C_NUM}">\\1</span>',
    ),
]


def _highlight(plain: str) -> str:

    s = _html.escape(plain, quote=False)
    
    for pattern, replacement in _RULES:
        s = pattern.sub(replacement, s)
        
    return s

def _measure_doc(doc: QTextDocument) -> tuple[int, int]:
  
    WIDE = 200_000.0
    doc.setPageSize(QSizeF(WIDE, WIDE * 500))
    doc.documentLayout().documentSize()

    w = int(doc.idealWidth()) + 40
    h = int(doc.documentLayout().documentSize().height()) + 32

    doc.setPageSize(QSizeF(w, h))
    
    return w, h


def render_full_pseudocode(vu, scale: int) -> QPixmap:

    raw_lines = vu.cfunc.get_pseudocode()

    html_rows: list[str] = []
    for i in range(len(raw_lines)):
    
        # tag_remove() is the official IDA API for stripping colour escapes.
        plain = ida_lines.tag_remove(raw_lines[i].line)
        html_rows.append(_highlight(plain))

    body = "<br/>".join(html_rows)
    full_html = (
        "<html><body style='"
        f"background-color:{_BG};"
        f"color:{_FG};"
        "font-family:Consolas,'Courier New',monospace;"
        "font-size:10pt;"
        "white-space:pre;"
        "margin:16px 20px;"
        f"'>{body}</body></html>"
    )

    doc = QTextDocument()
    doc.setHtml(full_html)

    w, h = _measure_doc(doc)
    print(f"[screenshot] Content: {w}×{h} logical px  ->  "
          f"{w * scale}×{h * scale} physical px")

    pix = QPixmap(QSize(w * scale, h * scale))
    pix.setDevicePixelRatio(scale)
    pix.fill(QColor(_BG))

    painter = QPainter(pix)
    doc.drawContents(painter)
    painter.end()

    return pix

ACTION_CAPTURE_WIDGET_COPY     = "screenshot:CaptureWidgetCopy"
ACTION_CAPTURE_WINDOW_COPY     = "screenshot:CaptureWindowCopy"
ACTION_CAPTURE_WIDGET_SAVE     = "screenshot:CaptureWidgetSave"
ACTION_CAPTURE_WINDOW_SAVE     = "screenshot:CaptureWindowSave"
ACTION_CAPTURE_PSEUDOCODE_COPY = "screenshot:CapturePseudocodeCopy"
ACTION_CAPTURE_PSEUDOCODE_SAVE = "screenshot:CapturePseudocodeSave"

class screenshot_handler_t(ida_kernwin.action_handler_t):

    def __init__(self, widget_only: bool, save_to_file: bool) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.widget_only  = widget_only
        self.save_to_file = save_to_file

    def activate(self, ctx):  # pyright: ignore
        if self.widget_only:
            tw     = ida_kernwin.get_current_widget()
            target = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw)
        else:
            target = QApplication.activeWindow()

        if target is None:
            print("[screenshot] Could not find widget or window!")
            return 1

        scale = ida_kernwin.ask_long(2, "Screenshot scale multiplier:")
        if not scale or scale < 1:
            scale = 1

        self._deliver(render_widget_img(target, scale))
        return 1

    def _deliver(self, img: QPixmap) -> None:
        if self.save_to_file:
            path = ida_kernwin.ask_file(True, "screenshot.png", "Save screenshot")
            if path:
                ok = img.save(path)
                print(f"[screenshot] {'Saved OK' if ok else 'ERROR saving'} → {path}")
        else:
            image = img.toImage()
            if image.isNull():
                print("[screenshot] ERROR: QImage is null (pixmap too large?)")
            else:
                QApplication.clipboard().setImage(image)
                print("[screenshot] Copied to clipboard.")

    def update(self, ctx):  # pyright: ignore
        return ida_kernwin.AST_ENABLE_ALWAYS


class pseudocode_screenshot_handler_t(ida_kernwin.action_handler_t):

    def __init__(self, save_to_file: bool) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.save_to_file = save_to_file

    def activate(self, ctx):  # pyright: ignore
        if not HAS_HEXRAYS:
            print("[screenshot] Hex-Rays decompiler not available.")
            return 1

        tw = ida_kernwin.get_current_widget()
        vu = ida_hexrays.get_widget_vdui(tw)
        if vu is None:
            print("[screenshot] Not a pseudocode view.")
            return 1

        scale = ida_kernwin.ask_long(2, "Screenshot scale multiplier:")
        if not scale or scale < 1:
            scale = 1

        n = len(vu.cfunc.get_pseudocode())
        print(f"[screenshot] Rendering {n} lines (scale={scale})…")

        img = render_full_pseudocode(vu, scale)

        if self.save_to_file:
            path = ida_kernwin.ask_file(True, "pseudocode.png", "Save pseudocode screenshot")
            if path:
                ok = img.save(path)
                print(f"[screenshot] {'Saved OK' if ok else 'ERROR saving'} → {path}")
        else:
            image = img.toImage()
            if image.isNull():
                print("[screenshot] ERROR: QImage is null (pixmap too large?)")
                return 1
            QApplication.clipboard().setImage(image)
            print("[screenshot] Copied to clipboard.")

        return 1

    def update(self, ctx):  # pyright: ignore
        if not HAS_HEXRAYS:
            return ida_kernwin.AST_DISABLE
        if ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget()) is not None:
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE

class screenshot_ui_hooks_t(ida_kernwin.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):  # pyright: ignore
        for action in (
            ACTION_CAPTURE_WIDGET_COPY,
            ACTION_CAPTURE_WINDOW_COPY,
            ACTION_CAPTURE_WIDGET_SAVE,
            ACTION_CAPTURE_WINDOW_SAVE,
        ):
            ida_kernwin.attach_action_to_popup(
                widget, popup, action,
                "Sc&reenshot/",
                ida_kernwin.SETMENU_APP,
            )

        if HAS_HEXRAYS and ida_hexrays.get_widget_vdui(widget) is not None:
            for action in (
                ACTION_CAPTURE_PSEUDOCODE_COPY,
                ACTION_CAPTURE_PSEUDOCODE_SAVE,
            ):
                ida_kernwin.attach_action_to_popup(
                    widget, popup, action,
                    "Sc&reenshot/",
                    ida_kernwin.SETMENU_APP,
                )

class screenshot_plugin_t(ida_idaapi.plugin_t):
    flags         = ida_idaapi.PLUGIN_DRAW | ida_idaapi.PLUGIN_HIDE
    help          = ""
    comment       = "Screenshot Capture"
    wanted_name   = "screenshot"
    wanted_hotkey = ""

    ui_hooks: screenshot_ui_hooks_t

    def init(self):
        self.ui_hooks = screenshot_ui_hooks_t()

        actions = [
            (
                ACTION_CAPTURE_WIDGET_COPY,
                "Copy wid~g~et screenshot to clipboard",
                screenshot_handler_t(True, False),
                "Copy a screenshot of the current widget to the clipboard",
            ),
            (
                ACTION_CAPTURE_WINDOW_COPY,
                "Copy ~w~indow screenshot to clipboard",
                screenshot_handler_t(False, False),
                "Copy a screenshot of the current window to the clipboard",
            ),
            (
                ACTION_CAPTURE_WIDGET_SAVE,
                "Save widget screenshot to file…",
                screenshot_handler_t(True, True),
                "Save a screenshot of the current widget to a file",
            ),
            (
                ACTION_CAPTURE_WINDOW_SAVE,
                "Save window screenshot to file…",
                screenshot_handler_t(False, True),
                "Save a screenshot of the current window to a file",
            ),
            (
                ACTION_CAPTURE_PSEUDOCODE_COPY,
                "Copy ~f~ull pseudocode to clipboard",
                pseudocode_screenshot_handler_t(False),
                "Render the complete decompiled pseudocode and copy to clipboard",
            ),
            (
                ACTION_CAPTURE_PSEUDOCODE_SAVE,
                "Save full pseudocode to file…",
                pseudocode_screenshot_handler_t(True),
                "Render the complete decompiled pseudocode and save to a PNG file",
            ),
        ]

        for action_id, label, handler, tooltip in actions:
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    action_id, label, handler, None, tooltip,
                )
            )

        self.ui_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self):  # pyright: ignore
        pass

    def term(self):
        self.ui_hooks.unhook()


def PLUGIN_ENTRY():
    return screenshot_plugin_t()
