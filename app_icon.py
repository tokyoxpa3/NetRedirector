# -*- coding: utf-8 -*-
"""應用程式圖示產生器 (訊號中轉站 / 交換機風格)。

- 提供 get_app_icon() 讓 GUI 在執行期直接於記憶體繪製多尺寸 QIcon，
  不依賴任何外部檔案 (打包為單一 exe 時也能正常顯示)。
- 直接執行本檔 (python app_icon.py) 會把 PNG 與 ICO 資產寫入 assets/，
  供 Nuitka 打包時做為 exe 圖示 (--windows-icon-from-ico)。

圖示意象：網路交換機 + 訊號中轉，中央一台交換機，四周輻射出訊號弧線，
代表把流量導向多個方向。
"""

import io
import struct
import os

from PySide6.QtCore import Qt, QRectF, QPointF, QBuffer, QIODevice
from PySide6.QtGui import (
    QColor, QIcon, QPixmap, QPainter, QPen, QBrush, QLinearGradient,
)

_SIZES = (16, 24, 32, 48, 64, 128, 256)


def _draw(painter: QPainter, side: int):
    """在 side x side 的畫布上繪製圖示。"""
    s = float(side)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    # 背景圓角方塊，深藍→青綠漸層
    bg_rect = QRectF(0.5, 0.5, s - 1.0, s - 1.0)
    radius = s * 0.22
    grad = QLinearGradient(0, 0, s, s)
    grad.setColorAt(0.0, QColor("#0b3d6b"))
    grad.setColorAt(0.55, QColor("#0f6f9b"))
    grad.setColorAt(1.0, QColor("#0aa3a3"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(grad))
    painter.drawRoundedRect(bg_rect, radius, radius)

    # 中央交換機機身 (前方面板)
    body_w = s * 0.50
    body_h = s * 0.34
    body_x = (s - body_w) / 2.0
    body_y = (s - body_h) / 2.0
    body = QRectF(body_x, body_y, body_w, body_h)
    painter.setPen(QPen(QColor("#e8f7ff"), max(1.0, s * 0.02)))
    painter.setBrush(QBrush(QColor("#123f5e")))
    painter.drawRoundedRect(body, s * 0.08, s * 0.08)

    # 面板上的連接埠指示燈 (一排)
    n_ports = 4
    port_r = s * 0.035
    if side >= 24:
        total = body_w * 0.72
        gap = total / (n_ports - 1)
        start_x = body_x + body_w * 0.14
        port_y = body_y + body_h * 0.62
        for i in range(n_ports):
            cx = start_x + gap * i
            on = (i % 2 == 0)
            color = QColor("#39ff88") if on else QColor("#2bb673")
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawEllipse(QPointF(cx, port_y), port_r, port_r)

    # 訊號中轉弧線 (自交換機向外輻射)
    if side >= 32:
        arc_pen = QPen(QColor("#7df9ff"))
        arc_pen.setWidthF(max(1.0, s * 0.035))
        arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        center = QPointF(s / 2.0, s / 2.0)
        for i in range(1, 4):
            r = s * (0.30 + 0.13 * i)
            painter.drawArc(
                QRectF(center.x() - r, center.y() - r, r * 2, r * 2),
                -45 * 16, 90 * 16,
            )
        # 對稱的下方弧線
        for i in range(1, 3):
            r = s * (0.30 + 0.14 * i)
            painter.drawArc(
                QRectF(center.x() - r, center.y() - r, r * 2, r * 2),
                135 * 16, 90 * 16,
            )

    # 四個角落的小節點 (訊號中轉端點)
    if side >= 24:
        dot_r = s * 0.045
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor("#ffd166")))
        for dx, dy in ((-0.34, -0.34), (0.34, -0.34), (-0.34, 0.34), (0.34, 0.34)):
            painter.drawEllipse(
                QPointF(s / 2.0 + s * dx, s / 2.0 + s * dy), dot_r, dot_r,
            )


def get_app_icon() -> QIcon:
    """回傳多尺寸 QIcon (執行期直接繪製，不依賴檔案)。"""
    icon = QIcon()
    for side in _SIZES:
        pm = QPixmap(side, side)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        try:
            _draw(p, side)
        finally:
            p.end()
        icon.addPixmap(pm)
    return icon


def _make_png(side: int) -> bytes:
    pm = QPixmap(side, side)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    try:
        _draw(p, side)
    finally:
        p.end()
    img = pm.toImage()
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    if not img.save(buf, "PNG"):
        raise RuntimeError("無法編碼 PNG")
    return bytes(buf.data())


def _build_ico(pngs: dict[int, bytes]) -> bytes:
    """把多尺寸 PNG 打包成 ICO (ICO 支援 PNG 壓縮項目)。

    pngs: {size: png_bytes}。Windows 用 width/height=0 表示 256px。
    """
    sizes = sorted(pngs.keys())
    out = io.BytesIO()
    out.write(struct.pack("<HHH", 0, 1, len(sizes)))  # ICONDIR
    offset = 6 + 16 * len(sizes)
    blobs = []
    for sz in sizes:
        data = pngs[sz]
        w = h = 0 if sz >= 256 else sz
        out.write(struct.pack(
            "<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset,
        ))
        offset += len(data)
        blobs.append(data)
    for data in blobs:
        out.write(data)
    return out.getvalue()


def generate_assets(out_dir: str = "assets") -> None:
    """產生 PNG 與 ICO 資產檔。"""
    import io
    os.makedirs(out_dir, exist_ok=True)
    pngs = {}
    for side in _SIZES:
        data = _make_png(side)
        pngs[side] = data
        with open(os.path.join(out_dir, f"app_icon_{side}.png"), "wb") as f:
            f.write(data)
    with open(os.path.join(out_dir, "app_icon.ico"), "wb") as f:
        f.write(_build_ico(pngs))
    # 另存一份 256px 主圖，方便 README/其他用途
    with open(os.path.join(out_dir, "app_icon.png"), "wb") as f:
        f.write(pngs[256])
    print(f"已產生圖示資產到 {out_dir}/ (PNG x{len(_SIZES)} + ICO)")


if __name__ == "__main__":
    import sys
    from PySide6.QtGui import QGuiApplication
    app = QGuiApplication(sys.argv)
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "assets"
    generate_assets(out_dir)
