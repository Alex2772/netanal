#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetUtil Qt — красивый Material-интерфейс для диагностики сети Windows 11.

Переиспользует весь бэкенд из netutil.py (сбор конфигураций, онлайн-проверки,
DNS-анализ, вердикты). Здесь только GUI на PySide6 + qt-material.

Запуск:
    python netutil_qt.py

Установка зависимостей:
    pip install -r requirements.txt
"""

import queue
import sys
import threading
import time

try:
    from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
    from PySide6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QLabel, QPushButton, QTabWidget, QProgressBar, QFrame,
        QTableWidget, QTableWidgetItem, QTextEdit, QCheckBox, QFileDialog,
        QScrollArea, QHeaderView, QAbstractItemView, QListWidget,
        QStackedWidget, QSystemTrayIcon, QMenu, QGraphicsDropShadowEffect,
        QGraphicsOpacityEffect, QDialog, QDialogButtonBox,
    )
except ImportError as e:  # noqa: BLE001
    print("Не установлен PySide6. Установи зависимости:\n"
          "    pip install -r requirements.txt")
    print("Ошибка:", e)
    sys.exit(1)

try:
    from qt_material import apply_stylesheet, list_themes
    HAS_MATERIAL = True
except ImportError:  # noqa: BLE001
    HAS_MATERIAL = False

import netutil as nu


# ----------------------------------------------------------------------------
# Цвета severity (Material-палитра)
# ----------------------------------------------------------------------------
SEV_CHIP = {
    "ok":      ("#1b5e20", "#c8e6c9"),  # зелёный
    "warn":    ("#e65100", "#ffe0b2"),  # оранжевый
    "bad":     ("#b71c1c", "#ffcdd2"),  # красный
    "neutral": ("#455a64", "#eceff1"),  # серый
}
SEV_TEXT = {
    "ok": "#66bb6a", "warn": "#ffa726", "bad": "#ef5350", "neutral": "#90a4ae",
}

# Группировка статус-карточек с заголовками секций
STATUS_GROUPS = [
    ("VPN и маршрутизация", [
        ("vpn", "VPN/туннель"), ("route", "Маршрутизация"),
        ("split", "Split-tunneling"), ("vpn_quality", "VPN-качество"),
    ]),
    ("DNS", [
        ("dns_live", "DNS (напрямую)"), ("resolver", "DNS-резолвер"),
        ("censorship", "DNS-фильтрация"), ("cache", "DNS-кэш"),
    ]),
    ("Система", [
        ("proxy", "Системный прокси"), ("winsock", "Winsock (LSP)"),
        ("adapters", "Вирт. адаптеры"),
    ]),
]


def chip(text: str, severity: str = "neutral") -> QLabel:
    """Цветной бейдж-«чип» для значения статуса."""
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    bg, fg = SEV_CHIP.get(severity, SEV_CHIP["neutral"])
    lbl.setStyleSheet(
        f"background-color: {bg}; color: {fg}; border-radius: 6px;"
        f" padding: 4px 8px; font-weight: 600;")
    return lbl


MONITOR_URLS = [
    "https://api.ipify.org?format=json",
    "https://www.cloudflare.com/cdn-cgi/trace",
]


def monitor_probe():
    """Лёгкая проверка туннеля без замера скорости (минимальный импакт).

    Важно: проверяем реальный end-to-end трафик (DNS+TCP+TLS+HTTP) через
    текущий путь, а не закэшированный getaddrinfo/один TCP-коннект — иначе
    fake-ip и кэш дают ложное «всё ок».
    Возвращает {state, checks[(label, value, sev)], detail}.
    """
    checks = []
    ip_text = nu.run_raw(["ipconfig", "/all"]) or ""
    tunnel_ips = nu.tunnel_interface_ips(nu.parse_ipconfig_adapters(ip_text))
    route_text = nu.run_raw(["route", "print", "-4"]) or ""
    frac, _ = nu.tunnel_traffic_fraction(
        nu.parse_route_print(route_text), tunnel_ips)
    if frac < 0.5:
        return {"state": "off", "checks": [], "detail": "VPN выключен"}
    checks.append(("VPN", "активен", "ok"))

    # End-to-end HTTPS через текущий путь (TUN/прокси), без системного прокси.
    r = None
    dur = 0.0
    for url in MONITOR_URLS:
        t0 = time.perf_counter()
        r = nu.http_test(url, use_system_proxy=False, timeout=8.0)
        dur = (time.perf_counter() - t0) * 1000.0
        if r.get("ok"):
            break
    if not r or not r.get("ok"):
        checks.append(("Трафик", "нет ответа", "bad"))
        return {"state": "suspect", "checks": checks,
                "detail": "трафик через туннель не проходит"}
    if dur < 4000:
        sev = "ok"
    elif dur < 8000:
        sev = "warn"
    else:
        sev = "bad"
    checks.append(("Трафик", "%d мс" % round(dur), sev))
    if sev == "bad":
        return {"state": "suspect", "checks": checks,
                "detail": "трафик очень медленный (%d мс)" % round(dur)}
    return {"state": "ok", "checks": checks,
            "detail": "трафик %d мс" % round(dur)}


# ----------------------------------------------------------------------------
# Тема / акценты
# ----------------------------------------------------------------------------
ACCENT_COLORS = {
    "Бирюзовый": "#00bcd4",
    "Синий": "#42a5f5",
    "Фиолетовый": "#ab47bc",
    "Зелёный": "#66bb6a",
    "Янтарный": "#ffb300",
    "Розовый": "#ec407a",
}


def _lighten(hex_color, f=0.25):
    c = hex_color.lstrip('#')
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
    r = min(255, int(r + (255 - r) * f))
    g = min(255, int(g + (255 - g) * f))
    b = min(255, int(b + (255 - b) * f))
    return '#%02x%02x%02x' % (r, g, b)


COUNTRY_CODES = {
    "Russia": "RU", "Russian Federation": "RU", "Germany": "DE",
    "Poland": "PL", "United States": "US", "Netherlands": "NL",
    "Luxembourg": "LU", "Finland": "FI", "Sweden": "SE", "France": "FR",
    "United Kingdom": "GB", "Australia": "AU", "Canada": "CA",
    "Switzerland": "CH", "Austria": "AT", "Czechia": "CZ", "Estonia": "EE",
    "Latvia": "LV", "Lithuania": "LT", "Turkey": "TR", "Kazakhstan": "KZ",
    "Singapore": "SG", "Japan": "JP", "South Korea": "KR", "China": "CN",
    "India": "IN", "Brazil": "BR", "Ukraine": "UA", "Belarus": "BY",
}


def country_code(value):
    """Код страны (RU/PL) или название (Poland) -> 2-буквенный код."""
    if not value:
        return ""
    v = str(value).strip()
    if len(v) == 2 and v.isalpha():
        return v.upper()
    return COUNTRY_CODES.get(v, "")


# простые полосы/кресты — чтобы флаги рисовались и на Windows
H_FLAGS = {
    "RU": ["#ffffff", "#0039a6", "#d52b1e"],
    "PL": ["#ffffff", "#dc143c"],
    "DE": ["#000000", "#dd0000", "#ffce00"],
    "NL": ["#ae1c28", "#ffffff", "#21468b"],
    "AT": ["#ed2939", "#ffffff", "#ed2939"],
    "HU": ["#cd2a3e", "#ffffff", "#436f4d"],
    "BG": ["#ffffff", "#00966e", "#d62612"],
    "LT": ["#fdb913", "#006a44", "#c1272d"],
    "EE": ["#0072ce", "#000000", "#ffffff"],
    "LU": ["#ed2939", "#ffffff", "#00a1de"],
    "CO": ["#fcd116", "#003893", "#ce1126"],
    "AR": ["#74acdf", "#ffffff", "#74acdf"],
}
V_FLAGS = {
    "FR": ["#0055a4", "#ffffff", "#ef4135"],
    "IT": ["#009246", "#ffffff", "#ce2b37"],
    "IE": ["#169b62", "#ffffff", "#ff883e"],
    "BE": ["#000000", "#fdda24", "#ef3340"],
    "RO": ["#002b7f", "#fcd116", "#ce1126"],
}
CROSS_FLAGS = {
    "FI": ("#ffffff", "#003580"),
    "SE": ("#006aa7", "#fecc00"),
    "NO": ("#ba0c2f", "#ffffff"),
    "DK": ("#c60c30", "#ffffff"),
    "IS": ("#02529c", "#ffffff"),
}


def flag_icon(value, w=20, h=14):
    """Рисует флаг страны (или бейдж с кодом) как QPixmap."""
    code = country_code(value)
    pm = QPixmap(w, h)
    pm.fill(QColor("#37474f"))
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    if code in H_FLAGS:
        cols = H_FLAGS[code]
        n = len(cols)
        for i, c in enumerate(cols):
            p.fillRect(0, int(i * h / n), w, int(h / n) + 1, QColor(c))
    elif code in V_FLAGS:
        cols = V_FLAGS[code]
        n = len(cols)
        for i, c in enumerate(cols):
            p.fillRect(int(i * w / n), 0, int(w / n) + 1, h, QColor(c))
    elif code in CROSS_FLAGS:
        bg, cross = CROSS_FLAGS[code]
        p.fillRect(0, 0, w, h, QColor(bg))
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(cross))
        p.drawRect(0, int(h * 2 / 5), w, max(2, int(h / 5)))
        p.drawRect(int(w * 2 / 5), 0, max(2, int(w / 5)), h)
    elif code == "US":
        for i in range(7):
            p.fillRect(0, int(i * h / 7), w, int(h / 7) + 1,
                       QColor("#b22234" if i % 2 == 0 else "#ffffff"))
        p.fillRect(0, 0, int(w * 0.45), int(h * 0.55), QColor("#3c3b6e"))
    elif code == "GB":
        p.fillRect(0, 0, w, h, QColor("#012169"))
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("#ffffff"))
        p.drawRect(0, int(h * 2 / 5), w, max(2, int(h / 5)))
        p.drawRect(int(w * 2 / 5), 0, max(2, int(w / 5)), h)
    else:
        # бейдж с кодом
        p.setPen(QColor("#e0e0e0"))
        f = p.font()
        f.setPixelSize(max(7, h - 5))
        f.setBold(True)
        p.setFont(f)
        p.drawText(0, 0, w, h, Qt.AlignCenter, code[:2] or "??")
    p.end()
    return pm


def filtered_avg(values):
    """Среднее с отсевом выбросов (IQR-фильтр): рвёт медленные SYN-ACK,
    оставляет «типичный» пинг."""
    if not values:
        return None
    if len(values) < 4:
        return sum(values) / len(values)
    s = sorted(values)
    n = len(s)
    q1 = s[n // 4]
    q3 = s[(3 * n) // 4]
    iqr = q3 - q1
    lo = q1 - 1.5 * iqr
    hi = q3 + 1.5 * iqr
    kept = [v for v in values if lo <= v <= hi]
    if not kept:
        kept = values
    return sum(kept) / len(kept)


def _palette(dark):
    if dark:
        return {
            "bg": "#121417", "card": "#1c1f24", "card2": "#23282f",
            "border": "#2a2e35", "text": "#e0e0e0", "muted": "#8a9099",
            "btn": "#262a30", "btn_hover": "#31363d", "btn_press": "#1f2328",
            "disabled": "#6a7078", "disabled_bg": "#20242a",
            "list_bg": "#171a1e", "item_hover": "#262a30",
            "table_bg": "#171a1e", "table_alt": "#1b1e23",
            "header": "#20242a", "header_text": "#9e9e9e",
            "scroll": "#31363d", "tip_bg": "#2a2d33", "tip_border": "#3a3f46",
            "check_border": "#3a3f46", "check_bg": "#171a1e",
            "input_bg": "#171a1e", "tab_hover": "#d0d4d9",
            "on_accent": "#0b0c0e",
        }
    return {
        "bg": "#f4f5f7", "card": "#ffffff", "card2": "#f8fafc",
        "border": "#e2e5ea", "text": "#1f2328", "muted": "#6b7280",
        "btn": "#eceef2", "btn_hover": "#e0e3e8", "btn_press": "#d8dbe0",
        "disabled": "#a0a6ae", "disabled_bg": "#eef0f3",
        "list_bg": "#ffffff", "item_hover": "#f0f2f5",
        "table_bg": "#ffffff", "table_alt": "#f7f8fa",
        "header": "#eceef2", "header_text": "#4b5563",
        "scroll": "#c8ccd2", "tip_bg": "#1f2328", "tip_border": "#1f2328",
        "check_border": "#c8ccd2", "check_bg": "#ffffff",
        "input_bg": "#ffffff", "tab_hover": "#3a4048",
        "on_accent": "#ffffff",
    }


def build_qss(accent, dark=True):
    """Material-тема (тёмная/светлая) с акцентным цветом."""
    p = _palette(dark)
    light = _lighten(accent)
    return f"""
    QWidget {{ color: {p['text']}; font-family: 'Segoe UI'; font-size: 13px; }}
    QMainWindow {{ background-color: {p['bg']}; }}
    QLabel {{ background: transparent; }}
    QLabel#cardTitle {{ color: {p['text']}; }}
    QLabel#valText {{ color: {p['text']}; }}
    QLabel#muted {{ color: {p['muted']}; }}
    QLabel#brandText {{ color: {p['text']}; }}
    QLabel#sectionHdr {{ color: {p['text']}; }}
    QToolTip {{ background-color: {p['tip_bg']}; color: {p['on_accent']};
                border: 1px solid {p['tip_border']}; border-radius: 5px;
                padding: 5px 9px; }}

    DetailCard, ZoneCard, SummaryCard, MonitorCard {{
        background-color: {p['card']}; border-radius: 14px;
        border: 1px solid {p['border']}; }}
    SummaryCard {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 {p['card']}, stop:1 {p['card2']}); }}
    DetailCard:hover, ZoneCard:hover, SummaryCard:hover, MonitorCard:hover {{
        border: 1px solid {accent}; }}

    QPushButton {{ background-color: {p['btn']}; color: {p['text']}; border: none;
                   border-radius: 8px; padding: 8px 16px; font-weight: 600; }}
    QPushButton:hover {{ background-color: {p['btn_hover']}; }}
    QPushButton:pressed {{ background-color: {p['btn_press']}; }}
    QPushButton:disabled {{ color: {p['disabled']};
                            background-color: {p['disabled_bg']}; }}
    QPushButton#primary {{ background-color: {accent}; color: {p['on_accent']};
                           font-weight: 700; }}
    QPushButton#primary:hover {{ background-color: {light}; }}

    QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 10px;
                        top: -1px; }}
    QTabBar::tab {{ background: transparent; padding: 9px 20px;
                    color: {p['muted']}; border-bottom: 2px solid transparent;
                    font-weight: 600; }}
    QTabBar::tab:selected {{ color: {p['text']};
                             border-bottom: 2px solid {accent}; }}
    QTabBar::tab:hover {{ color: {p['tab_hover']}; }}

    QProgressBar {{ background-color: {p['btn']}; border-radius: 4px;
                    border: none; }}
    QProgressBar::chunk {{ background-color: {accent}; border-radius: 4px; }}

    QListWidget {{ background-color: {p['list_bg']}; border: none;
                   border-radius: 10px; padding: 4px; }}
    QListWidget::item {{ padding: 8px 12px; border-radius: 7px;
                         color: {p['muted']}; }}
    QListWidget::item:selected {{ background-color: {accent};
                                  color: {p['on_accent']}; font-weight: 600; }}
    QListWidget::item:hover {{ background-color: {p['item_hover']}; }}

    QTableWidget {{ background-color: {p['table_bg']};
                    gridline-color: {p['border']}; border: none;
                    alternate-background-color: {p['table_alt']}; }}
    QHeaderView::section {{ background-color: {p['header']};
                            color: {p['header_text']}; border: none;
                            padding: 7px; font-weight: 600; }}
    QTextEdit {{ background-color: {p['input_bg']}; color: {p['text']};
                 border: 1px solid {p['border']}; border-radius: 10px;
                 padding: 8px; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; }}
    QScrollBar::handle:vertical {{ background: {p['scroll']}; border-radius: 5px;
                                   min-height: 30px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; }}
    QScrollBar::handle:horizontal {{ background: {p['scroll']};
                                     border-radius: 5px; min-width: 30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}

    QCheckBox {{ spacing: 8px; color: {p['muted']}; }}
    QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px;
                            border: 2px solid {p['check_border']};
                            background: {p['check_bg']}; }}
    QCheckBox::indicator:checked {{ background-color: {accent};
                                    border-color: {accent}; }}
    """


def add_shadow(widget, blur=24, dy=4, alpha=90):
    """Мягкая тень под карточкой."""
    eff = QGraphicsDropShadowEffect(widget)
    eff.setBlurRadius(blur)
    eff.setOffset(0, dy)
    eff.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(eff)
    return eff


def clear_layout(lay):
    """Рекурсивно очистить QLayout (включая вложенные layout'ы и виджеты)."""
    while lay.count():
        it = lay.takeAt(0)
        w = it.widget()
        if w is not None:
            w.deleteLater()
            continue
        sub = it.layout()
        if sub is not None:
            clear_layout(sub)


class Sparkline(QWidget):
    """Мини-график (спарклайн) — история значений пинга/скорости."""

    def __init__(self, parent=None, color="#00bcd4", height=42):
        super().__init__(parent)
        self.values = []
        self.color = color
        self.setFixedHeight(height)
        self.setMinimumWidth(120)

    def add(self, v):
        if v is None:
            return
        self.values.append(float(v))
        if len(self.values) > 60:
            self.values = self.values[-60:]
        self.update()

    def paintEvent(self, e):
        from PySide6.QtGui import QPainter, QPen, QPainterPath
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        if len(self.values) < 2:
            p.setPen(QPen(QColor("#31363d"), 1))
            p.drawLine(0, h // 2, w, h // 2)
            p.end()
            return
        vals = self.values
        mn, mx = min(vals), max(vals)
        if mx == mn:
            mx = mn + 1.0
        n = len(vals)
        path = QPainterPath()
        first = True
        for i, v in enumerate(vals):
            x = i * (w - 4) / (n - 1) + 2
            y = h - 4 - (v - mn) * (h - 8) / (mx - mn)
            if first:
                path.moveTo(x, y)
                first = False
            else:
                path.lineTo(x, y)
        p.setPen(QPen(QColor(self.color), 1.6))
        p.drawPath(path)
        p.end()


class DetailCard(QFrame):
    """Карточка с заголовком (эмодзи) и подпунктами 'параметр: значение'."""
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        add_shadow(self)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 14)
        lay.setSpacing(6)
        self.title_lbl = QLabel(title)
        self.title_lbl.setObjectName("cardTitle")
        self.title_lbl.setStyleSheet("font-size: 14px; font-weight: 700;")
        lay.addWidget(self.title_lbl)
        self.rows = {}
        self.flags = {}
        self.rows_lay = QVBoxLayout()
        self.rows_lay.setSpacing(4)
        lay.addLayout(self.rows_lay)

    def add_row(self, label, value="…", severity="neutral"):
        row = QHBoxLayout()
        row.setSpacing(6)
        lbl = QLabel(label)
        lbl.setObjectName("muted")
        flag = QLabel()
        flag.setFixedSize(20, 14)
        flag.hide()
        val = QLabel(value)
        val.setObjectName("valText")
        val.setToolTip(value)
        if severity == "neutral":
            val.setStyleSheet("font-weight: 600;")
        else:
            val.setStyleSheet("font-weight: 600; color: %s;"
                              % SEV_TEXT.get(severity, "#90a4ae"))
        row.addWidget(lbl)
        row.addStretch()
        row.addWidget(flag)
        row.addWidget(val)
        self.rows_lay.addLayout(row)
        self.rows[label] = val
        self.flags[label] = flag

    def set_row(self, label, value, severity="neutral"):
        val = self.rows.get(label)
        if val is not None:
            val.setText(value)
            val.setToolTip(value)
            if severity == "neutral":
                val.setStyleSheet("font-weight: 600;")
            else:
                val.setStyleSheet("font-weight: 600; color: %s;"
                                  % SEV_TEXT.get(severity, "#90a4ae"))

    def set_flag(self, label, value):
        fl = self.flags.get(label)
        if fl is None:
            return
        code = country_code(value)
        if code:
            fl.setPixmap(flag_icon(code))
            fl.show()
        else:
            fl.hide()


class SummaryCard(QFrame):
    """Сводная карточка: вердикт + список пунктов с цветными точками."""

    def __init__(self, parent=None):
        super().__init__(parent)
        add_shadow(self, blur=32, dy=6)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 20, 16)
        root.setSpacing(8)
        top = QHBoxLayout()
        top.setSpacing(12)
        self.stripe = QFrame()
        self.stripe.setFixedWidth(4)
        self.stripe.setStyleSheet("background: #66bb6a; border-radius: 2px;")
        top.addWidget(self.stripe)
        self.icon_lbl = QLabel("…")
        self.icon_lbl.setStyleSheet("font-size: 30px;")
        top.addWidget(self.icon_lbl)
        self.status_lbl = QLabel("…")
        self.status_lbl.setStyleSheet(
            "font-size: 19px; font-weight: 800; letter-spacing: 0.5px;")
        top.addWidget(self.status_lbl)
        top.addStretch()
        root.addLayout(top)
        self.check_lbl = QLabel("")
        self.check_lbl.setObjectName("muted")
        self.check_lbl.setStyleSheet("font-size: 11px;")
        root.addWidget(self.check_lbl)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.hide()
        root.addWidget(self.progress_bar)
        self.counts_lbl = QLabel("")
        self.counts_lbl.setObjectName("muted")
        self.counts_lbl.setStyleSheet("font-size: 11px;")
        self.counts_lbl.hide()
        root.addWidget(self.counts_lbl)
        self.items_lay = QVBoxLayout()
        self.items_lay.setSpacing(3)
        root.addLayout(self.items_lay)

    def set_check_status(self, text, color=None):
        self.check_lbl.setText(text)
        self.check_lbl.setStyleSheet(
            "font-size: 11px; color: %s;" % (color or "#8a9099"))

    def set_progress(self, done, total, counts_text=""):
        pct = int(done * 100 / total) if total else 0
        self.progress_bar.setValue(pct)
        self.progress_bar.show()
        self.set_check_status("Сайты: %d / %d" % (done, total), "#ffa726")
        self.counts_lbl.setText(counts_text)
        self.counts_lbl.setVisible(bool(counts_text))

    def finish_check(self, text):
        self.progress_bar.hide()
        self.counts_lbl.hide()
        self.set_check_status(text, "#66bb6a")

    def _set_head(self, icon, text, color):
        self.icon_lbl.setText(icon)
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(
            "font-size: 18px; font-weight: 800; color: %s;" % color)
        self.stripe.setStyleSheet(
            "background: %s; border-radius: 2px;" % color)

    def set_status(self, severity, items=None):
        if severity == "ok":
            self._set_head("✅", "ВСЁ ОК", "#66bb6a")
        elif severity == "bad":
            self._set_head("❌", "НЕ ОК", "#ef5350")
        elif severity == "pending":
            self._set_head("⏳", "ИДЁТ ПРОВЕРКА", "#90a4ae")
        else:
            self._set_head("⚠️", "ЕСТЬ ЗАМЕЧАНИЯ", "#ffa726")
        clear_layout(self.items_lay)
        for label, value, sev in (items or []):
            self._add_item(label, value, sev)

    def _add_item(self, label, value, sev):
        color = {"ok": "#66bb6a", "warn": "#ffa726",
                 "bad": "#ef5350"}.get(sev, "#90a4ae")
        row = QHBoxLayout()
        row.setSpacing(6)
        dot = QLabel("●")
        dot.setStyleSheet("color: %s; font-size: 10px;" % color)
        row.addWidget(dot)
        lab = QLabel(label)
        lab.setObjectName("muted")
        lab.setStyleSheet("font-size: 12px;")
        row.addWidget(lab)
        row.addStretch()
        val = QLabel(value)
        val.setStyleSheet("font-size: 12px; font-weight: 600; color: %s;"
                          % color)
        row.addWidget(val)
        self.items_lay.addLayout(row)


class MonitorCard(QFrame):
    """Карточка фонового мониторинга: что проверяется и с каким результатом."""

    def __init__(self, parent=None):
        super().__init__(parent)
        add_shadow(self)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 14)
        lay.setSpacing(6)
        self.title_lbl = QLabel("📡 Мониторинг туннеля")
        self.title_lbl.setObjectName("cardTitle")
        self.title_lbl.setStyleSheet("font-size: 14px; font-weight: 700;")
        lay.addWidget(self.title_lbl)
        st_row = QHBoxLayout()
        st_row.setSpacing(6)
        self.dot = QLabel("●")
        self.dot.setStyleSheet("color: #757575; font-size: 12px;")
        self.state_lbl = QLabel("выключен")
        self.state_lbl.setObjectName("muted")
        st_row.addWidget(self.dot)
        st_row.addWidget(self.state_lbl)
        st_row.addStretch()
        lay.addLayout(st_row)
        # список проверок «что проверяем → результат»
        self.items_lay = QVBoxLayout()
        self.items_lay.setSpacing(3)
        lay.addLayout(self.items_lay)
        self.last_lbl = QLabel("последняя: —")
        self.last_lbl.setObjectName("muted")
        self.last_lbl.setStyleSheet("font-size: 11px;")
        lay.addWidget(self.last_lbl)
        self.next_bar = QProgressBar()
        self.next_bar.setRange(0, 100)
        self.next_bar.setValue(0)
        self.next_bar.setTextVisible(False)
        self.next_bar.setFixedHeight(4)
        lay.addWidget(self.next_bar)
        self.next_lbl = QLabel("следующая: —")
        self.next_lbl.setObjectName("muted")
        self.next_lbl.setStyleSheet("font-size: 11px;")
        lay.addWidget(self.next_lbl)
        self.btn = QPushButton("Включить")
        lay.addWidget(self.btn)

    def _clear(self):
        while self.items_lay.count():
            it = self.items_lay.takeAt(0)
            w = it.widget()
            if w is not None:
                w.deleteLater()
                continue
            sub = it.layout()
            if sub is not None:
                clear_layout(sub)

    def set_state(self, state, checks=None, detail=""):
        color = {"off": "#757575", "ok": "#66bb6a", "bad": "#ef5350",
                 "suspect": "#ffa726"}.get(state, "#757575")
        labels = {"off": "VPN выключен", "ok": "туннель в норме",
                  "suspect": "есть сомнения", "bad": "туннель нестабилен"}
        self.dot.setStyleSheet("color: %s; font-size: 12px;" % color)
        self.state_lbl.setText(labels.get(state, state))
        self.state_lbl.setStyleSheet("color: %s;" % color)
        self._clear()
        for label, value, sev in (checks or []):
            self._add_check(label, value, sev)
        if detail:
            self.last_lbl.setText("последняя: %s" % time.strftime("%H:%M:%S"))

    def _add_check(self, label, value, sev):
        color = {"ok": "#66bb6a", "warn": "#ffa726",
                 "bad": "#ef5350"}.get(sev, "#90a4ae")
        row = QHBoxLayout()
        row.setSpacing(6)
        dot = QLabel("●")
        dot.setStyleSheet("color: %s; font-size: 9px;" % color)
        row.addWidget(dot)
        lab = QLabel(label)
        lab.setObjectName("muted")
        lab.setStyleSheet("font-size: 12px;")
        row.addWidget(lab)
        row.addStretch()
        val = QLabel(value)
        val.setStyleSheet("font-size: 12px; font-weight: 600; color: %s;"
                          % color)
        row.addWidget(val)
        self.items_lay.addLayout(row)

    def set_off(self):
        self.dot.setStyleSheet("color: #757575; font-size: 12px;")
        self.state_lbl.setText("выключен")
        self.state_lbl.setStyleSheet("")
        self._clear()
        self.next_bar.setValue(0)
        self.next_lbl.setText("следующая: —")
        self.last_lbl.setText("последняя: —")


class CheckChart(QWidget):
    """Сетка результатов проверки: клетка на сайт, цвет = статус."""

    CS = 11
    GAP = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cells = {}
        self.setMinimumHeight(3 * (self.CS + self.GAP) + 14)
        self.setToolTip("Клетка = сайт: 🟩 доступен, 🟥 нет, ⬛ ещё не проверен")

    def set_results(self, cells):
        self.cells = cells
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        y = 2
        for zone in ("RU", "Зарубежные", "Заблокированные"):
            x = 2
            for c in (self.cells.get(zone) or []):
                if c is True:
                    col = QColor("#66bb6a")
                elif c is False:
                    col = QColor("#ef5350")
                else:
                    col = QColor("#31363d")
                p.setBrush(col)
                p.setPen(Qt.NoPen)
                p.drawRoundedRect(x, y, self.CS, self.CS, 2, 2)
                x += self.CS + self.GAP
            y += self.CS + self.GAP + 3
        p.end()


class ProgressCard(QFrame):
    """Карточка хода онлайн-проверки (видна только во время проверки)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        add_shadow(self)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(16)
        left = QVBoxLayout()
        left.setSpacing(4)
        self.title_lbl = QLabel("⏳ Проверка")
        self.title_lbl.setObjectName("cardTitle")
        self.title_lbl.setStyleSheet("font-size: 14px; font-weight: 700;")
        left.addWidget(self.title_lbl)
        self.phase_lbl = QLabel("…")
        self.phase_lbl.setObjectName("muted")
        left.addWidget(self.phase_lbl)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(True)
        self.bar.setFixedHeight(18)
        left.addWidget(self.bar)
        self.counts_lbl = QLabel("—")
        self.counts_lbl.setObjectName("muted")
        self.counts_lbl.setStyleSheet("font-size: 12px;")
        left.addWidget(self.counts_lbl)
        lay.addLayout(left, 1)
        self.chart = CheckChart()
        lay.addWidget(self.chart)

    def set_progress(self, done, total, phase, cells):
        self.phase_lbl.setText(phase)
        pct = int(done * 100 / total) if total else 0
        self.bar.setValue(pct)
        self.bar.setFormat("%d / %d" % (done, total))
        parts = []
        for z in ("RU", "Зарубежные", "Заблокированные"):
            cl = cells.get(z) or []
            ok = sum(1 for c in cl if c is True)
            parts.append("%s %d/%d" % (z, ok, len(cl)))
        self.counts_lbl.setText("  ·  ".join(parts))
        self.chart.set_results(cells)


class SiteListDialog(QDialog):
    """Редактор списков доменов по зонам (один URL на строку)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Списки сайтов для проверки")
        self.resize(720, 560)
        lay = QVBoxLayout(self)
        hint = QLabel("Один URL на строку. Имя берётся из домена. "
                      "Списки сохраняются в sites.json рядом с утилитой.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        self.tabs = QTabWidget()
        self.editors = {}
        for zone in nu.ZONES:
            edit = QTextEdit()
            edit.setAcceptRichText(False)
            edit.setPlainText("\n".join(u for _n, u in nu.ZONE_SITES[zone]))
            self.tabs.addTab(edit, "%s (%d)" % (zone, len(nu.ZONE_SITES[zone])))
            self.editors[zone] = edit
        lay.addWidget(self.tabs)
        btns = QDialogButtonBox()
        reset_btn = btns.addButton("Сбросить к дефолтным",
                                   QDialogButtonBox.ResetRole)
        btns.addButton(QDialogButtonBox.Save)
        btns.addButton(QDialogButtonBox.Cancel)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        reset_btn.clicked.connect(self._reset)
        lay.addWidget(btns)

    def _reset(self):
        for zone, edit in self.editors.items():
            default = {"RU": nu.DEFAULT_RU_SITES,
                       "Зарубежные": nu.DEFAULT_FOREIGN_SITES,
                       "Заблокированные": nu.DEFAULT_BLOCKED_SITES}[zone]
            edit.setPlainText("\n".join(u for _n, u in default))

    def values(self):
        out = {}
        for zone, edit in self.editors.items():
            urls = [ln.strip() for ln in edit.toPlainText().splitlines()
                    if ln.strip()]
            out[zone] = [(nu._name_from_url(u), u) for u in urls]
        return out


class ZoneCard(QFrame):
    """Карточка зоны: статус, IP с флагом, параметры (пинг/скорость/сайты)."""

    def __init__(self, zone: str, total: int, parent=None):
        super().__init__(parent)
        add_shadow(self)
        self.total = total
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(6)
        self.title = QLabel(zone)
        self.title.setObjectName("cardTitle")
        self.title.setStyleSheet("font-size: 15px; font-weight: 700;")
        lay.addWidget(self.title)
        eg_row = QHBoxLayout()
        eg_row.setSpacing(6)
        self.egress_flag = QLabel()
        self.egress_flag.setFixedSize(20, 14)
        self.egress_flag.hide()
        self.egress = QLabel("IP: …")
        self.egress.setStyleSheet("color: #26a69a; font-size: 12px;")
        self.egress.setWordWrap(True)
        eg_row.addWidget(self.egress_flag)
        eg_row.addWidget(self.egress, 1)
        lay.addLayout(eg_row)
        self.status = QLabel("…")
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setStyleSheet(
            "font-size: 15px; font-weight: 800; border-radius: 8px;"
            " padding: 8px;")
        lay.addWidget(self.status)

        # параметры: выровненные строки «лейбл … значение»
        self.params = {}
        for lbl in ("Пинг", "DNS", "Скорость", "Сайтов"):
            row = QHBoxLayout()
            row.setSpacing(8)
            k = QLabel(lbl)
            k.setObjectName("muted")
            v = QLabel("—")
            v.setObjectName("valText")
            v.setStyleSheet("font-weight: 700;")
            row.addWidget(k)
            row.addStretch()
            row.addWidget(v)
            lay.addLayout(row)
            self.params[lbl] = v

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        lay.addWidget(self.bar)
        self.spark = Sparkline(color="#00bcd4")
        self.spark.setToolTip("История пинга (мс)")
        lay.addWidget(self.spark)
        self.spark_cap = QLabel("📈 пинг, мс")
        self.spark_cap.setObjectName("muted")
        self.spark_cap.setStyleSheet("font-size: 11px;")
        lay.addWidget(self.spark_cap)
        self.spark_speed = Sparkline(color="#66bb6a", height=32)
        self.spark_speed.setToolTip("История скорости (Мбит/с)")
        lay.addWidget(self.spark_speed)
        self.spark_speed_cap = QLabel("📶 скорость, Мбит/с")
        self.spark_speed_cap.setObjectName("muted")
        self.spark_speed_cap.setStyleSheet("font-size: 11px;")
        lay.addWidget(self.spark_speed_cap)
        self._set_status("—", "neutral")

    def _set_status(self, text: str, severity: str):
        bg = SEV_CHIP.get(severity, SEV_CHIP["neutral"])[0]
        self.status.setText(text)
        self.status.setStyleSheet(
            f"font-size: 15px; font-weight: 800; border-radius: 8px;"
            f" padding: 8px; background-color: {bg}; color: #ffffff;")

    def set_param(self, label, value, severity="neutral"):
        v = self.params.get(label)
        if v is not None:
            v.setText(value)
            if severity == "neutral":
                v.setStyleSheet("font-weight: 700;")
            else:
                v.setStyleSheet("font-weight: 700; color: %s;"
                                % SEV_TEXT.get(severity, "#90a4ae"))


class NetUtilQt(QMainWindow):
    DNS_SIDS = ("dns_live", "resolver", "split_dns", "censorship", "cache")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetUtil — диагностика сети Windows 11")
        self.resize(1180, 800)

        self.queue = queue.Queue()
        self.runner = None
        self.data = {}
        self.findings = []
        self.online_data = {}
        self.status_cards = {}
        self.status_rows = {}
        self.zone_cards = {}
        self.online_done = False
        self._monitor_result = None
        self._monitor_state = None  # None = ещё не знаем (старт/после вкл.)
        self._last_speed_time = 0.0
        self._monitor_next = 0.0
        self.dark = True
        self.current_accent = ACCENT_COLORS["Бирюзовый"]
        self.zone_state = {
            z: {"total": len(nu.ZONE_SITES[z]), "ok": 0, "lats": [],
                "dns_ms": [], "speed": None, "speed_ok": False}
            for z in nu.ZONES
        }
        self._dns_result = None

        self._build_ui()
        self._setup_tray()
        self.setWindowIcon(self._make_icon(ACCENT_COLORS["Бирюзовый"]))
        self.refresh_all()
        self._start_monitor()

        # Таймер: опрос очереди OnlineRunner + фоновых проверок
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        self.timer.start(150)

        # Таймер: обратный отсчёт до следующей проверки мониторинга
        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self._update_monitor_countdown)
        self.ui_timer.start(1000)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(8)

        # ---- брендинг ----
        brand_row = QHBoxLayout()
        brand_row.setSpacing(8)
        logo = QLabel("⚡")
        logo.setStyleSheet("font-size: 20px;")
        brand_row.addWidget(logo)
        brand = QLabel("NETUTIL")
        brand.setObjectName("brandText")
        brand.setStyleSheet("font-size: 21px; font-weight: 900;"
                            " letter-spacing: 3px;")
        brand_row.addWidget(brand)
        sub = QLabel("диагностика сети · туннеля · DNS")
        sub.setObjectName("muted")
        sub.setStyleSheet("font-size: 12px;")
        brand_row.addWidget(sub)
        brand_row.addStretch()
        root.addLayout(brand_row)

        # тонкая полоса активности проверки
        self.activity = QProgressBar()
        self.activity.setRange(0, 0)
        self.activity.setFixedHeight(3)
        self.activity.setTextVisible(False)
        self.activity.hide()
        root.addWidget(self.activity)

        # ---- шапка ----
        head = QHBoxLayout()
        self.btn_refresh = QPushButton("▶ Проверить всё")
        self.btn_refresh.setObjectName("primary")
        self.btn_export = QPushButton("Сохранить отчёт…")
        self.auto_cb = QCheckBox("Мониторинг туннеля (60 с)")
        self.auto_cb.setChecked(True)
        self.admin_lbl = QLabel(
            "⚡ права администратора" if nu.is_admin()
            else "⚠ без прав администратора (часть данных недоступна)")
        self.admin_lbl.setStyleSheet(
            "color: #66bb6a;" if nu.is_admin() else "color: #ef5350;")
        head.addWidget(self.btn_refresh)
        head.addWidget(self.auto_cb)
        self.btn_theme = QPushButton("🎨")
        self.theme_menu = QMenu(self.btn_theme)
        for nm, col in ACCENT_COLORS.items():
            act = self.theme_menu.addAction(nm)
            act.triggered.connect(lambda checked=False, c=col: self._set_accent(c))
        self.btn_theme.setMenu(self.theme_menu)
        self.btn_theme.setToolTip("Акцентный цвет")
        head.addWidget(self.btn_theme)
        self.btn_mode = QPushButton("🌓")
        self.btn_mode.setToolTip("Тёмная / светлая тема")
        self.btn_mode.clicked.connect(self._toggle_theme)
        head.addWidget(self.btn_mode)
        self.btn_sites = QPushButton("📋 Списки")
        self.btn_sites.setToolTip("Редактировать списки доменов для проверки")
        self.btn_sites.clicked.connect(self.edit_site_lists)
        head.addWidget(self.btn_sites)
        head.addStretch()
        head.addWidget(self.admin_lbl)
        head.addWidget(self.btn_export)
        root.addLayout(head)
        self.status_lbl = QLabel("Готово")
        self.status_lbl.setStyleSheet("color: #757575;")
        root.addWidget(self.status_lbl)

        # ---- вкладки ----
        self.tabs = QTabWidget()
        root.addWidget(self.tabs)
        self._build_dashboard_tab()
        self._build_summary_tab()
        self._build_system_tab()

        # ---- футер ----
        foot = QHBoxLayout()
        foot.setSpacing(6)
        self.monitor_dot = QLabel("●")
        self.monitor_dot.setStyleSheet("color: #66bb6a; font-size: 10px;")
        foot.addWidget(self.monitor_dot)
        self.monitor_lbl = QLabel("мониторинг активен")
        self.monitor_lbl.setStyleSheet("color: #607d8b; font-size: 12px;")
        foot.addWidget(self.monitor_lbl)
        foot.addStretch()
        ver = QLabel("NetUtil · v1.0")
        ver.setStyleSheet("color: #455a64; font-size: 12px;")
        foot.addWidget(ver)
        root.addLayout(foot)

        # ---- сигналы ----
        self.btn_refresh.clicked.connect(self.refresh_all)
        self.btn_export.clicked.connect(self.export_report)
        self.auto_cb.toggled.connect(self._toggle_monitor)

    def _build_dashboard_tab(self):
        w = QWidget()
        self.tabs.addTab(w, "Главная")
        lay = QVBoxLayout(w)
        lay.setSpacing(8)

        def add_header(text):
            hdr = QLabel(text)
            hdr.setObjectName("sectionHdr")
            hdr.setStyleSheet(
                "font-size: 15px; font-weight: 700;"
                " margin-top: 10px; border-bottom: 1px solid #37474f;"
                " padding-bottom: 4px;")
            lay.addWidget(hdr)

        # 1) Сводный статус ОК / НЕ ОК + карточка мониторинга
        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        self.summary_card = SummaryCard()
        top_row.addWidget(self.summary_card, 3)
        self.monitor_card = MonitorCard()
        self.monitor_card.btn.clicked.connect(self._toggle_monitor_btn)
        top_row.addWidget(self.monitor_card, 2)
        lay.addLayout(top_row)

        # 2) Доступность по зонам
        add_header("📍 Доступность по зонам")
        zones_row = QHBoxLayout()
        zones_row.setSpacing(8)
        for z in nu.ZONES:
            zc = ZoneCard(z, len(nu.ZONE_SITES[z]))
            zc.setToolTip(f"Доступность сайтов зоны «{z}», пинг (средний "
                          f"с отсевом выбросов), DNS и скорость.")
            self.zone_cards[z] = zc
            zones_row.addWidget(zc)
        lay.addLayout(zones_row)

        # 3) Карточки с подпунктами
        self.status_rows = {}
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        vpn_card = DetailCard("🔒 VPN и маршрутизация")
        vpn_card.setToolTip("Состояние туннеля, режим маршрутизации, "
                            "split-tunneling, качество и общий диагноз.")
        for lbl in ("Туннель", "Режим", "Split", "Качество", "Диагноз"):
            vpn_card.add_row(lbl, "…", "neutral")
        for sid, lbl in (("vpn", "Туннель"), ("route", "Режим"),
                         ("split", "Split"), ("vpn_quality", "Качество"),
                         ("diagnosis", "Диагноз")):
            self.status_rows[sid] = (vpn_card, lbl)
        row1.addWidget(vpn_card)

        self.dns_card = DetailCard("🧭 DNS")
        self.dns_card.setToolTip("Резолвит ли DNS, через какой резолвер и куда "
                                 "(страна), split-DNS, фильтрация и мусор в кэше.")
        for lbl in ("Резолвинг", "Резолвер", "Split DNS", "Фильтрация", "Кэш"):
            self.dns_card.add_row(lbl, "…", "neutral")
        for sid, lbl in (("dns_live", "Резолвинг"), ("resolver", "Резолвер"),
                         ("split_dns", "Split DNS"),
                         ("censorship", "Фильтрация"), ("cache", "Кэш")):
            self.status_rows[sid] = (self.dns_card, lbl)
        row1.addWidget(self.dns_card)
        lay.addLayout(row1)

        self.ip_card = DetailCard("🌍 IP-адреса")
        self.ip_card.setToolTip("Внешние IP, которые видят сайты, по зонам: "
                                "в РФ, наружу и для заблокированных.")
        for lbl in ("В РФ", "Наружу", "Заблокированные"):
            self.ip_card.add_row(lbl, "…", "neutral")
        row2.addWidget(self.ip_card)

        sys_card = DetailCard("⚙️ Система")
        sys_card.setToolTip("Системный прокси и виртуальные адаптеры (TUN/TAP). "
                            "Winsock/LSP — в подменю «Система».")
        for lbl in ("Прокси", "Адаптеры"):
            sys_card.add_row(lbl, "…", "neutral")
        for sid, lbl in (("proxy", "Прокси"), ("adapters", "Адаптеры")):
            self.status_rows[sid] = (sys_card, lbl)
        row2.addWidget(sys_card)

        self.udp_card = DetailCard("🎮 UDP (игры)")
        self.udp_card.setToolTip(
            "Качество UDP: RTT и потери. Методы одинаковые — STUN (3478), "
            "NTP (123), DNS (53), отличаются только адреса. Отдельной зоны "
            "«Заблокированные» нет: UDP в РФ не блокируется (блокировка на "
            "TCP/SNI), а QUIC конфликтует с Xray. Важно для игр "
            "(Elite: Dangerous и др.).")
        for lbl in ("RU", "Зарубежные"):
            self.udp_card.add_row(lbl, "…", "neutral")
        row2.addWidget(self.udp_card)
        lay.addLayout(row2)

        hint = QLabel(
            "Доступно = ответило >= 80% сайтов зоны. Скорость — многопоточная "
            "загрузка, пинг — минимальный TCP-RTT.")
        hint.setStyleSheet("color: #757575;")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        lay.addStretch()

    def _build_summary_tab(self):
        w = QWidget()
        self.tabs.addTab(w, "Сводка")
        lay = QVBoxLayout(w)
        self.findings_scroll = QScrollArea()
        self.findings_scroll.setWidgetResizable(True)
        self.findings_container = QWidget()
        self.findings_lay = QVBoxLayout(self.findings_container)
        self.findings_lay.setSpacing(6)
        self.findings_lay.setContentsMargins(4, 4, 4, 4)
        self.findings_scroll.setWidget(self.findings_container)
        lay.addWidget(self.findings_scroll)

    def _build_system_tab(self):
        """Подменю: слева список секций, справа содержимое."""
        w = QWidget()
        self.tabs.addTab(w, "Система")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 4, 0, 0)
        self.sys_list = QListWidget()
        self.sys_list.setFixedWidth(190)
        self.sys_stack = QStackedWidget()
        lay.addWidget(self.sys_list)
        lay.addWidget(self.sys_stack)

        # онлайн-детали
        online_page = QWidget()
        ol = QVBoxLayout(online_page)
        ol.setContentsMargins(4, 4, 4, 4)
        self.online_table = QTableWidget(0, 6)
        self.online_table.setHorizontalHeaderLabels(
            ["Проверка", "Цель", "DNS", "TCP 443", "HTTP (прокси)",
             "HTTP (напрямую)"])
        self.online_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch)
        self.online_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.online_table.setAlternatingRowColors(True)
        ol.addWidget(self.online_table)
        self.sys_list.addItem("Онлайн (детально)")
        self.sys_stack.addWidget(online_page)

        # системные секции
        self.section_pages = {}
        self._section_built = {}
        for title, _fn in nu.SECTIONS:
            page = QWidget()
            self.section_pages[title] = page
            self.sys_list.addItem(title)
            self.sys_stack.addWidget(page)
        self.sys_list.currentRowChanged.connect(self._on_sys_select)

    def _on_sys_select(self, idx):
        self.sys_stack.setCurrentIndex(idx)
        if idx > 0:
            item = self.sys_list.item(idx)
            title = item.text() if item else None
            if title and not self._section_built.get(title):
                self._build_section(title)
                self._section_built[title] = True

    # ------------------------------------------------------------- refresh
    def refresh_all(self):
        if getattr(self, "_collect_running", False):
            return
        self._collect_running = True
        self._collect_result = None
        self.status_lbl_text("Проверка (конфигурация + онлайн)…")
        threading.Thread(target=self._collect_worker, daemon=True).start()

    def _collect_worker(self):
        try:
            self._collect_result = nu.collect_all()
        except Exception:  # noqa: BLE001
            self._collect_result = ({}, [])

    def _apply_collect(self):
        self._collect_running = False
        data, findings = self._collect_result or ({}, [])
        self._collect_result = None
        self.data = data
        self.findings = findings
        self._render_findings()
        self._render_sections()
        self._populate_status()
        self._start_dns_check()
        self.start_online()  # онлайн-проверка запускается сразу

    def status_lbl_text(self, text):
        self.status_lbl.setText(text)

    # ------------------------------------------------------------- findings
    def _render_findings(self):
        while self.findings_lay.count():
            it = self.findings_lay.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        if not self.findings:
            self.findings_lay.addWidget(
                self._finding_row("ok", "✅", "Явных проблем не обнаружено."))
        else:
            icon = {"error": "❌", "warn": "⚠️", "info": "ℹ️"}
            for sev, msg in self.findings:
                self.findings_lay.addWidget(
                    self._finding_row(sev, icon.get(sev, "•"), msg))
        tip = QLabel("💡 Подсказки")
        tip.setObjectName("muted")
        tip.setStyleSheet("font-weight: 700; margin-top: 10px;")
        self.findings_lay.addWidget(tip)
        for hint in (
            "Маршрут в туннель при выключенном VPN — подними метрику адаптера.",
            "Сломанный Winsock: netsh winsock reset + перезагрузка.",
            "Мусорные TUN/TAP — удали в Диспетчере устройств (показать скрытые).",
            "Остаточный прокси — Параметры → Сеть → Прокси.",
            "DNS: ipconfig /flushdns, проверь NRPT и DoH.",
            "MTU при обрывах: 1400–1420 на туннельном адаптере.",
        ):
            lbl = QLabel("• " + hint)
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color: #8a9099; font-size: 12px;")
            self.findings_lay.addWidget(lbl)
        self.findings_lay.addStretch()

    def _finding_row(self, sev, icon, msg):
        color = {"ok": "#66bb6a", "error": "#ef5350", "bad": "#ef5350",
                 "warn": "#ffa726", "info": "#4fc3f7"}.get(sev, "#607d8b")
        f = QFrame()
        f.setStyleSheet(
            f"QFrame {{ background: #1c1f24; border-radius: 8px;"
            f" border-left: 3px solid {color}; }}")
        h = QHBoxLayout(f)
        h.setContentsMargins(10, 8, 12, 8)
        h.setSpacing(8)
        ic = QLabel(icon)
        ic.setStyleSheet("font-size: 15px;")
        h.addWidget(ic)
        lbl = QLabel(msg)
        lbl.setWordWrap(True)
        lbl.setObjectName("valText")
        h.addWidget(lbl, 1)
        return f

    # ------------------------------------------------------------- sections
    def _render_sections(self):
        """Лениво: при новом сборе только сбрасываем секции и строим
        выбранную. Остальные построятся при открытии (иначе UI замирает)."""
        for title, _fn in nu.SECTIONS:
            self._section_built[title] = False
            w = self.section_pages[title]
            while w.layout() and w.layout().count():
                item = w.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
        idx = self.sys_list.currentRow()
        if idx > 0:
            item = self.sys_list.item(idx)
            title = item.text() if item else None
            if title and not self._section_built.get(title):
                self._build_section(title)
                self._section_built[title] = True

    def _build_section(self, title):
        w = self.section_pages[title]
        lay = w.layout() or QVBoxLayout(w)
        lay.setContentsMargins(6, 6, 6, 6)
        sec = self.data.get(title, {}) if hasattr(self, "data") else {}
        tables = sec.get("tables", [])
        text = sec.get("text")
        if not tables and not text:
            empty = QLabel("— нет данных —")
            empty.setStyleSheet("color: #607d8b; font-size: 13px;"
                                " padding: 24px;")
            empty.setAlignment(Qt.AlignCenter)
            lay.addWidget(empty)
        for tbl in tables:
            name = QLabel(tbl.get("name", ""))
            name.setObjectName("muted")
            name.setStyleSheet("font-weight: 700; margin-top: 6px;")
            lay.addWidget(name)
            table = self._make_table(tbl.get("columns", []),
                                     tbl.get("rows", []))
            lay.addWidget(table)
        if text:
            te = QTextEdit()
            te.setReadOnly(True)
            te.setPlainText(text)
            te.setMaximumHeight(220)
            lay.addWidget(te)
        lay.addStretch()

    def _make_table(self, columns, rows):
        t = QTableWidget(len(rows), len(columns))
        t.setHorizontalHeaderLabels(columns)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                it = QTableWidgetItem(str(val))
                t.setItem(r, c, it)
        return t

    # ------------------------------------------------------------- status
    def _populate_status(self):
        items = {}
        for item in nu.determine_status(self.data):
            items[item["id"]] = item
        for sid, lbl in (("dns_live", "DNS (напрямую)"),
                         ("resolver", "DNS-резолвер"),
                         ("split_dns", "Split DNS"),
                         ("censorship", "DNS-фильтрация"),
                         ("vpn_quality", "VPN-качество"),
                         ("split", "Split-tunneling"),
                         ("diagnosis", "Диагноз VPN")):
            items[sid] = {"id": sid, "label": lbl, "value": "проверяется…",
                          "severity": "neutral"}
        self.status_items = items
        for sid, item in items.items():
            entry = self.status_rows.get(sid)
            if entry:
                card, lbl = entry
                card.set_row(lbl, item["value"], item["severity"])
        self._update_dns_visibility()
        self._update_summary()

    def _set_status(self, sid, text, severity):
        if sid not in self.status_items:
            self.status_items[sid] = {}
        self.status_items[sid]["value"] = text
        self.status_items[sid]["severity"] = severity
        entry = self.status_rows.get(sid)
        if entry:
            card, lbl = entry
            card.set_row(lbl, text, severity)
        self._update_dns_visibility()
        self._update_summary()

    def _update_dns_visibility(self):
        """DNS-карточка всегда видна."""
        if hasattr(self, "dns_card"):
            self.dns_card.setVisible(True)

    def _update_summary(self):
        items = []
        worst = "ok"

        def _bump(sev):
            nonlocal worst
            if sev == "bad":
                worst = "bad"
            elif sev == "warn" and worst == "ok":
                worst = "warn"

        # зоны доступности (оцениваем после онлайн-проверки)
        if self.online_done:
            for z, st in self.zone_state.items():
                _s, sev = nu.zone_status(st["ok"], st["total"])
                zname = {"RU": "RU", "Зарубежные": "Зарубежные",
                         "Заблокированные": "Заблокированные"}.get(z, z)
                items.append(("Зона %s" % zname,
                              "%d/%d" % (st["ok"], st["total"]), sev))
                _bump(sev)

        for sid, item in self.status_items.items():
            sev = item.get("severity", "neutral")
            if sev not in ("ok", "warn", "bad"):
                continue
            if sid == "vpn_quality" and item.get("value") == "VPN выключен":
                continue  # не проблема, просто VPN не активен
            if sid in self.DNS_SIDS and sev == "ok":
                continue  # DNS молчит, пока всё в порядке
            if sid == "winsock" and sev == "ok":
                continue  # Winsock показываем только при проблеме
            items.append((item.get("label", sid), item.get("value", ""), sev))
            _bump(sev)

        # сначала проблемы, потом предупреждения, потом ОК
        order = {"bad": 0, "warn": 1, "ok": 2}
        items.sort(key=lambda x: order.get(x[2], 3))

        # пока проверка не завершена — не показываем негативный вердикт,
        # чтобы статус не прыгал («НЕ ОК» -> «ОК»)
        if not self.online_done:
            self.summary_card.set_status("pending", items)
        elif worst == "ok":
            self.summary_card.set_status("ok", items)
        else:
            self.summary_card.set_status(worst, items)

    # ------------------------------------------------------------- checks
    def _start_dns_check(self):
        self._dns_result = None
        self._split_dns_result = None

        def worker():
            self._dns_result = nu.dns_analysis()

        def worker2():
            try:
                self._split_dns_result = nu.split_dns_check()
            except Exception:  # noqa: BLE001
                self._split_dns_result = {"value": "ошибка проверки",
                                          "severity": "neutral"}

        threading.Thread(target=worker, daemon=True).start()
        threading.Thread(target=worker2, daemon=True).start()

    def _apply_dns_result(self, res):
        d = res.get("direct", {})
        self._set_status("dns_live", d.get("value", "?"),
                         "ok" if d.get("state") == "ok" else "bad")
        g = res.get("resolver_geo")
        entry = self.status_rows.get("resolver")
        if g and g.get("country"):
            prov = (g.get("org") or "").split(" ")[0]
            self._set_status("resolver", f"{g['country']} · {prov}", "ok")
            if entry:
                entry[0].set_flag(entry[1], g.get("country_code")
                                  or g.get("country", ""))
        else:
            if res.get("whoami"):
                self._set_status("resolver", "определён (без гео)", "neutral")
            else:
                self._set_status("resolver", "не определён", "neutral")
            if entry:
                entry[0].set_flag(entry[1], "")
        c = res.get("censorship", {})
        self._set_status("censorship", c.get("value", "?"),
                         "ok" if c.get("state") == "clean" else "bad")

    def _update_vpn_quality(self):
        vpn_item = self.status_items.get("vpn")
        vpn_active = bool(vpn_item and vpn_item.get("value") == "Активен")
        if not vpn_active:
            self._set_status("vpn_quality", "VPN выключен", "neutral")
            return
        val, sev = nu.vpn_quality_verdict(self.zone_state)
        self._set_status("vpn_quality", val, sev)

    def _update_diagnosis(self):
        vpn_item = self.status_items.get("vpn")
        vpn_active = bool(vpn_item and vpn_item.get("value") == "Активен")
        diag = nu.vpn_diagnosis(self.zone_state, vpn_active)
        if diag:
            self._set_status("diagnosis", diag["value"], diag.get("severity",
                                                                 "bad"))
        else:
            self._set_status("diagnosis", "В норме", "ok")

    # ------------------------------------------------------------- zones
    def _update_zone(self, zone):
        st = self.zone_state.get(zone)
        zc = self.zone_cards.get(zone)
        if not st or not zc:
            return
        total, ok = st["total"], st["ok"]
        status, sev = nu.zone_status(ok, total)
        zc._set_status(status, sev)

        # пинг: среднее с отсевом выбросов (IQR)
        avg = filtered_avg(st["lats"])
        if avg is not None:
            psev = "ok" if avg < 150 else ("warn" if avg < 350 else "bad")
            zc.set_param("Пинг", "%d мс" % round(avg), psev)
            zc.spark.add(avg)
            lats = st["lats"]
            zc.spark_cap.setText("📈 пинг, мс · %.0f–%.0f" % (min(lats),
                                                               max(lats)))
        else:
            zc.set_param("Пинг", "—", "neutral")
            zc.spark_cap.setText("📈 пинг, мс")

        # DNS: среднее время резолва по сайтам зоны
        dns_vals = st.get("dns_ms") or []
        if dns_vals:
            d_avg = filtered_avg(dns_vals)
            dsev = "ok" if d_avg < 100 else ("warn" if d_avg < 300 else "bad")
            zc.set_param("DNS", "%d мс" % round(d_avg), dsev)
        else:
            zc.set_param("DNS", "—", "neutral")

        # скорость
        if st.get("speed_ok"):
            mbps = float(st["speed"] or 0)
            ssev = "ok" if mbps >= 15 else ("warn" if mbps >= 5 else "bad")
            zc.set_param("Скорость", "%.0f Мбит/с" % mbps, ssev)
            hist = zc.spark_speed.values
            if hist:
                zc.spark_speed_cap.setText(
                    "📶 скорость, Мбит/с · %.0f–%.0f" % (min(hist), max(hist)))
            else:
                zc.spark_speed_cap.setText("📶 скорость, Мбит/с")
        elif st.get("speed") is not None:
            zc.set_param("Скорость", "нет", "bad")
            zc.spark_speed_cap.setText("📶 скорость, Мбит/с")
        else:
            zc.set_param("Скорость", "…", "neutral")
            zc.spark_speed_cap.setText("📶 скорость, Мбит/с")

        # сайты + прогресс-бар
        if total:
            pct = int(ok * 100 / total)
            zc.bar.setValue(pct)
            zc.set_param("Сайтов", "%d/%d" % (ok, total), sev)
        else:
            zc.bar.setValue(0)
            zc.set_param("Сайтов", "—", "neutral")

    def _reset_zones(self):
        self.chart_cells = {z: [] for z in nu.ZONES}
        for z in nu.ZONES:
            self.zone_state[z] = {"total": len(nu.ZONE_SITES[z]), "ok": 0,
                                  "lats": [], "dns_ms": [],
                                  "speed": None, "speed_ok": False}
            zc = self.zone_cards.get(z)
            if zc:
                zc.total = len(nu.ZONE_SITES[z])
                zc.egress.setText("IP: …")
                zc.egress_flag.hide()
                self._update_zone(z)
        for lbl in ("В РФ", "Наружу", "Заблокированные"):
            self.ip_card.set_row(lbl, "…", "neutral")
        if hasattr(self, "udp_card"):
            for lbl in ("RU", "Зарубежные"):
                self.udp_card.set_row(lbl, "…", "neutral")

    def _update_progress(self, phase=None):
        if not hasattr(self, "chart_cells"):
            self.chart_cells = {z: [] for z in nu.ZONES}
        done = sum(len(v) for v in self.chart_cells.values())
        total = sum(len(nu.ZONE_SITES[z]) for z in nu.ZONES)
        parts = []
        for z in nu.ZONES:
            cl = self.chart_cells.get(z) or []
            ok = sum(1 for c in cl if c is True)
            parts.append("%s %d/%d" % (z, ok, len(cl)))
        if hasattr(self, "summary_card"):
            self.summary_card.set_progress(done, total, "  ·  ".join(parts))

    # ------------------------------------------------------------- online
    def start_online(self):
        if self.runner and self.runner.is_alive():
            return
        self.online_done = False
        self.online_table.setRowCount(0)
        self.online_data = {}
        self._reset_zones()
        self._set_status("vpn_quality", "проверяется…", "neutral")
        self._set_status("split", "проверяется…", "neutral")
        self.btn_refresh.setEnabled(False)
        self.btn_refresh.setText("⏳ Проверка…")
        self.activity.show()
        self._update_progress()
        self.runner = nu.OnlineRunner(self.queue)
        self.runner.start()

    def _poll(self):
        # очередь OnlineRunner
        try:
            while True:
                kind, key, res = self.queue.get_nowait()
                if kind == "site":
                    self._handle_site(key, res)
                elif kind == "dns":
                    self._handle_dns(key, res)
                elif kind == "gateway":
                    self._handle_gateway(key, res)
                elif kind == "speed":
                    self._handle_speed(key, res)
                elif kind == "udp":
                    self._handle_udp(key, res)
                elif kind == "ip":
                    self._handle_ip(res)
                elif kind == "done":
                    self.online_done = True
                    self.btn_refresh.setEnabled(True)
                    self.btn_refresh.setText("▶ Проверить всё")
                    self.activity.hide()
                    done = sum(len(v) for v in
                               getattr(self, "chart_cells", {}).values())
                    total = sum(len(nu.ZONE_SITES[z]) for z in nu.ZONES)
                    self.summary_card.finish_check(
                        "✅ Проверка завершена в %s · %d/%d сайтов"
                        % (time.strftime("%H:%M:%S"), done, total))
                    self.status_lbl_text("Готово · " + time.strftime("%H:%M:%S"))
                    self._update_diagnosis()
                    self._update_summary()
        except queue.Empty:
            pass
        # фоновые проверки
        if getattr(self, "_collect_result", None) is not None:
            self._apply_collect()
        if self._dns_result is not None:
            self._apply_dns_result(self._dns_result)
            self._dns_result = None
        if getattr(self, "_split_dns_result", None) is not None:
            r = self._split_dns_result
            self._set_status("split_dns", r.get("value", "?"),
                             r.get("severity", "neutral"))
            self._split_dns_result = None
        if self._monitor_result is not None:
            self._apply_monitor_result(self._monitor_result)
            self._monitor_result = None

    def _handle_site(self, group, res):
        dns = res.get("dns", {})
        tcp = res.get("tcp", {})
        http = res.get("http", {})
        http_d = res.get("http_direct", {})

        dns_cell = (", ".join(dns.get("ips", []))[:26] if dns.get("ok")
                    else "✗ " + dns.get("error", "")[:22])
        tcp_cell = (f"ok {tcp.get('rtt_ms')}мс" if tcp.get("ok")
                    else "✗ " + tcp.get("error", "")[:22])
        http_cell = (f"{http.get('status')} · {http.get('rtt_ms')}мс"
                     if http.get("ok")
                     else ("SSL серт (Минцифры?)" if http.get("ssl_error")
                           else "✗ " + http.get("error", "")[:22]))
        http_d_cell = (f"{http_d.get('status')} · {http_d.get('rtt_ms')}мс"
                       if http_d.get("ok")
                       else ("SSL серт (Минцифры?)" if http_d.get("ssl_error")
                             else "✗ " + http_d.get("error", "")[:22]))

        reachable = nu.site_reachable(res, group)
        row = self.online_table.rowCount()
        self.online_table.insertRow(row)
        cells = [f"[{group}] {res.get('name')}", res.get("host"), dns_cell,
                 tcp_cell, http_cell, http_d_cell]
        for c, val in enumerate(cells):
            it = QTableWidgetItem(val)
            if c in (2, 3, 4, 5):
                if val.startswith("ok"):
                    it.setForeground(QColor("#66bb6a"))
                elif "SSL" in val:
                    it.setForeground(QColor("#ffa726"))
                else:
                    it.setForeground(QColor("#ef5350"))
            self.online_table.setItem(row, c, it)

        st = self.zone_state.get(group)
        if st:
            dns_rtt = dns.get("rtt_ms")
            if dns.get("ok") and dns_rtt is not None:
                st.setdefault("dns_ms", []).append(dns_rtt)
            if reachable:
                st["ok"] += 1
                rtt = tcp.get("rtt_ms")  # честный TCP-пинг (RTT)
                if rtt:
                    st["lats"].append(rtt)
            self._update_zone(group)
            if not hasattr(self, "chart_cells"):
                self.chart_cells = {z: [] for z in nu.ZONES}
            self.chart_cells.setdefault(group, []).append(reachable)
            self._update_progress()

    def _handle_dns(self, label, res):
        cell = ""
        if res.get("ok"):
            ips = ", ".join(res.get("ips", []))[:20]
            cell = f"ok {res.get('rtt_ms')}мс {ips}"
        else:
            cell = "✗ " + res.get("error", "")[:26]
        row = self.online_table.rowCount()
        self.online_table.insertRow(row)
        for c, val in enumerate([f"[DNS] {label}", res.get("server", ""),
                                 cell, "", "", ""]):
            it = QTableWidgetItem(val)
            self.online_table.setItem(row, c, it)

    def _handle_gateway(self, gw, res):
        cell = (f"ok {res.get('rtt_ms')}мс" if res.get("ok")
                else "✗ " + res.get("error", ""))
        row = self.online_table.rowCount()
        self.online_table.insertRow(row)
        for c, val in enumerate(["[Шлюз]", gw, cell, "", "", ""]):
            self.online_table.setItem(row, c, QTableWidgetItem(val))

    def _handle_speed(self, zone, res):
        st = self.zone_state.get(zone)
        if not st:
            return
        if res.get("ok"):
            st["speed"] = res.get("mbps")
            st["speed_ok"] = True
        else:
            st["speed"] = res.get("error", "?")
            st["speed_ok"] = False
        self._update_zone(zone)
        zc = self.zone_cards.get(zone)
        if zc and st.get("speed_ok") and st.get("speed") is not None:
            zc.spark_speed.add(float(st["speed"]))
        self._update_vpn_quality()

    def _handle_udp(self, zone, res):
        if not hasattr(self, "udp_card"):
            return
        if not res.get("ok"):
            self.udp_card.set_row(zone, res.get("error", "нет ответа"), "bad")
            return
        rtt = res.get("rtt_ms")
        loss = res.get("loss", 100.0)
        ports = res.get("ports") or []
        ports_s = ", ".join(str(p) for p in ports)
        if loss > 25:
            sev = "bad"
        elif loss > 0 or rtt > 150:
            sev = "warn"
        else:
            sev = "ok"
        self.udp_card.set_row(zone, "%d мс · потери %d%% · порты %s"
                              % (round(rtt), round(loss), ports_s), sev)

    def _handle_ip(self, info):
        for z in nu.ZONES:
            d = info.get(z) or {}
            zc = self.zone_cards.get(z)
            if not zc:
                continue
            ip = d.get("ip")
            geo = d.get("geo") or {}
            cc = geo.get("country_code") or geo.get("country", "")
            if ip and geo.get("country"):
                zc.egress.setText(f"{ip} · {geo['country']}")
                zc.egress_flag.setPixmap(flag_icon(cc))
                zc.egress_flag.show()
            elif ip:
                zc.egress.setText(ip)
                zc.egress_flag.hide()
            else:
                zc.egress.setText("не определён")
                zc.egress_flag.hide()

        # карточка IP-адресов: В РФ / Наружу / Заблокированные
        ru_d = info.get("RU") or {}
        fo_d = info.get("Зарубежные") or {}
        bl_d = info.get("Заблокированные") or {}

        def fmt(d):
            ip = d.get("ip")
            geo = d.get("geo") or {}
            if ip and geo.get("country"):
                return f"{ip} · {geo['country']}"
            return ip or "—"

        for row, d in (("В РФ", ru_d), ("Наружу", fo_d),
                       ("Заблокированные", bl_d)):
            self.ip_card.set_row(row, fmt(d), "neutral")
            geo = d.get("geo") or {}
            self.ip_card.set_flag(
                row, geo.get("country_code") or geo.get("country", ""))

        zone_ips = {z: (info.get(z) or {}).get("ip") for z in nu.ZONES}
        egress = {z: (info.get(z) or {}).get("egress") for z in nu.ZONES}
        vpn_item = self.status_items.get("vpn")
        vpn_active = bool(vpn_item and vpn_item.get("value") == "Активен")
        val, sev = nu.split_tunneling_status(zone_ips, vpn_active, egress)
        self._set_status("split", val, sev)

    # ------------------------------------------------------------- tray + monitor
    def _apply_theme(self):
        app = QApplication.instance()
        app.setStyleSheet(build_qss(self.current_accent, self.dark))
        self.setWindowIcon(self._make_icon(self.current_accent))
        for zc in self.zone_cards.values():
            zc.spark.color = self.current_accent

    def _set_accent(self, color):
        self.current_accent = color
        self._apply_theme()

    def _toggle_theme(self):
        self.dark = not self.dark
        self.btn_mode.setText("🌙" if self.dark else "☀️")
        self._apply_theme()

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self._make_icon("#757575"))
        self.tray.setToolTip("NetUtil")
        menu = QMenu()
        act_show = menu.addAction("Открыть NetUtil")
        act_show.triggered.connect(self.show_normal)
        act_quit = menu.addAction("Выйти")
        act_quit.triggered.connect(self._quit_app)
        self.tray.setContextMenu(menu)
        self.tray.show()

    def show_normal(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _quit_app(self):
        self._shutdown()
        QApplication.instance().quit()

    def _shutdown(self):
        for tmr in ("monitor_timer", "ui_timer", "timer"):
            try:
                getattr(self, tmr).stop()
            except Exception:  # noqa: BLE001
                pass
        if self.runner is not None:
            try:
                self.runner.stop()
                self.runner.join(timeout=8)
            except Exception:  # noqa: BLE001
                pass
        self.tray.hide()

    def _fade_in(self):
        try:
            anim = QPropertyAnimation(self, b"windowOpacity", self)
            anim.setDuration(420)
            anim.setStartValue(0.45)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.OutCubic)
            anim.start()
            self._fade_anim = anim
        except Exception:  # noqa: BLE001
            self.setWindowOpacity(1.0)

    def closeEvent(self, e):
        # сворачиваем в трей, а не выходим
        e.ignore()
        self.hide()
        try:
            self.tray.showMessage("NetUtil", "Свёрнуто в трей — "
                                  "утилита продолжает следить за туннелем.",
                                  QSystemTrayIcon.Information, 3000)
        except Exception:  # noqa: BLE001
            pass

    def _make_icon(self, color):
        pm = QPixmap(32, 32)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(3, 3, 26, 26)
        p.end()
        return QIcon(pm)

    def _start_monitor(self):
        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self._monitor_tick)
        self.monitor_timer.start(60000)
        self._monitor_next = time.time() + 60
        self.monitor_card.btn.setText("Пауза")
        self._monitor_tick()

    def _toggle_monitor_btn(self):
        self.auto_cb.setChecked(not self.auto_cb.isChecked())

    def _toggle_monitor(self, checked):
        if checked:
            self._start_monitor()
        else:
            self.monitor_timer.stop()
            self._monitor_state = None
            self.tray.setIcon(self._make_icon("#757575"))
            self.tray.setToolTip("NetUtil — мониторинг выключен")
            self.monitor_dot.setStyleSheet("color: #757575; font-size: 10px;")
            self.monitor_lbl.setText("мониторинг выключен")
            self.monitor_lbl.setStyleSheet("color: #607d8b; font-size: 12px;")
            self.monitor_card.set_off()
            self.monitor_card.btn.setText("Включить")

    def _monitor_tick(self):
        self._monitor_next = time.time() + 60
        if self._monitor_result is None:
            threading.Thread(target=self._monitor_worker, daemon=True).start()

    def _update_monitor_countdown(self):
        if not self.auto_cb.isChecked():
            return
        left = max(0, int(self._monitor_next - time.time()))
        self.monitor_card.next_bar.setValue(int((60 - left) / 60 * 100))
        self.monitor_card.next_lbl.setText("следующая через %d с" % left)

    def _monitor_worker(self):
        self._monitor_result = self._monitor_once()

    def _monitor_once(self):
        """Градуированная проверка: DNS+пинг, скорость — только при сомнениях."""
        r = monitor_probe()
        state = r["state"]
        checks = list(r["checks"])
        if state != "suspect":
            return {"state": state, "checks": checks, "detail": r["detail"]}
        # скорость не чаще раза в 5 минут
        if time.time() - self._last_speed_time < 300:
            checks.append(("Скорость", "не мерили (пауза)", "neutral"))
            return {"state": state, "checks": checks, "detail": r["detail"]}
        self._last_speed_time = time.time()
        sp = nu.speed_test(nu.SPEED_ENDPOINTS["Зарубежные"])
        if sp.get("ok") and sp.get("mbps", 0) >= 5.0:
            checks.append(("Скорость", "%.0f Мбит/с" % sp["mbps"], "ok"))
            return {"state": "ok", "checks": checks,
                    "detail": "%s, скорость %.1f Мбит/с"
                              % (r["detail"], sp["mbps"])}
        checks.append(("Скорость", "низкая", "bad"))
        return {"state": "bad", "checks": checks,
                "detail": "туннель нестабилен (%s)" % r["detail"]}

    def _apply_monitor_result(self, res):
        state = res.get("state", "off")
        detail = res.get("detail", "")
        checks = res.get("checks") or []
        prev = self._monitor_state
        color = {"off": "#757575", "ok": "#66bb6a", "bad": "#ef5350",
                 "suspect": "#ffa726"}.get(state, "#757575")
        self.tray.setIcon(self._make_icon(color))
        self.tray.setToolTip("NetUtil — %s: %s" % (state, detail))
        labels = {"off": "VPN выключен", "ok": "туннель в норме",
                  "suspect": "есть сомнения", "bad": "туннель нестабилен"}
        self.monitor_dot.setStyleSheet("color: %s; font-size: 10px;" % color)
        self.monitor_lbl.setText(labels.get(state, "мониторинг"))
        self.monitor_lbl.setStyleSheet("color: %s; font-size: 12px;" % color)
        self.monitor_card.set_state(state, checks, detail)
        if state == "bad" and prev != "bad":
            self.tray.showMessage(
                "NetUtil", "⚠️ Туннель нестабилен: %s" % detail,
                QSystemTrayIcon.Warning, 6000)
        self._monitor_state = state
        # VPN включили -> перезапускаем полную проверку
        if prev == "off" and state in ("ok", "suspect", "bad"):
            self.status_lbl_text("VPN включён — запускаю полную проверку…")
            self.refresh_all()

    # ------------------------------------------------------------- export
    def edit_site_lists(self):
        dlg = SiteListDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.values()
        if any(not v for v in data.values()):
            self.status_lbl_text("Пустой список зоны — изменения не сохранены")
            return
        if not nu.save_site_lists(data):
            self.status_lbl_text("Не удалось записать sites.json")
            return
        nu.reload_site_lists()
        for z in nu.ZONES:
            zc = self.zone_cards.get(z)
            if zc:
                zc.total = len(nu.ZONE_SITES[z])
        self.status_lbl_text(
            "Списки сохранены (%s) · запускаю проверку"
            % ", ".join("%s: %d" % (z, len(nu.ZONE_SITES[z]))
                        for z in nu.ZONES))
        self.start_online()

    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить отчёт", "netutil-report.json",
            "JSON (*.json);;Все файлы (*.*)")
        if not path:
            return
        nu.export_report(path, self.data, self.findings, self.online_data)
        self.setWindowTitle(f"NetUtil — отчёт сохранён: {path}")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetUtil")
    app.setStyle("Fusion")
    app.setStyleSheet(build_qss(ACCENT_COLORS["Бирюзовый"]))
    win = NetUtilQt()
    win.show()
    win._fade_in()
    code = app.exec()
    win._shutdown()
    sys.exit(code)


if __name__ == "__main__":
    main()
