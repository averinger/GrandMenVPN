# -*- coding: utf-8 -*-
"""
GrandMenVPN — клиент для sing-box (VLESS/VMess/Trojan/SS/Hysteria2/TUIC) и AmneziaWG (WARP).

Требования:
    pip install customtkinter requests[socks]
    Рядом со скриптом/exe (или внутри PyInstaller-сборки) должны лежать:
        sing-box.exe (версии 1.12 или новее)
        amneziawg-go.exe, awg.exe, wintun.dll (x64), nssm.exe   — для AmneziaWG/WARP
"""
import customtkinter as ctk
from tkinter import messagebox, filedialog
import json
import subprocess
import urllib.parse
import os
import sys
import threading
import time
import socket
import requests
import concurrent.futures
import ipaddress
import base64
import random
import tempfile
import webbrowser
import ctypes
import re
import shutil

# ============ 1. ПУТИ И ПРАВА АДМИНИСТРАТОРА ============
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


if sys.platform != "win32":
    print("GrandMenVPN работает только в Windows.")
    sys.exit(1)

if not is_admin():
    if getattr(sys, "frozen", False):
        _args = sys.argv[1:]
    else:
        _args = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, subprocess.list2cmdline(_args), None, 1)
    sys.exit()

# после повышения прав рабочая папка может оказаться System32 — фиксируем её
os.chdir(BASE_DIR)

try:
    import socks  # noqa: F401  (PySocks нужен requests для socks5)
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# ============ 2. КОНСТАНТЫ И СОСТОЯНИЕ ============
NO_WINDOW = subprocess.CREATE_NO_WINDOW
DEVNULL = subprocess.DEVNULL

CONFIG_FILE = os.path.join(BASE_DIR, "saved_config.txt")
SINGBOX_CONFIG = os.path.join(BASE_DIR, "config.json")
SINGBOX_LOG = os.path.join(BASE_DIR, "singbox_debug.log")
AWG_LOG = os.path.join(BASE_DIR, "awg_service.log")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.txt")
RU_CIDR_FILE = os.path.join(BASE_DIR, "ru-cidr.txt")      # кеш списка RU-подсетей
SPLIT_STATE_FILE = os.path.join(BASE_DIR, "ru-routes-applied.txt")  # какие маршруты добавили
SPLIT_FLAG_FILE = os.path.join(BASE_DIR, "split_direct.txt")        # вкл/выкл авто-сплит
RU_CIDR_URLS = [
    "https://ipdeny.com/ips/ru/",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/country/ru",
    "https://raw.githubusercontent.com/4skinSkywalker/anti-ru/main/geoip.txt",
]
WARP_SITE_URL = "https://warp-ru.duckdns.org/"
SERVICE_NAME = "AmneziaWG_Go_Client"
AWG_IFACE = "wg0"

# --- hosts-файл: через него закрепляем IP белых сайтов в режиме WARP/AmneziaWG ---
HOSTS_FILE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "drivers", "etc", "hosts")
HOSTS_BEGIN = "# >>> GrandMenVPN whitelist >>>"
HOSTS_END = "# <<< GrandMenVPN whitelist <<<"

# --- внешние бинарники: в onefile-сборке они лежат во временной папке %TEMP%,
#     а sing-box 1.12+ отказывается стартовать elevated из такой папки
#     ("must not be writable by a non-administrative principal").
#     Поэтому распаковываем их в защищённый каталог и запускаем оттуда. ---
STAGE_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "GrandMenVPN")
STAGE_BIN_DIR = os.path.join(STAGE_DIR, "bin")
EXTERNAL_BINARIES = ("sing-box.exe", "amneziawg-go.exe", "awg.exe", "wintun.dll", "nssm.exe")
# официальный бинарный rule-set с российскими подсетями (SagerNet/sing-geoip)
RU_RULESET_FILE = "geoip-ru.srs"

# Российские домены, которые не покрываются ccTLD (.ru/.рф/.su)
RU_DOMAINS = [
    "vk.com", "vk.ru", "yandex.com", "yandex.ru", "ya.ru", "mail.ru", "rambler.ru", "rambler.ru",
    "list.ru", "bk.ru", "inbox.ru", "internet.ru", "rambler.ru", "autorambler.ru", "lenta.ru",
    "gazeta.ru", "rbc.ru", "ria.ru", "tass.ru", "kommersant.ru", "vc.ru", "habr.com", "pikabu.ru",
    "otzovik.com", "irecommend.ru", "wildberries.ru", "ozon.ru", "avito.ru", "drom.ru",
    "sber.ru", "sberbank.ru", "tbank.ru", "tinkoff.ru", "alfabank.ru", "vtb.ru", "gazprombank.ru",
    "gosuslugi.ru", "nalog.ru", "gosuslugi.ru", "rossiya.ru", "russian federation",
    "megafon.ru", "mts.ru", "beeline.ru", "tele2.ru", "rostelecom.ru", "dom.ru", "er-telecom.ru",
    "rt.ru", "ru.mail.ru", "dzen.ru", "zen.yandex.ru", "cloudmail.ru", "yandex.net",
]
RU_DOMAIN_SUFFIXES = [".ru", ".рф", ".su", ".moscow", ".xn--p1ai"]

MAX_CANDIDATES = 300   # сколько ссылок пингуем
MAX_PING_MS = 600      # отсев по TCP-пингу
CHECK_LIMIT = 30       # сколько лучших по пингу проверяем реально
CHECK_WORKERS = 6
WANT_GOOD = 10         # останавливаемся, когда нашли столько рабочих

IP_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com")

GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/srgvsky/goida/main/sub/all.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/1.txt",
]

sing_box_process = None
sing_box_log = None
vpn_mode = None          # None | "singbox" | "awg"
vpn_connected = False
vpn_busy = False
awg_endpoint_ip = None
whitelist_route_ips = []      # IP-адреса, добавленные в обход туннеля
is_scanning = False
best_server_link = None
original_ip = ""
connection_time = 0
timer_job = None

target_progress = 0.0
current_progress = 0.0
trans_y = 0.0
loading_done = False


# ============ 3. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============
def get_resource_path(filename):
    """Ищем файл сначала в staging-папке, потом внутри PyInstaller-сборки, потом рядом с программой."""
    if filename in EXTERNAL_BINARIES and os.path.isdir(STAGE_BIN_DIR):
        staged = os.path.join(STAGE_BIN_DIR, filename)
        if os.path.exists(staged):
            return staged
    candidates = []
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidates.append(os.path.join(sys._MEIPASS, filename))
    candidates.append(os.path.join(BASE_DIR, filename))
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[-1]


def ensure_stage_binaries():
    """
    Распаковывает внешние бинарники из onefile-сборки в %ProgramData%\\GrandMenVPN\\bin
    и закрывает ACL (писать могут только SYSTEM и Администраторы).

    Зачем: sing-box 1.12+ отказывается запускаться elevated, если его .exe лежит
    в папке, доступной на запись не-админам (а _MEIPASS в %TEMP% — именно такая).
    Плюс путь к amneziawg-go.exe из папки %TEMP% нельзя писать в службу Windows:
    после закрытия программы папка исчезнет.
    """
    if not getattr(sys, "frozen", False):
        return True                      # при запуске из исходников файлы уже на месте
    src_dir = getattr(sys, "_MEIPASS", None)
    if not src_dir:
        return False

    try:
        os.makedirs(STAGE_BIN_DIR, exist_ok=True)
    except Exception as e:
        show_error("Ошибка", f"Не удалось создать папку {STAGE_BIN_DIR}:\n{e}")
        return False

    for name in EXTERNAL_BINARIES:
        src = os.path.join(src_dir, name)
        dst = os.path.join(STAGE_BIN_DIR, name)
        if not os.path.exists(src):
            show_error("Ошибка", f"{name} не найден внутри сборки!")
            return False
        try:
            if (not os.path.exists(dst)) or os.path.getsize(dst) != os.path.getsize(src):
                shutil.copy2(src, dst)
        except Exception as e:
            show_error("Ошибка", f"Не удалось распаковать {name}:\n{e}")
            return False

    # rule-set с российскими подсетями — тоже в стабильную папку
    src_rs = os.path.join(src_dir, RU_RULESET_FILE)
    if os.path.exists(src_rs):
        try:
            shutil.copy2(src_rs, os.path.join(STAGE_BIN_DIR, RU_RULESET_FILE))
        except Exception:
            pass

    # закрываем ACL: запись — только для SYSTEM и Администраторов.
    # SID-ы используем вместо имён, чтобы не зависеть от языка Windows.
    run_cmd(["icacls", STAGE_BIN_DIR, "/inheritance:r",
             "/grant", "*S-1-5-18:(OI)(CI)F",
             "/grant", "*S-1-5-32-544:(OI)(CI)F",
             "/grant", "*S-1-5-32-545:(OI)(CI)RX"], timeout=30)
    return True


def get_ru_ruleset_path():
    """Путь к бинарному rule-set с российскими подсетями (если он есть)."""
    for p in (os.path.join(STAGE_BIN_DIR, RU_RULESET_FILE),
              get_resource_path(RU_RULESET_FILE)):
        if p and os.path.exists(p):
            return p
    return None


def check_dll_architecture(dll_path):
    if not os.path.exists(dll_path):
        return False
    try:
        with open(dll_path, "rb") as f:
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), "little")
            f.seek(pe_offset + 4)
            machine = int.from_bytes(f.read(2), "little")
            return machine in (0x8664, 0xAA64)  # x64 или ARM64
    except Exception:
        return False


def decode_output(b):
    """nssm и некоторые утилиты выводят UTF-16 — обычный decode ломает текст."""
    if not b:
        return ""
    if b"\x00" in b:
        return b.decode("utf-16", errors="ignore")
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("utf-8", errors="replace")


def run_cmd(args, timeout=30):
    """Запуск внешней команды без окна. Возвращает (код, текст)."""
    try:
        r = subprocess.run(args, capture_output=True, stdin=DEVNULL, creationflags=NO_WINDOW, timeout=timeout)
        return r.returncode, (decode_output(r.stdout) + decode_output(r.stderr)).strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


def tail_file(path, n=800):
    try:
        with open(path, "rb") as f:
            txt = decode_output(f.read())
        txt = re.sub(r"\x1b\[[0-9;]*m", "", txt)
        return txt[-n:].strip()
    except Exception:
        return ""


def ui(fn):
    """Безопасно выполнить функцию в главном потоке Tk."""
    try:
        app.after(0, fn)
    except Exception:
        pass


def show_error(title, msg):
    ui(lambda: messagebox.showerror(title, msg))


# ============ 4. АНИМАЦИЯ ============
def animate_progress():
    global current_progress
    if loading_done:
        return
    if current_progress < target_progress:
        diff = target_progress - current_progress
        current_progress += max(diff * 0.15, 0.005)
        if current_progress > target_progress:
            current_progress = target_progress
        try:
            loading_progress.set(current_progress)
        except Exception:
            pass
    app.after(16, animate_progress)


def save_config(text):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except Exception:
        return False


def load_saved_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""


def open_warp_site():
    webbrowser.open(WARP_SITE_URL)


# ============ 4. БЕЛЫЙ СПИСОК (сайты, которые работают БЕЗ VPN) ============
def normalize_domain(text):
    """Приводит пользовательский ввод к домену: без схемы, пути, порта, www."""
    s = (text or "").strip().lower()
    if not s:
        return ""
    s = re.sub(r"^[a-z]+://", "", s)          # убираем http:// https://
    s = s.split("/")[0]                       # убираем путь
    s = s.split("?")[0]
    s = s.split("#")[0]
    s = s.split("@")[-1]                      # убираем user@
    s = s.replace("*.", "")                   # *.example.com -> example.com
    if s.count(":") == 1 and s.split(":")[1].isdigit():
        s = s.split(":")[0]                   # убираем порт
    s = s.strip(".")
    if not s or " " in s or "/" in s:
        return ""
    if "." not in s and s not in ("localhost",):
        return ""                             # без точки — не домен
    if not re.match(r"^[a-zа-яё0-9.\-]+$", s, re.IGNORECASE):
        return ""
    if s.startswith("www."):
        s = s[4:]                             # www.example.com -> example.com
    return s


def load_whitelist():
    """Список доменов, которые должны открываться напрямую (без VPN)."""
    out = []
    if not os.path.exists(WHITELIST_FILE):
        return out
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                d = normalize_domain(line)
                if d and d not in out:
                    out.append(d)
    except Exception:
        pass
    return out


def save_whitelist(domains):
    try:
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            f.write("# Белый список GrandMenVPN: эти сайты открываются напрямую, без VPN.\n")
            f.write("# По одному домену на строку. Можно писать example.com или https://example.com\n")
            for d in domains:
                f.write(d + "\n")
        return True
    except Exception:
        return False


def hosts_read():
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def hosts_apply(entries):
    """Записывает наши строки в hosts-файл, заменяя только свой блок."""
    content = hosts_read()
    # вырезаем прежний блок
    if HOSTS_BEGIN in content:
        head, _, rest = content.partition(HOSTS_BEGIN)
        _, _, tail = rest.partition(HOSTS_END)
        content = head + tail
    if entries:
        lines = [HOSTS_BEGIN]
        for ip, dom in entries:
            lines.append(f"{ip}\t{dom}")
        lines.append(HOSTS_END)
        content = content.rstrip("\n") + "\n" + "\n".join(lines) + "\n"
    try:
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception:
        return False


def hosts_clear():
    """Убирает наш блок из hosts-файла."""
    content = hosts_read()
    if HOSTS_BEGIN not in content:
        return False
    head, _, rest = content.partition(HOSTS_BEGIN)
    _, _, tail = rest.partition(HOSTS_END)
    try:
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write(head + tail)
        return True
    except Exception:
        return False


def load_config_from_file():
    filetypes = [("Все конфиги", "*.conf *.txt *.json *.yaml"), ("AmneziaWG", "*.conf"),
                 ("JSON", "*.json"), ("Все файлы", "*.*")]
    path = filedialog.askopenfilename(title="Выберите файл с конфигом", filetypes=filetypes)
    if not path:
        return
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            content = f.read().strip()
        if not content:
            messagebox.showwarning("Внимание", "Файл пустой.")
            return
        link_text.delete("1.0", ctk.END)
        link_text.insert("1.0", content)
        if parse_any_config(content):
            messagebox.showinfo("Успех", "Файл загружен. Нажмите «Сохранить и подключиться».")
        else:
            messagebox.showwarning("Внимание", "Формат не распознан.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"{e}")


# >>> PARSERS BEGIN
# ============ 5. ПАРСИНГ КОНФИГОВ ============
def normalize_cidr(value):
    value = value.strip()
    if "/" in value:
        return value
    try:
        ip = ipaddress.ip_address(value)
        return f"{value}/{'128' if ip.version == 6 else '32'}"
    except ValueError:
        return value


def b64decode_any(s):
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def qv(q, key, default=""):
    v = q.get(key)
    return v[0] if v and v[0] != "" else default


def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def build_tls(q, host, security="tls"):
    tls = {
        "enabled": True,
        "server_name": qv(q, "sni") or qv(q, "peer") or host,
        "insecure": truthy(qv(q, "allowInsecure") or qv(q, "insecure") or qv(q, "allow_insecure")),
    }
    alpn = qv(q, "alpn")
    if alpn:
        tls["alpn"] = [a for a in alpn.split(",") if a]
    fp = qv(q, "fp")
    if security == "reality":
        tls["reality"] = {"enabled": True, "public_key": qv(q, "pbk"), "short_id": qv(q, "sid")}
        tls["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}  # для reality uTLS обязателен
    elif fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def build_transport(net, host_header, path, service_name):
    net = (net or "tcp").lower()
    if net in ("tcp", "raw", "none", ""):
        return None
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        if host_header:
            t["headers"] = {"Host": host_header}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": service_name or ""}
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host_header:
            t["host"] = host_header
        return t
    if net in ("h2", "http"):
        t = {"type": "http", "path": path or "/"}
        if host_header:
            t["host"] = [host_header]
        return t
    raise ValueError(f"unsupported transport: {net}")


def parse_awg_conf(conf_text):
    try:
        interface, peer, section, peer_count = {}, {}, None, 0
        for line in conf_text.lstrip("\ufeff").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                section = line.strip("[] ").lower()
                if section == "peer":
                    peer_count += 1
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip().lower(), v.split("#")[0].strip()
                if section == "interface":
                    interface[k] = v
                elif section == "peer" and peer_count == 1:
                    peer[k] = v

        endpoint = peer.get("endpoint", "")
        if ":" not in endpoint or not interface.get("privatekey") or not peer.get("publickey"):
            return None
        host, port_str = endpoint.rsplit(":", 1)
        host = host.strip("[]")

        addr = [normalize_cidr(a) for a in interface.get("address", "10.8.0.2/32").split(",") if a.strip()]
        dns = [d.strip() for d in interface.get("dns", "").split(",") if d.strip()]
        allowed = [a.strip() for a in peer.get("allowedips", "0.0.0.0/0, ::/0").split(",") if a.strip()]

        return {
            "type": "wireguard", "tag": "proxy", "address": addr, "dns": dns,
            "private_key": interface["privatekey"],
            "mtu": int(interface.get("mtu", 1280)),
            "peers": [{"address": host, "port": int(port_str), "public_key": peer["publickey"],
                       "allowed_ips": allowed}],
        }
    except Exception:
        return None


def parse_vless(uri):
    try:
        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)
        if not p.hostname or not p.port or not p.username:
            return None
        security = qv(q, "security", "none")
        ob = {"type": "vless", "tag": "proxy", "server": p.hostname, "server_port": p.port,
              "uuid": urllib.parse.unquote(p.username)}
        if qv(q, "flow"):
            ob["flow"] = qv(q, "flow")
        if security in ("tls", "reality"):
            ob["tls"] = build_tls(q, p.hostname, security)
        tr = build_transport(qv(q, "type", "tcp"), qv(q, "host") or qv(q, "sni") or p.hostname,
                             qv(q, "path"), qv(q, "serviceName"))
        if tr:
            ob["transport"] = tr
        return ob
    except Exception:
        return None


def parse_vmess(uri):
    try:
        d = json.loads(b64decode_any(uri[8:].split("#")[0]))
        host = d.get("add")
        if not host or not d.get("id"):
            return None
        ob = {"type": "vmess", "tag": "proxy", "server": host, "server_port": int(d.get("port", 443)),
              "uuid": d["id"], "alter_id": int(d.get("aid", 0) or 0), "security": d.get("scy") or "auto"}
        if d.get("tls") == "tls":
            tls = {"enabled": True, "server_name": d.get("sni") or d.get("host") or host, "insecure": False}
            if d.get("alpn"):
                tls["alpn"] = [a for a in str(d["alpn"]).split(",") if a]
            if d.get("fp"):
                tls["utls"] = {"enabled": True, "fingerprint": d["fp"]}
            ob["tls"] = tls
        path = d.get("path", "")
        tr = build_transport(d.get("net", "tcp"), d.get("host") or d.get("sni") or host, path, path)
        if tr:
            ob["transport"] = tr
        return ob
    except Exception:
        return None


def parse_trojan(uri):
    try:
        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)
        if not p.hostname or not p.port or not p.username:
            return None
        ob = {"type": "trojan", "tag": "proxy", "server": p.hostname, "server_port": p.port,
              "password": urllib.parse.unquote(p.username)}
        if qv(q, "security", "tls") != "none":
            ob["tls"] = build_tls(q, p.hostname)
        tr = build_transport(qv(q, "type", "tcp"), qv(q, "host") or qv(q, "sni") or p.hostname,
                             qv(q, "path"), qv(q, "serviceName"))
        if tr:
            ob["transport"] = tr
        return ob
    except Exception:
        return None


def parse_ss(uri):
    try:
        body = uri[5:].split("#")[0]
        if "@" not in body.split("?")[0]:          # старый формат: ss://BASE64(method:pass@host:port)
            body = b64decode_any(body.split("?")[0])
        p = urllib.parse.urlparse("ss://" + body)
        if "plugin" in urllib.parse.parse_qs(p.query):
            return None                             # плагины не поддерживаем
        if not p.username or not p.hostname or not p.port:
            return None
        if p.password is not None:
            method, pw = urllib.parse.unquote(p.username), urllib.parse.unquote(p.password)
        else:
            method, pw = b64decode_any(urllib.parse.unquote(p.username)).split(":", 1)
        return {"type": "shadowsocks", "tag": "proxy", "server": p.hostname, "server_port": p.port,
                "method": method, "password": pw}
    except Exception:
        return None


def parse_hysteria2(uri):
    try:
        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)
        if not p.hostname or not p.port:
            return None
        pw = urllib.parse.unquote(p.username or "")
        if p.password:
            pw += ":" + urllib.parse.unquote(p.password)
        ob = {"type": "hysteria2", "tag": "proxy", "server": p.hostname, "server_port": p.port,
              "password": pw, "tls": build_tls(q, p.hostname)}
        if qv(q, "obfs"):
            ob["obfs"] = {"type": qv(q, "obfs"), "password": qv(q, "obfs-password")}
        return ob
    except Exception:
        return None


def parse_tuic(uri):
    try:
        p = urllib.parse.urlparse(uri)
        q = urllib.parse.parse_qs(p.query)
        if not p.hostname or not p.port or not p.username:
            return None
        ob = {"type": "tuic", "tag": "proxy", "server": p.hostname, "server_port": p.port,
              "uuid": urllib.parse.unquote(p.username), "password": urllib.parse.unquote(p.password or ""),
              "tls": build_tls(q, p.hostname)}
        if qv(q, "congestion_control"):
            ob["congestion_control"] = qv(q, "congestion_control")
        if qv(q, "udp_relay_mode"):
            ob["udp_relay_mode"] = qv(q, "udp_relay_mode")
        return ob
    except Exception:
        return None


PARSERS = {"vless://": parse_vless, "vmess://": parse_vmess, "trojan://": parse_trojan, "ss://": parse_ss,
           "hysteria2://": parse_hysteria2, "hy2://": parse_hysteria2, "tuic://": parse_tuic}


def parse_any_config(text):
    text = text.strip().lstrip("\ufeff")
    if "[interface]" in text.lower():
        return parse_awg_conf(text)
    for line in text.splitlines():
        line = line.strip()
        low = line.lower()
        for prefix, parser in PARSERS.items():
            if low.startswith(prefix):
                return parser(line)
    return None
# >>> PARSERS END


# ============ 6. СЕТЬ И ПРОВЕРКИ ============
def get_public_ip(proxies=None, timeout=5, urls=IP_URLS):
    for url in urls:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout)
            if r.status_code == 200:
                t = r.text.strip()
                ipaddress.ip_address(t)
                return t
        except Exception:
            continue
    return ""


def update_ip_label(check_change=False):
    ui(lambda: ip_label.configure(text="Ваш IP: Загрузка...", text_color="#aaaaaa"))

    def fetch():
        global original_ip
        # 2 URL вместо 3 — быстрее; если IP ещё не запоминали — запоминаем
        ip = get_public_ip(timeout=4, urls=IP_URLS[:2])
        if ip and not original_ip:
            original_ip = ip
        if check_change and vpn_connected and ip and ip == original_ip:
            time.sleep(1.5)                  # было 3
            ip = get_public_ip(timeout=4, urls=IP_URLS[:1]) or ip
        if not ip:
            ui(lambda: ip_label.configure(text="Ваш IP: Ошибка сети", text_color="#f44336"))
            return
        ui(lambda: ip_label.configure(text=f"Ваш IP: {ip}", text_color="#00a884"))
        if check_change and vpn_connected:
            if ip == original_ip:
                ui(lambda: messagebox.showwarning("IP не изменился", "Проверьте логи (singbox_debug.log / awg_service.log)."))
            else:
                original_ip = ip

    threading.Thread(target=fetch, daemon=True).start()


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_ping(host, port):
    try:
        t = time.time()
        with socket.create_connection((host, int(port)), timeout=1.5):
            return int((time.time() - t) * 1000)
    except Exception:
        return 9999


def get_host_port(link):
    ob = parse_any_config(link)
    if ob and ob.get("server") and ob.get("server_port"):
        return ob["server"], ob["server_port"]
    return None


def check_config_real(link, orig_ip):
    """Поднимает временный sing-box (SOCKS) и проверяет, что через него меняется IP."""
    ob = parse_any_config(link)
    if not ob or ob.get("type") == "wireguard":
        return False, ""
    exe = get_resource_path("sing-box.exe")
    if not os.path.exists(exe):
        return False, ""
    if not SOCKS_SUPPORT:
        return True, ""          # проверить нельзя — доверяем пингу

    port = get_free_port()
    cfg = {
        "log": {"level": "error"},
        "dns": {"servers": [{"type": "local", "tag": "dns-local"}]},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy", "default_domain_resolver": "dns-local"},
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    proc = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen([exe, "run", "-c", path], creationflags=NO_WINDOW,
                                stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
        ready, deadline = False, time.time() + 6
        while time.time() < deadline:
            if proc.poll() is not None:
                return False, ""
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            return False, ""
        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        new_ip = get_public_ip(proxies=proxies, timeout=6, urls=IP_URLS[:2])
        return (True, new_ip) if new_ip and new_ip != orig_ip else (False, new_ip)
    except Exception as e:
        return False, str(e)
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.unlink(path)
        except OSError:
            pass


def extract_links(text):
    prefixes = tuple(PARSERS)
    return [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith(prefixes)]


def fetch_source(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        txt = r.text.strip()
        links = extract_links(txt)
        if not links:                      # возможно, подписка в base64
            try:
                links = extract_links(b64decode_any(txt))
            except Exception:
                pass
        return links
    except Exception:
        return []


def scan_servers(on_progress=None):
    def report(text, p):
        if on_progress:
            on_progress(text, p)

    report("Скачивание списков...", 0.02)
    raw, done = set(), 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(GITHUB_SOURCES)) as ex:
        futs = [ex.submit(fetch_source, u) for u in GITHUB_SOURCES]
        for f in concurrent.futures.as_completed(futs):
            done += 1
            raw.update(f.result())
            report(f"Загружено {done}/{len(GITHUB_SOURCES)}", 0.02 + 0.08 * done / len(GITHUB_SOURCES))
    if not raw:
        return []

    orig_ip = get_public_ip(timeout=5)
    links = list(raw)
    if len(links) > MAX_CANDIDATES:
        links = random.sample(links, MAX_CANDIDATES)

    report(f"Пинг {len(links)}...", 0.1)
    targets = []
    for l in links:
        hp = get_host_port(l)
        if hp:
            targets.append((l, hp[0], hp[1]))

    def ping_th(t):
        l, h, p = t
        ping = get_ping(h, p)
        return {"link": l, "host": h, "port": p, "ping": ping} if ping < MAX_PING_MS else None

    ping_res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for res in ex.map(ping_th, targets):
            if res:
                ping_res.append(res)
    ping_res.sort(key=lambda x: x["ping"])

    candidates = ping_res[:CHECK_LIMIT]
    if not candidates:
        return []
    report("Проверка IP...", 0.5)

    good, lock, stop, counter = [], threading.Lock(), threading.Event(), [0]

    def real_th(srv):
        if stop.is_set():
            return
        ok, nip = check_config_real(srv["link"], orig_ip)
        with lock:
            counter[0] += 1
            n = counter[0]
            if ok:
                srv["new_ip"] = nip or "?"
                good.append(srv)
                if len(good) >= WANT_GOOD:
                    stop.set()
            found = len(good)
        report(f"Проверка {n}/{len(candidates)} (найдено {found})", 0.5 + 0.5 * n / len(candidates))

    with concurrent.futures.ThreadPoolExecutor(max_workers=CHECK_WORKERS) as ex:
        list(ex.map(real_th, candidates))
    good.sort(key=lambda x: x["ping"])
    return good


# ============ 7. ЗАПУСК / ОСТАНОВКА VPN ============
# ---- состояние интерфейса ----
def start_timer():
    global connection_time, timer_job
    stop_timer()
    connection_time = 0

    def tick():
        global connection_time, timer_job
        connection_time += 1
        h, m, s = connection_time // 3600, (connection_time % 3600) // 60, connection_time % 60
        time_label.configure(text=f"Время: {h:02}:{m:02}:{s:02}")
        timer_job = app.after(1000, tick)

    timer_job = app.after(1000, tick)


def stop_timer():
    global timer_job
    if timer_job:
        try:
            app.after_cancel(timer_job)
        except Exception:
            pass
        timer_job = None


def ui_connecting(text="Подключение..."):
    status_label.configure(text=text, text_color="#FFC107")
    connect_btn.configure(text="...", state="disabled")


def ui_connected():
    status_label.configure(text="Подключено", text_color="#00a884")
    connect_btn.configure(text="Отключиться", state="normal", fg_color="#d32f2f", hover_color="#b71c1c")
    start_timer()


def ui_disconnected():
    stop_timer()
    status_label.configure(text="Не защищено", text_color="#f44336")
    connect_btn.configure(text="Подключиться", state="normal", fg_color="#00a884", hover_color="#008f6f")
    time_label.configure(text="Время: 00:00:00")


# ---- sing-box ----
def kill_singbox():
    global sing_box_process, sing_box_log
    if sing_box_process:
        try:
            sing_box_process.terminate()
            try:
                sing_box_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sing_box_process.kill()
        except Exception:
            pass
        sing_box_process = None
    if sing_box_log:
        try:
            sing_box_log.close()
        except Exception:
            pass
        sing_box_log = None


def start_singbox(ob):
    global sing_box_process, sing_box_log, vpn_mode
    if not ensure_stage_binaries():
        return False
    exe = get_resource_path("sing-box.exe")
    if not os.path.exists(exe):
        show_error("Ошибка", "sing-box.exe не найден!")
        return False

    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]

    # адрес самого прокси-сервера — всегда напрямую, иначе получим петлю
    try:
        ip = ipaddress.ip_address(ob["server"])
        rules.append({"ip_cidr": str(ipaddress.ip_network(ip)), "action": "route", "outbound": "direct"})
    except ValueError:
        rules.append({"domain": ob["server"], "action": "route", "outbound": "direct"})
    except KeyError:
        pass

    rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

    # БЕЛЫЙ СПИСОК: эти сайты идут напрямую, минуя прокси
    whitelist = load_whitelist()
    if whitelist:
        rules.append({"domain_suffix": whitelist, "action": "route", "outbound": "direct"})

    # российские домены — напрямую (в 1.12 ключи geoip/geosite удалены, поэтому
    # используем rule_set с подсетями и явный список доменов)
    ru_domains = RU_DOMAIN_SUFFIXES + RU_DOMAINS
    rules.append({"domain_suffix": ru_domains, "action": "route", "outbound": "direct"})

    # rule_set с российскими подсетями (официальный geoip-ru.srs от SagerNet)
    rule_sets = []
    ru_ruleset = get_ru_ruleset_path()
    if ru_ruleset:
        rule_sets.append({"type": "local", "tag": "geoip-ru", "format": "binary", "path": ru_ruleset})
        rules.append({"rule_set": ["geoip-ru"], "action": "route", "outbound": "direct"})

    dns_rules = []
    if whitelist:
        # белые домены резолвим локально — иначе получим зарубежный IP
        dns_rules.append({"domain_suffix": whitelist, "server": "dns-local"})
    # российские домены резолвим локальным DNS — так они получают
    # российские IP и уходят напрямую
    dns_rules.append({"domain_suffix": ru_domains, "server": "dns-local"})

    cfg = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"type": "local", "tag": "dns-local"},
                {"type": "tls", "tag": "dns-remote", "server": "1.1.1.1", "detour": "proxy"},
            ],
            "final": "dns-remote",
            "rules": dns_rules,
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "singbox_tun",
                      "address": ["172.19.0.1/30"], "mtu": 1400, "auto_route": True, "strict_route": False}],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {"auto_detect_interface": True, "default_domain_resolver": "dns-local",
                  "final": "proxy", "rules": rules, "rule_set": rule_sets},
    }
    try:
        with open(SINGBOX_CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        show_error("Ошибка", f"Запись конфига: {e}")
        return False

    # Защита от утечки файлового дескриптора при повторном вызове
    if sing_box_log is not None:
        kill_singbox()

    try:
        sing_box_log = open(SINGBOX_LOG, "wb")
        sing_box_process = subprocess.Popen([exe, "run", "-c", SINGBOX_CONFIG], cwd=BASE_DIR,
                                            creationflags=NO_WINDOW, stdin=DEVNULL,
                                            stdout=sing_box_log, stderr=subprocess.STDOUT)
    except Exception as e:
        kill_singbox()
        show_error("Ошибка", str(e))
        return False

    # Ждём «sing-box started», но не дольше 4 секунд (было 10).
    # Читаем только хвост лога (8 КБ), а не весь файл целиком.
    deadline = time.time() + 4
    while time.time() < deadline:
        if sing_box_process.poll() is not None:
            break
        try:
            size = os.path.getsize(SINGBOX_LOG)
            with open(SINGBOX_LOG, "rb") as f:
                if size > 8192:
                    f.seek(size - 8192)
                if b"sing-box started" in f.read():
                    break
        except (OSError, ValueError):
            pass
        time.sleep(0.1)

    if sing_box_process.poll() is not None:
        err = tail_file(SINGBOX_LOG, 600) or "процесс завершился без сообщений"
        kill_singbox()
        show_error("Ошибка Sing-box", err)
        return False
    vpn_mode = "singbox"
    return True


# ---- AmneziaWG ----
def resolve_ipv4(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return None


def get_default_gateway():
    """Шлюз основного маршрута по умолчанию (до поднятия туннеля)."""
    _, out = run_cmd(["route", "print", "-4", "0.0.0.0"])
    best = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            try:
                ipaddress.ip_address(parts[2])
                metric = int(parts[4])
            except ValueError:
                continue
            if best is None or metric < best[1]:
                best = (parts[2], metric)
    return best[0] if best else None


def build_awg_runtime_conf(text, endpoint_ip, port):
    """Конфиг для `awg setconf`: без Address/DNS/MTU/Table/Pre/Post*."""
    skip = {"address", "dns", "mtu", "table", "preup", "postup", "predown", "postdown", "saveconfig"}
    lines, replaced = [], False
    for raw in text.lstrip("\ufeff").splitlines():
        s = raw.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if s.startswith("["):
            lines.append(s)
            continue
        if "=" in s:
            key, val = s.split("=", 1)
            key, val = key.strip(), val.split("#")[0].strip()
            if key.lower() in skip:
                continue
            if key.lower() == "endpoint" and endpoint_ip and not replaced:
                val, replaced = f"{endpoint_ip}:{port}", True
            lines.append(f"{key} = {val}")
    return "\n".join(lines) + "\n"


def split_routes(allowed):
    routes_v4 = []
    routes_v6 = []
    for n in allowed:
        try:
            net = ipaddress.ip_network(n.strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            if net.prefixlen == 0:
                routes_v4 += ["0.0.0.0/1", "128.0.0.0/1"]
            else:
                routes_v4.append(str(net))
        elif net.version == 6:
            if net.prefixlen == 0:
                routes_v6 += ["::/1", "8000::/1"]
            else:
                routes_v6.append(str(net))
    return routes_v4, routes_v6


def compact_routes(routes, threshold=8):
    """
    Сворачивает длинный список маршрутов в два half-default.
    """
    if len(routes) <= threshold:
        return routes
    if routes and ":" in routes[0]:
        return ["::/1", "8000::/1"]
    return ["0.0.0.0/1", "128.0.0.0/1"]


def service_running():
    _, out = run_cmd(["sc", "query", SERVICE_NAME])
    return "RUNNING" in out.upper()


def service_exists():
    _, out = run_cmd(["sc", "query", SERVICE_NAME])
    up = out.upper()
    return ("FAILED" not in up) and (SERVICE_NAME.upper() in up)


def split_enabled():
    try:
        with open(SPLIT_FLAG_FILE, "r", encoding="utf-8") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


def set_split_enabled(on):
    try:
        with open(SPLIT_FLAG_FILE, "w", encoding="utf-8") as f:
            f.write("1" if on else "0")
    except Exception:
        pass


def _cidrs_from_source_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    out = []
    for rule in (data.get("rules") or []):
        for c in (rule.get("ip_cidr") or []):
            out.append(c)
    return out


def ensure_ru_cidr_list():
    """Список российских подсетей (CIDR). Кеш — ru-cidr.txt рядом с программой."""
    if os.path.exists(RU_CIDR_FILE):
        try:
            with open(RU_CIDR_FILE, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if lines:
                return lines
        except Exception:
            pass
    cidr = []
    # 1) декомпилируем официальный geoip-ru.srs через sing-box
    srs = get_ru_ruleset_path()
    exe = get_resource_path("sing-box.exe")
    if srs and os.path.exists(exe):
        out_json = os.path.join(STAGE_DIR, "ru-cidr.json")
        for args in ([exe, "rule-set", "decompile", "--output", out_json, srs],
                     [exe, "rule-set", "decompile", srs]):
            try:
                r = subprocess.run(args, capture_output=True, stdin=DEVNULL,
                                   creationflags=NO_WINDOW, timeout=180)
            except Exception:
                continue
            if os.path.exists(out_json):
                cidr = _cidrs_from_source_json(out_json)
            elif r.returncode == 0 and r.stdout:
                try:
                    data = json.loads(decode_output(r.stdout))
                    cidr = [c for rule in (data.get("rules") or [])
                            for c in (rule.get("ip_cidr") or [])]
                except Exception:
                    cidr = []
            if cidr:
                break
    # 2) фоллбэк: скачиваем готовый текстовый список
    if not cidr:
        for url in RU_CIDR_URLS:
            try:
                r = requests.get(url, timeout=30)
                if r.status_code == 200:
                    cidr = [l.strip() for l in r.text.splitlines()
                            if re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", l.strip())]
                    if cidr:
                        break
            except Exception:
                continue
    if cidr:
        try:
            with open(RU_CIDR_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(cidr) + "\n")
        except Exception:
            pass
    return cidr


def compact_ru_cidrs(cidrs, threshold=0.1):
    """
    Сжимает список RU-подсетей без потери покрытия:
    если в /16 российских адресов не меньше threshold доли — берём /16 целиком
    (одна строка вместо десятков), иначе оставляем точные префиксы внутри него.
    """
    by16 = {}
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if n.version != 4:
            continue
        key = str(ipaddress.ip_network((n.network_address, 16), strict=False))
        by16.setdefault(key, []).append(n)
    out = []
    for key, nets in by16.items():
        collapsed = list(ipaddress.collapse_addresses(nets))
        size = sum(x.num_addresses for x in collapsed)
        if size >= 65536 * threshold:
            out.append(key)
        else:
            out.extend(str(x) for x in collapsed)
    return sorted(set(out))


def _route_batch(lines, timeout=600):
    """Выполняет пачку команд route одним .bat — в разы быстрее, чем по одному процессу."""
    if not lines:
        return
    fd, bat = tempfile.mkstemp(suffix=".bat")
    try:
        with os.fdopen(fd, "w", encoding="ascii", errors="replace") as f:
            f.write("@echo off\r\n")
            for ln in lines:
                f.write(ln + "\r\n")
        subprocess.run(["cmd", "/c", bat], capture_output=True, stdin=DEVNULL,
                       creationflags=NO_WINDOW, timeout=timeout)
    except Exception:
        pass
    finally:
        try:
            os.remove(bat)
        except OSError:
            pass


def _route_lines_add(cidrs, gw):
    out = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if n.version == 4:
            out.append(f"route add {n.network_address} mask {n.netmask} {gw} metric 1")
        else:
            out.append(f"netsh interface ipv6 add route prefix={n} nexthop={gw} metric=1 store=active")
    return out


def _route_lines_del(cidrs):
    out = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if n.version == 4:
            out.append(f"route delete {n.network_address} mask {n.netmask}")
        else:
            out.append(f"netsh interface ipv6 delete route prefix={n}")
    return out


def apply_ru_split(gateway, on_progress=None):
    """Российские подсети — напрямую через физический шлюз, остальное — в туннель."""
    full = ensure_ru_cidr_list()
    if not full or not gateway:
        return 0
    cidrs = compact_ru_cidrs(full)
    if not cidrs:
        return 0
    lines = _route_lines_add(cidrs, gateway)
    chunks = [lines[i:i + 300] for i in range(0, len(lines), 300)]
    done = [0]
    lock = threading.Lock()

    def work(chunk):
        _route_batch(chunk)
        with lock:
            done[0] += len(chunk)
            n = done[0]
        if on_progress:
            on_progress(n, len(lines))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(work, chunks))
    try:
        with open(SPLIT_STATE_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(cidrs))
    except Exception:
        pass
    if on_progress:
        on_progress(len(lines), len(lines))
    return len(cidrs)


def clear_ru_split():
    """Убирает добавленные маршруты сплита (в т.ч. оставшиеся после краша)."""
    paths = []
    if os.path.exists(SPLIT_STATE_FILE):
        try:
            with open(SPLIT_STATE_FILE, "r", encoding="utf-8") as f:
                paths = [l.strip() for l in f if l.strip()]
        except Exception:
            pass
    lines = _route_lines_del(paths)
    chunks = [lines[i:i + 300] for i in range(0, len(lines), 300)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(_route_batch, chunks))
    try:
        os.remove(SPLIT_STATE_FILE)
    except OSError:
        pass


def resolve_whitelist(domains):
    """
    Домен -> IP. ВАЖНО вызывать ДО поднятия туннеля, пока DNS ещё физический:
    после переключения DNS на туннельный резолвер вернулись бы зарубежные IP.
    """
    out = {}
    for d in domains:
        try:
            infos = socket.getaddrinfo(d, None, socket.AF_INET)
        except OSError:
            continue
        if infos:
            out[d] = infos[0][4][0]
    return out


def apply_whitelist_bypass(resolved, gateway):
    """
    Обход туннеля в режиме AmneziaWG/WARP.

    Трафик идёт в туннель по маршрутам 0.0.0.0/1 + 128.0.0.0/1, поэтому для
    белых сайтов добавляем более специфичные /32-маршруты через физический шлюз
    (правило longest-prefix-match выигрывает у /1). Чтобы браузер использовал
    именно эти IP, закрепляем их в hosts-файле.
    """
    global whitelist_route_ips
    if not resolved:
        return 0
    ips = list(resolved.values())
    if gateway:
        for ip in ips:
            run_cmd(["route", "add", ip, "mask", "255.255.255.255", gateway, "metric", "1"])
    whitelist_route_ips = ips
    hosts_apply([(ip, dom) for dom, ip in resolved.items()])
    run_cmd(["ipconfig", "/flushdns"], timeout=15)
    return len(ips)


def clear_whitelist_bypass():
    """Убирает обходные маршруты и записи из hosts-файла."""
    hosts_clear()
    global whitelist_route_ips
    for ip in whitelist_route_ips:
        run_cmd(["route", "delete", ip, "mask", "255.255.255.255"])
    whitelist_route_ips = []
    run_cmd(["ipconfig", "/flushdns"], timeout=15)


def cleanup_awg():
    global awg_endpoint_ip
    # убираем маршруты авто-сплита и обхода белого списка
    try:
        clear_ru_split()
    except Exception:
        pass
    try:
        clear_whitelist_bypass()
    except Exception:
        pass
    # Удаляем все маршруты, которые добавил наш интерфейс (IPv4 и IPv6)
    for prefix in ["0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"]:
        run_cmd(["netsh", "interface", "ipv4", "delete", "route", f"prefix={prefix}", f"interface={AWG_IFACE}"])
    for prefix in ["::/1", "8000::/1", "::/0"]:
        run_cmd(["netsh", "interface", "ipv6", "delete", "route", f"prefix={prefix}", f"interface={AWG_IFACE}"])

    nssm = get_resource_path("nssm.exe")
    if os.path.exists(nssm) and service_exists():
        if service_running():
            run_cmd([nssm, "stop", SERVICE_NAME])
        run_cmd([nssm, "remove", SERVICE_NAME, "confirm"])
    if awg_endpoint_ip:
        run_cmd(["route", "delete", awg_endpoint_ip, "mask", "255.255.255.255"])
        awg_endpoint_ip = None


def start_awg(text, ob):
    global vpn_mode, awg_endpoint_ip
    if not ensure_stage_binaries():
        return False
    amnezia_exe = get_resource_path("amneziawg-go.exe")
    awg_tool = get_resource_path("awg.exe")
    wintun_path = get_resource_path("wintun.dll")
    nssm = get_resource_path("nssm.exe")
    for name, path in (("amneziawg-go.exe", amnezia_exe), ("awg.exe", awg_tool),
                       ("wintun.dll", wintun_path), ("nssm.exe", nssm)):
        if not os.path.exists(path):
            show_error("Ошибка", f"{name} не найден!")
            return False
    if not check_dll_architecture(wintun_path):
        show_error("Ошибка DLL", "wintun.dll не подходит по архитектуре (нужна 64-битная x64 с wintun.net).")
        return False

    peer = ob["peers"][0]
    endpoint_ip = resolve_ipv4(peer["address"])
    gateway = get_default_gateway()
    conf_text = build_awg_runtime_conf(text, endpoint_ip, peer["port"])

    # БЕЛЫЙ СПИСОК: резолвим заранее, пока DNS ещё физический (не туннельный),
    # иначе получим зарубежные IP и /32-маршруты окажутся бесполезными
    wl_resolved = resolve_whitelist(load_whitelist())

    fd, conf_path = tempfile.mkstemp(suffix=".conf")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(conf_text)

        cleanup_awg()
        try:
            os.remove(AWG_LOG)
        except OSError:
            pass

        rc, out = run_cmd([nssm, "install", SERVICE_NAME, amnezia_exe, AWG_IFACE])
        if rc != 0:
            show_error("Ошибка NSSM install", out)
            return False
        run_cmd([nssm, "set", SERVICE_NAME, "ObjectName", "LocalSystem"])
        run_cmd([nssm, "set", SERVICE_NAME, "Start", "SERVICE_DEMAND_START"])
        run_cmd([nssm, "set", SERVICE_NAME, "AppDirectory", os.path.dirname(amnezia_exe)])
        run_cmd([nssm, "set", SERVICE_NAME, "AppStdout", AWG_LOG])
        run_cmd([nssm, "set", SERVICE_NAME, "AppStderr", AWG_LOG])

        run_cmd([nssm, "start", SERVICE_NAME])
        running = False
        for _ in range(8):
            time.sleep(0.5)
            if service_running():
                running = True
                break
        if not running:
            show_error("Ошибка запуска службы",
                       "Служба AmneziaWG не запустилась за 4 секунды.\n\n" + tail_file(AWG_LOG, 500))
            cleanup_awg()
            return False

        applied, last = False, ""
        for _ in range(6):
            rc, last = run_cmd([awg_tool, "setconf", AWG_IFACE, conf_path])
            if rc == 0:
                applied = True
                break
            time.sleep(0.5)
        if not applied:
            show_error("Ошибка awg setconf",
                       f"Не удалось применить конфиг:\n\n{last}\n\n{tail_file(AWG_LOG, 400)}")
            cleanup_awg()
            return False

        # 5. IP-адрес интерфейса (IPv4)
        v4 = next((a for a in ob["address"] if ipaddress.ip_interface(a).version == 4), "10.8.0.2/32")
        iface = ipaddress.ip_interface(v4)
        ok, last = False, ""
        for _ in range(4):
            rc, last = run_cmd(["netsh", "interface", "ipv4", "set", "address", f"name={AWG_IFACE}",
                                "source=static", f"address={iface.ip}", f"mask={iface.netmask}"])
            if rc == 0:
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            show_error("Ошибка netsh", f"Не удалось назначить IPv4 интерфейсу {AWG_IFACE}:\n{last}")
            cleanup_awg()
            return False
        run_cmd(["netsh", "interface", "ipv4", "set", "interface", f"name={AWG_IFACE}", "metric=1"])
        run_cmd(["netsh", "interface", "ipv4", "set", "subinterface", f"name={AWG_IFACE}",
                 f"mtu={ob.get('mtu', 1280)}", "store=active"])

        # IPv6-адрес интерфейса (если есть)
        v6 = next((a for a in ob["address"] if ipaddress.ip_interface(a).version == 6), None)
        if v6:
            iface_v6 = ipaddress.ip_interface(v6)
            run_cmd(["netsh", "interface", "ipv6", "set", "address", f"name={AWG_IFACE}",
                     f"address={iface_v6.ip}/{iface_v6.network.prefixlen}"])
            run_cmd(["netsh", "interface", "ipv6", "set", "interface", f"name={AWG_IFACE}", "metric=1"])

        # 6. DNS туннеля
        dns_list = [d for d in ob.get("dns", []) if ":" not in d] or ["1.1.1.1"]
        run_cmd(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={AWG_IFACE}",
                 "source=static", f"address={dns_list[0]}", "validate=no"])
        for i, d in enumerate(dns_list[1:], start=2):
            run_cmd(["netsh", "interface", "ipv4", "add", "dnsservers", f"name={AWG_IFACE}",
                     f"address={d}", f"index={i}", "validate=no"])

        # 7. маршруты (IPv4 и IPv6)
        routes_v4, routes_v6 = split_routes(peer.get("allowed_ips", ["0.0.0.0/0", "::/0"]))
        routes_v4 = compact_routes(routes_v4)
        if len(routes_v6) > 8:
            routes_v6 = ["::/1", "8000::/1"]

        if endpoint_ip and gateway:
            run_cmd(["route", "add", endpoint_ip, "mask", "255.255.255.255", gateway, "metric", "1"])
            awg_endpoint_ip = endpoint_ip
        for prefix in routes_v4:
            run_cmd(["netsh", "interface", "ipv4", "add", "route", f"prefix={prefix}",
                     f"interface={AWG_IFACE}", "nexthop=0.0.0.0", "metric=1", "store=active"])
        for prefix in routes_v6:
            run_cmd(["netsh", "interface", "ipv6", "add", "route", f"prefix={prefix}",
                     f"interface={AWG_IFACE}", "metric=1", "store=active"])

        # БЕЛЫЙ СПИСОК: эти сайты идут мимо туннеля (через физический шлюз)
        if wl_resolved and gateway:
            apply_whitelist_bypass(wl_resolved, gateway)

        # АВТО-СПЛИТ: российские подсети — напрямую, остальное — в туннель
        if split_enabled() and gateway:
            def prog(n, total):
                ui(lambda: status_label.configure(text=f"Маршруты RU: {n}/{total}",
                                                   text_color="#FFC107"))
            apply_ru_split(gateway, prog)

        vpn_mode = "awg"
        return True
    except Exception as e:
        show_error("Ошибка AmneziaWG", f"Системная ошибка: {e}")
        cleanup_awg()
        return False
    finally:
        try:
            os.remove(conf_path)
        except OSError:
            pass


# ---- общее ----
def disconnect_all():
    global vpn_mode, vpn_connected
    kill_singbox()
    if vpn_mode == "awg":
        cleanup_awg()
    vpn_mode = None
    vpn_connected = False


def _connect_worker(text, ob):
    global vpn_busy, vpn_connected, original_ip
    ip_ex = None
    try:
        if vpn_connected or vpn_mode:
            disconnect_all()

        ip_ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        ip_future = ip_ex.submit(get_public_ip, timeout=2, urls=IP_URLS[:1])

        ok = start_awg(text, ob) if ob["type"] == "wireguard" else start_singbox(ob)

        try:
            fetched = ip_future.result(timeout=1)
            if fetched:
                original_ip = fetched
        except Exception:
            # таймаут или ошибка сети — не фатально, продолжаем
            pass

        if ok:
            vpn_connected = True
            ui(ui_connected)
            ui(lambda: app.after(800, lambda: update_ip_label(check_change=True)))
        else:
            ui(ui_disconnected)
    except Exception as e:
        show_error("Ошибка", str(e))
        try:
            disconnect_all()
        except Exception:
            pass
        ui(ui_disconnected)
    finally:
        if ip_ex:
            try:
                ip_ex.shutdown(wait=False)
            except Exception:
                pass
        vpn_busy = False


def start_vpn(uri=None):
    global vpn_busy
    if vpn_busy:
        return
    if not uri:
        uri = link_text.get("1.0", ctk.END).strip()
    if not uri:
        messagebox.showerror("Ошибка", "Сначала вставьте конфиг.")
        return
    ob = parse_any_config(uri)
    if not ob:
        messagebox.showerror("Ошибка", "Неизвестный протокол или неверный формат конфига.")
        return
    vpn_busy = True
    ui_connecting()
    threading.Thread(target=_connect_worker, args=(uri, ob), daemon=True).start()


def stop_vpn():
    global vpn_busy
    if vpn_busy:
        return
    vpn_busy = True
    ui_connecting("Отключение...")

    def worker():
        global vpn_busy
        try:
            disconnect_all()
        finally:
            vpn_busy = False
            ui(ui_disconnected)
            update_ip_label()

    threading.Thread(target=worker, daemon=True).start()


def connect_to_server(link):
    if vpn_busy:
        return
    link_text.delete("1.0", ctk.END)
    link_text.insert("1.0", link)
    save_config(link)
    update_active_config_label()
    start_vpn(link)


def connect_best():
    if best_server_link:
        connect_to_server(best_server_link)
    else:
        messagebox.showinfo("Инфо", "Нет серверов в списке")


def on_closing():
    try:
        disconnect_all()
    except Exception:
        pass
    app.destroy()


# ============ 8. UI ============
app = ctk.CTk()
app.title("GrandMenVPN")
app.geometry("900x700")
app.protocol("WM_DELETE_WINDOW", on_closing)

loading_frame = ctk.CTkFrame(app, fg_color="#1a1a1a", corner_radius=0)
cb = ctk.CTkFrame(loading_frame, fg_color="transparent")
cb.place(relx=0.5, rely=0.45, anchor="center")
loading_logo = ctk.CTkLabel(cb, text="GrandMenVPN", font=("Arial", 40, "bold"), text_color="#00a884")
loading_logo.pack(pady=(0, 40))
loading_progress = ctk.CTkProgressBar(cb, width=500, height=10, corner_radius=5, fg_color="#2a2a2a",
                                      progress_color="#00a884")
loading_progress.pack(pady=10)
loading_progress.set(0)
loading_status = ctk.CTkLabel(cb, text="LOADING..", font=("Arial", 12, "bold"), text_color="#666666")
loading_status.pack(pady=(15, 0))
loading_frame.place(relx=0, rely=0, relwidth=1, relheight=1)

main_frame = ctk.CTkFrame(app, corner_radius=0, fg_color="transparent")
sidebar = ctk.CTkFrame(main_frame, width=200, corner_radius=0, fg_color="#1a1a1a")
sidebar.pack(side="left", fill="y")
ctk.CTkLabel(sidebar, text="GrandMenVPN", font=("Arial", 20, "bold"), text_color="#00a884").pack(pady=(30, 40))


def show_tab(t):
    for frame in (home_frame, settings_frame, whitelist_frame):
        try:
            frame.pack_forget()
        except Exception:
            pass
    if t == "home":
        home_frame.pack(fill="both", expand=True, padx=20, pady=20)
    elif t == "settings":
        settings_frame.pack(fill="both", expand=True, padx=20, pady=20)
    else:
        whitelist_frame.pack(fill="both", expand=True, padx=20, pady=20)


ctk.CTkButton(sidebar, text="🏠 Главная", anchor="w", fg_color="transparent",
              command=lambda: show_tab("home")).pack(fill="x", padx=10, pady=5)
ctk.CTkButton(sidebar, text="⚙️ Ручной ввод", anchor="w", fg_color="transparent",
              command=lambda: show_tab("settings")).pack(fill="x", padx=10, pady=5)
ctk.CTkButton(sidebar, text="🔓 Без VPN", anchor="w", fg_color="transparent",
              command=lambda: show_tab("whitelist")).pack(fill="x", padx=10, pady=5)

content_frame = ctk.CTkFrame(main_frame, corner_radius=0, fg_color="#222222")
content_frame.pack(side="right", fill="both", expand=True)

# ---- главная ----
home_frame = ctk.CTkFrame(content_frame, corner_radius=0, fg_color="transparent")
hf = ctk.CTkFrame(home_frame, fg_color="transparent")
hf.pack(fill="x", pady=(20, 10))
status_label = ctk.CTkLabel(hf, text="Не защищено", font=("Arial", 32, "bold"), text_color="#f44336")
status_label.pack(anchor="w")
time_label = ctk.CTkLabel(hf, text="Время: 00:00:00", font=("Arial", 16), text_color="#aaaaaa")
time_label.pack(anchor="w")

ip_f = ctk.CTkFrame(hf, fg_color="transparent")
ip_f.pack(anchor="w", pady=(5, 0))
ip_label = ctk.CTkLabel(ip_f, text="Ваш IP: Загрузка...", font=("Arial", 14), text_color="#aaaaaa")
ip_label.pack(side="left")
ctk.CTkButton(ip_f, text="🔄", width=30, height=30, fg_color="transparent",
              command=update_ip_label).pack(side="left", padx=10)

config_info_label = ctk.CTkLabel(hf, text="Активный конфиг: Не выбран", font=("Arial", 14), text_color="#f44336")
config_info_label.pack(anchor="w", pady=(5, 0))

bf = ctk.CTkFrame(home_frame, fg_color="transparent")
bf.pack(pady=10, fill="x")
connect_btn = ctk.CTkButton(bf, text="Подключиться", font=("Arial", 20, "bold"), height=60, width=250,
                            corner_radius=30, fg_color="#00a884", hover_color="#008f6f",
                            command=lambda: on_connect_click())
connect_btn.pack(side="left", expand=True, padx=(0, 10))
best_btn = ctk.CTkButton(bf, text="⚡ Лучший", font=("Arial", 18, "bold"), height=60, width=150,
                         corner_radius=30, fg_color="#0078D7", command=connect_best)
best_btn.pack(side="right", padx=(10, 0))

sf = ctk.CTkFrame(home_frame, fg_color="#1e1e1e", corner_radius=15)
sf.pack(fill="both", expand=True, pady=5)
shf = ctk.CTkFrame(sf, fg_color="transparent")
shf.pack(fill="x", padx=20, pady=(15, 5))
ctk.CTkLabel(shf, text="Рабочие серверы из интернета", font=("Arial", 18, "bold")).pack(side="left")
scan_btn = ctk.CTkButton(shf, text="Пересканировать", width=140, command=lambda: start_rescan())
scan_btn.pack(side="right")
scan_status_label = ctk.CTkLabel(sf, text="Нажмите 'Пересканировать' для поиска.", text_color="#aaaaaa")
scan_status_label.pack(anchor="w", padx=20, pady=(0, 10))
results_frame = ctk.CTkScrollableFrame(sf, fg_color="transparent")
results_frame.pack(fill="both", expand=True, padx=10, pady=5)

# ---- ручной ввод ----
settings_frame = ctk.CTkFrame(content_frame, corner_radius=0, fg_color="transparent")
ctk.CTkLabel(settings_frame, text="Ручной ввод конфига", font=("Arial", 24, "bold")).pack(anchor="w", pady=(10, 5))
ctk.CTkLabel(settings_frame, text="VLESS / VMess / Trojan / SS / Hysteria2 / TUIC / AmneziaWG",
             font=("Arial", 14), text_color="#00a884").pack(anchor="w", pady=(0, 15))

instr_box = ctk.CTkFrame(settings_frame, fg_color="#2b2b2b", corner_radius=10)
instr_box.pack(fill="x", pady=(0, 15))
ctk.CTkLabel(instr_box, text="Вставьте ссылку или загрузите файл .conf (AmneziaWG):",
             font=("Arial", 13), justify="left").pack(anchor="w", padx=15, pady=(15, 5))
ctk.CTkButton(instr_box, text="🌐 Открыть warp-ru.duckdns.org (генератор WARP)", fg_color="#3498db",
              hover_color="#2980b9", command=open_warp_site).pack(anchor="w", padx=15, pady=(5, 15))

load_btn_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
load_btn_frame.pack(fill="x", pady=(5, 10))
ctk.CTkButton(load_btn_frame, text="📂 Загрузить из файла", fg_color="#8e44ad", hover_color="#732d91",
              font=("Arial", 13, "bold"), command=load_config_from_file).pack(side="left", padx=(0, 10))
ctk.CTkButton(load_btn_frame, text="🧹 Очистить поле", fg_color="#555555", hover_color="#444444",
              command=lambda: link_text.delete("1.0", ctk.END)).pack(side="left")

ctk.CTkLabel(settings_frame, text="Или вставьте текст конфига сюда:", font=("Arial", 14, "bold")).pack(anchor="w", pady=(5, 5))
link_text = ctk.CTkTextbox(settings_frame, height=150, corner_radius=10, font=("Consolas", 11))
link_text.pack(fill="x", pady=5)
_saved = load_saved_config()
if _saved:
    link_text.insert("1.0", _saved)

man_btn_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
man_btn_frame.pack(fill="x", pady=15)

PROTO_NAMES = {"wireguard": "AmneziaWG / WARP", "vless": "VLESS", "vmess": "VMess", "trojan": "Trojan",
               "shadowsocks": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC"}


def update_active_config_label():
    text = load_saved_config()
    if not text:
        config_info_label.configure(text="Активный конфиг: Не выбран", text_color="#f44336")
        return
    ob = parse_any_config(text)
    name = PROTO_NAMES.get(ob["type"]) if ob else None
    config_info_label.configure(text=f"Активный конфиг: {name or 'Пользовательский'}", text_color="#00a884")


def apply_config():
    text = link_text.get("1.0", ctk.END).strip()
    if not text:
        messagebox.showwarning("Внимание", "Поле пустое.")
        return
    if not parse_any_config(text):
        messagebox.showerror("Ошибка", "Не удалось распознать конфиг.")
        return
    if vpn_busy:
        return
    save_config(text)
    update_active_config_label()
    show_tab("home")
    start_vpn(text)          # переподключится, если VPN уже был включён


ctk.CTkButton(man_btn_frame, text="✅ Сохранить и подключиться", fg_color="#00a884", hover_color="#008f6f",
              font=("Arial", 14, "bold"), command=apply_config).pack(side="left", padx=(0, 10))


# ---- белый список (сайты, которые открываются без VPN) ----
whitelist_frame = ctk.CTkFrame(content_frame, corner_radius=0, fg_color="transparent")
ctk.CTkLabel(whitelist_frame, text="Белый список", font=("Arial", 24, "bold")).pack(anchor="w", pady=(10, 5))
ctk.CTkLabel(whitelist_frame, text="Эти сайты будут открываться напрямую, без VPN",
             font=("Arial", 14), text_color="#00a884").pack(anchor="w", pady=(0, 15))

wl_info = ctk.CTkFrame(whitelist_frame, fg_color="#2b2b2b", corner_radius=10)
wl_info.pack(fill="x", pady=(0, 15))
ctk.CTkLabel(wl_info,
             text="В режиме sing-box домены идут напрямую.\n"
                  "В режиме WARP/AmneziaWG для них добавляются отдельные маршруты\n"
                  "через обычный шлюз и закрепляются в hosts-файле.",
             font=("Arial", 12), justify="left").pack(anchor="w", padx=15, pady=(12, 8))

split_row = ctk.CTkFrame(wl_info, fg_color="transparent")
split_row.pack(fill="x", padx=15, pady=(0, 12))
ctk.CTkLabel(split_row, text="Авто-сплит: все российские подсети — напрямую, остальное — через VPN",
             font=("Arial", 13), anchor="w", justify="left").pack(side="left", fill="x", expand=True)
split_switch = ctk.CTkSwitch(split_row, text="", width=52, command=lambda: on_split_toggle())
split_switch.pack(side="right", padx=(10, 0))
if split_enabled():
    split_switch.select()

wl_add_frame = ctk.CTkFrame(whitelist_frame, fg_color="transparent")
wl_add_frame.pack(fill="x", pady=(0, 10))
wl_entry = ctk.CTkEntry(wl_add_frame, placeholder_text="например: 2ip.io", height=40,
                        font=("Arial", 14))
wl_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
wl_entry.bind("<Return>", lambda _e: add_whitelist_entry())


def on_split_toggle():
    """Включение/выключение авто-сплита RU-трафика."""
    on = bool(split_switch.get())
    set_split_enabled(on)
    if on:
        threading.Thread(target=prepare_ru_cidr_list_async, daemon=True).start()
    else:
        threading.Thread(target=clear_ru_split, daemon=True).start()


def prepare_ru_cidr_list_async():
    """Готовим список RU-подсетей заранее (в фоне), чтобы подключение было быстрым."""
    try:
        cidrs = ensure_ru_cidr_list()
        ui(lambda: wl_count_label.configure(
            text=f"В списке: {len(load_whitelist())}   |   RU-подсетей: {len(cidrs)}"))
    except Exception:
        pass


def add_whitelist_entry():
    raw = wl_entry.get()
    dom = normalize_domain(raw)
    if not dom:
        messagebox.showwarning("Внимание", "Не похоже на домен. Пример: 2ip.io")
        return
    items = load_whitelist()
    if dom in items:
        messagebox.showinfo("Инфо", f"{dom} уже есть в списке.")
        return
    items.append(dom)
    if save_whitelist(items):
        wl_entry.delete(0, "end")
        refresh_whitelist_ui()
    else:
        messagebox.showerror("Ошибка", "Не удалось сохранить whitelist.txt")


def remove_whitelist_entry(dom):
    items = [d for d in load_whitelist() if d != dom]
    if save_whitelist(items):
        refresh_whitelist_ui()
    else:
        messagebox.showerror("Ошибка", "Не удалось сохранить whitelist.txt")


def refresh_whitelist_ui():
    for w in wl_list.winfo_children():
        w.destroy()
    items = load_whitelist()
    if not items:
        ctk.CTkLabel(wl_list, text="Список пуст — все сайты идут через VPN",
                     text_color="#aaaaaa", font=("Arial", 13)).pack(pady=30)
    else:
        for dom in items:
            row = ctk.CTkFrame(wl_list, fg_color="#2a2a2a", corner_radius=10)
            row.pack(fill="x", pady=4, padx=5)
            ctk.CTkLabel(row, text=f"🔓 {dom}", anchor="w", font=("Arial", 14)).pack(
                side="left", padx=15, pady=8, fill="x", expand=True)
            ctk.CTkButton(row, text="✖", width=36, height=30, fg_color="#555555", hover_color="#444444",
                          command=lambda d=dom: remove_whitelist_entry(d)).pack(side="right", padx=12, pady=8)
    wl_count_label.configure(text=f"В списке: {len(items)}")
    wl_apply_btn.configure(state="normal" if items else "disabled")


def prepare_ru_cidr_list_async_silent():
    try:
        ensure_ru_cidr_list()
    except Exception:
        pass


ctk.CTkButton(wl_add_frame, text="➕ Добавить", width=140, height=40, fg_color="#00a884",
              hover_color="#008f6f", font=("Arial", 14, "bold"),
              command=add_whitelist_entry).pack(side="right")

wl_list = ctk.CTkScrollableFrame(whitelist_frame, fg_color="#1e1e1e", corner_radius=15,
                                 label_text="Сайты без VPN")
wl_list.pack(fill="both", expand=True, pady=5)
wl_count_label = ctk.CTkLabel(whitelist_frame, text="В списке: 0", text_color="#aaaaaa",
                               font=("Arial", 13))
wl_count_label.pack(anchor="w", pady=(8, 0))

wl_apply_btn = ctk.CTkButton(whitelist_frame, text="🔄 Применить (переподключиться)",
                              fg_color="#0078D7", hover_color="#005FB3", font=("Arial", 13, "bold"),
                              command=lambda: apply_whitelist_now())
wl_apply_btn.pack(anchor="w", pady=(10, 0))


def apply_whitelist_now():
    """Переподключает VPN, чтобы изменения белого списка вступили в силу."""
    if vpn_busy:
        return
    text = load_saved_config()
    if not text:
        messagebox.showinfo("Внимание", "Сначала сохраните конфиг VPN на вкладке «Ручной ввод».")
        return
    if vpn_connected:
        start_vpn(text)        # переподключится уже с новым белым списком
    else:
        messagebox.showinfo("Инфо", "VPN не подключён — список применится при подключении.")


def on_connect_click():
    if vpn_busy:
        return
    if vpn_connected:
        stop_vpn()
        return
    if not link_text.get("1.0", ctk.END).strip():
        messagebox.showinfo("Внимание", "Нет конфига.")
        show_tab("settings")
        return
    start_vpn()


def populate_results(servers, text="Найдено: "):
    global best_server_link
    for w in results_frame.winfo_children():
        w.destroy()
    if not servers:
        ctk.CTkLabel(results_frame, text="Серверов не найдено.", text_color="#f44336").pack(pady=20)
        best_server_link = None
        scan_status_label.configure(text="Пусто")
        return
    scan_status_label.configure(text=f"{text}{len(servers)}")
    best_server_link = servers[0]["link"]
    for i, s in enumerate(servers, 1):
        f = ctk.CTkFrame(results_frame, fg_color="#2a2a2a", corner_radius=10)
        f.pack(fill="x", pady=4, padx=5)
        info = f"#{i} {s['host']}:{s['port']}\n⚡ {s['ping']} ms | IP: {s.get('new_ip', '?')}"
        ctk.CTkLabel(f, text=info, justify="left", font=("Arial", 12)).pack(side="left", padx=15, pady=8)
        ctk.CTkButton(f, text="Подключиться", width=120,
                      command=lambda l=s["link"]: connect_to_server(l)).pack(side="right", padx=15, pady=8)


def transition_to_main(servers):
    global target_progress, trans_y
    target_progress = 1.0

    def slide():
        global trans_y, loading_done
        trans_y -= 0.05
        if trans_y <= -1.0:
            loading_done = True
            loading_frame.place_forget()
            main_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            populate_results(servers, "Автопоиск: найдено ")
            update_ip_label()
            update_active_config_label()
            refresh_whitelist_ui()
            show_tab("home" if load_saved_config() else "settings")
            return
        loading_frame.place(relx=0, rely=trans_y, relwidth=1, relheight=1)
        main_frame.place(relx=0, rely=1.0 + trans_y, relwidth=1, relheight=1)
        app.after(16, slide)

    app.after(600, slide)


def initial_setup():
    global target_progress

    def on_progress(text, prog):
        global target_progress
        target_progress = prog
        ui(lambda: loading_status.configure(text=text))

    on_progress("Запуск сканирования...", 0.1)
    try:
        servers = scan_servers(on_progress=lambda t, p: on_progress(t, 0.1 + p * 0.9))
    except Exception:
        servers = []
    ui(lambda: transition_to_main(servers))


def start_rescan():
    global is_scanning
    if is_scanning:
        return
    is_scanning = True
    for w in results_frame.winfo_children():
        w.destroy()
    scan_btn.configure(state="disabled", text="Сканирование...")
    scan_status_label.configure(text="Поиск...")

    def th():
        global is_scanning
        try:
            sv = scan_servers(on_progress=lambda t, p: ui(lambda: scan_status_label.configure(text=t)))
        except Exception:
            sv = []

        def up():
            global is_scanning
            populate_results(sv, "Пересканировано: ")
            scan_btn.configure(state="normal", text="Пересканировать")
            is_scanning = False

        ui(up)

    threading.Thread(target=th, daemon=True).start()


# убираем «осиротевшую» службу AmneziaWG после аварийного закрытия прошлого запуска
threading.Thread(target=cleanup_awg, daemon=True).start()

# распаковываем внешние бинарники в защищённую папку (для onefile-сборки)
threading.Thread(target=ensure_stage_binaries, daemon=True).start()

# готовим список российских подсетей заранее (нужен для авто-сплита)
threading.Thread(target=prepare_ru_cidr_list_async_silent, daemon=True).start()

app.after(100, animate_progress)
main_frame.place(relx=0, rely=1.0, relwidth=1, relheight=1)
app.after(200, lambda: threading.Thread(target=initial_setup, daemon=True).start())
app.mainloop()