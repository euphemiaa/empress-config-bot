#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
👑 امپرس | کانفیگ رایگان V2RayNG — ربات پست خودکار (فاز ۱)
کانال: https://t.me/EmpressConfig  |  شبکه اصلی: @EmpressNetwork

کارها در هر اجرا (بدون هیچ کتابخانه خارجی — فقط پایتون استاندارد):
  ۱) دریافت لیست کانفیگ از منابع عمومی گیت‌هاب (SOURCES پایین فایل)
  ۲) دیکود base64 در صورت نیاز + پارس لینک‌های vmess / vless / trojan / ss
  ۳) تست TCP به host:port هر سرور (ThreadPoolExecutor، پیش‌فرض ۴۰ ورکر، تایم‌اوت ۳ ثانیه)
  ۴) حذف تکراری‌های پست‌شده با حافظه state/posted.json
  ۵) انتخاب ۸ کانفیگ در هر پست: اول ۶ تا بهترین VLESS، بعد ۲ تا از بقیه پروتکل‌ها
     (قابل تغییر با CONFIGS_PER_POST و VLESS_COUNT)
  ۶) ساخت پست HTML فارسی چندکانفیگی به سبک @flyv2ray: تاریخ شمسی + بلوک‌های <code>
     + راهنمای سریع v2rayNG و NPV Tunnel + لینک دانلود اپ‌ها + دکمه‌ها + هشتگ + فوتر
  ۷) ساخت فایل پیوست .txt با همان کانفیگ‌ها (هر خط = یک کانفیگ برای کپی سریع در
     v2rayNG و NPV Tunnel) و ارسال با sendDocument به‌صورت ریپلای به پست
  ۸) ارسال با Bot API (parse_mode=HTML) یا نمایش پیش‌نمایش در حالت DRY_RUN=1

متغیرهای محیطی:
  BOT_TOKEN            توکن بات از BotFather (الزامی برای ارسال واقعی)
  CHANNEL_ID           @EmpressConfig یا -100xxxxxxxxxx
  CHANNEL_LINK         https://t.me/EmpressConfig (لینک دکمه در نبود TUTORIAL_URL)
  TUTORIAL_URL         (اختیاری، فاز ۲) لینک پست آموزشی پین‌شده برای دکمه
  DRY_RUN              1 = فقط پیش‌نمایش؛ بدون ارسال و بدون تغییر posted.json
  WORKERS              تعداد نخ‌های تست TCP (پیش‌فرض 40)
  TCP_TIMEOUT          تایم‌اوت تست به ثانیه (پیش‌فرض 3)
  CONFIGS_PER_POST     تعداد کانفیگ در هر پست (پیش‌فرض ۸؛ بازه 1 تا 15)
  VLESS_COUNT          سهم VLESS در هر پست (پیش‌فرض ۶؛ بقیه اسلات‌ها از بقیه پروتکل‌ها پر می‌شود)
  SUB_MAX_CONFIGS      تعداد کانفیگ در فایل سابسکریپشن (پیش‌فرض 100)
  PROTO_PRIORITY       اولویت پروتکل‌ها (پیش‌فرض vless,vmess,trojan,ss)
  STATE_MAX_AGE_DAYS   عمر حافظه dedupe به روز (پیش‌فرض 10)

نکته تلگرام: دکمه شیشه‌ای فقط URL از نوع http/https قبول می‌کند، بنابراین
لینک‌های vless:// و vmess:// داخل بلاک <code> می‌روند تا کاربر راحت کپی کند.
نکته NPV Tunnel: نپسترنت (NPV Tunnel / NapsternetV) همین لینک‌های vless/vmess/trojan
را با «کپی ← ➕ ← Import Config» می‌خواند؛ پس پست ما برای هر دو اپ کار می‌کند.
"""

import ast
import base64
import hashlib
import html
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

# ------------------------- تنظیمات -------------------------

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
CHANNEL_ID = os.environ.get("CHANNEL_ID", "").strip()
CHANNEL_LINK = os.environ.get("CHANNEL_LINK", "").strip() or "https://t.me/EmpressConfig"
# لینک پست آموزشی پین‌شده در کانال (پیش‌فرض؛ با متغیر TUTORIAL_URL قابل بازنویسی)
TUTORIAL_URL = os.environ.get("TUTORIAL_URL", "").strip() or "https://t.me/EmpressConfig/21"
DRY_RUN = os.environ.get("DRY_RUN", "0").strip().lower() in ("1", "true", "yes", "y")

WORKERS = int(os.environ.get("WORKERS", "40"))
TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "3"))
CONFIGS_PER_POST = max(1, min(15, int(os.environ.get("CONFIGS_PER_POST", "8"))))
VLESS_COUNT = max(0, int(os.environ.get("VLESS_COUNT", "6")))
SUB_MAX_CONFIGS = max(1, int(os.environ.get("SUB_MAX_CONFIGS", "100")))
PROTO_PRIORITY = [p for p in (x.strip().lower() for x in
                  os.environ.get("PROTO_PRIORITY", "vless,vmess,trojan,ss").split(",")) if p]
STATE_MAX_AGE_DAYS = int(os.environ.get("STATE_MAX_AGE_DAYS", "10"))
MAX_PER_HOST = 1  # در هر پست حداکثر یک کانفیگ از هر host:port (برای تنوع بیشتر)

TG_LIMIT = 4096   # سقف طول متن پیام در تلگرام (بر حسب واحد UTF-16)
TG_SAFETY = 64    # حاشیه امن برای محاسبه طول

STATE_DIR = "state"
POSTED_FILE = os.path.join(STATE_DIR, "posted.json")
LAST_RUN_FILE = os.path.join(STATE_DIR, "last_run.json")
SUB_FILE = os.path.join(STATE_DIR, "sub.txt")
SUB_B64_FILE = os.path.join(STATE_DIR, "sub_base64.txt")

TEHRAN_TZ = timezone(timedelta(hours=3, minutes=30))  # ایران دی‌سایور ندارد

# منابع کانفیگ — همه عمومی و رایگان (آخرین تست زنده: ۲۰۲۶-۱۱-۰۷)
# نکته: 0xRadikal پروژه‌ای مخصوص ایران است و کانفیگ‌های verified/top100 را خودش تست می‌کند.
SOURCES = [
    {
        "name": "barry-far/V2ray-Config (All)",
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    },
    {
        "name": "Danialsamadi/v2go (All)",
        "url": "https://raw.githubusercontent.com/Danialsamadi/v2go/main/AllConfigsSub.txt",
    },
    {
        "name": "MatinGhanbari/v2ray-configs (vless)",
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    },
    {
        "name": "MatinGhanbari/v2ray-configs (vmess)",
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
    },
    {
        "name": "MatinGhanbari/v2ray-configs (trojan)",
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    },
    {
        "name": "MatinGhanbari/v2ray-configs (ss)",
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",
    },
    {
        "name": "0xRadikal/Free-v2ray-Configs (verified)",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    },
    {
        "name": "0xRadikal/Free-v2ray-Configs (top100)",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    },
]

FOOTER = "👑 شبکه امپرس | 🆔 کانال اصلی: @EmpressNetwork"
HASHTAGS = "#کانفیگ_رایگان #V2RayNG #NPV_Tunnel"

# لینک رسمی دانلود اپ‌ها در گوگل‌پلی (برای خط «دانلود» در پست)
APP_V2RAYNG_URL = "https://play.google.com/store/apps/details?id=com.v2ray.ang"
APP_NPV_URL = "https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv"
NETWORK_URL = "https://t.me/EmpressNetwork"

PROTO_LABEL = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "ss": "Shadowsocks"}
NUM_EMOJI = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]


def proto_title(c):
    """عنوان نمایشی پروتکل؛ برای vless/trojan نوع security هم می‌آید (مثل VLESS Reality)."""
    label = PROTO_LABEL.get(c["proto"], c["proto"].upper())
    m = re.search(r"[?&]security=([a-z0-9]+)", c.get("link", ""), re.I)
    if m:
        sec = m.group(1).lower()
        if sec == "reality":
            return label + " Reality"
        if sec == "tls":
            return label + " TLS"
    return label


def proto_hashtag(c):
    t = re.sub(r"[^A-Za-z0-9_]", "_", proto_title(c).replace(" ", "_")).strip("_")
    return "#" + t

WEEKDAYS_FA = ["دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه", "شنبه", "یکشنبه"]
MONTHS_FA = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
             "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"]

FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
SCHEME_RE = re.compile(r"^(vmess|vless|trojan|ss)://", re.I)


# ------------------------- ابزارهای عمومی -------------------------

def log(msg):
    print(msg, flush=True)


def die(msg, code=1):
    log("❌ " + msg)
    sys.exit(code)


def fa(n):
    """تبدیل ارقام لاتین به فارسی."""
    return str(n).translate(FA_DIGITS)


def fa_num(n):
    """تبدیل عدد با جداکننده هزارگان فارسی (۱۲٬۳۴۵)."""
    return f"{n:,}".translate(FA_DIGITS).replace(",", "٬")


def tg_len(s):
    """طول متن از دید تلگرام (بر حسب واحد کد UTF-16)."""
    return len(s.encode("utf-16-le")) // 2


def b64_decode_any(s):
    """دیکود base64 استاندارد/urlsafe با ترمیم padding؛ اگر base64 نبود None."""
    s = re.sub(r"\s+", "", s)
    if not s or "@" in s:  # کاراکتر @ در الفبای base64 نیست
        return None
    for t in (s, s.replace("-", "+").replace("_", "/")):
        t2 = t + "=" * (-len(t) % 4)
        try:
            text = base64.b64decode(t2, validate=True).decode("utf-8")
            if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
                return text
        except Exception:
            continue
    return None


def smart_decode(text):
    """اگر کل متن base64 بود دیکودش کن، وگرنه همان متن خام را برگردان."""
    if "://" in text:
        return text
    dec = b64_decode_any(text)
    if dec and "://" in dec:
        return dec
    return text


def fetch_bytes(url, timeout=60):
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (EmpressConfigBot/1.0)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ------------------------- تاریخ شمسی -------------------------

def gregorian_to_jalali(gy, gm, gd):
    """تبدیل میلادی به جلالی (الگوریتم استاندارد جلالی، بدون کتابخانه خارجی)."""
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = (355666 + (365 * gy) + ((gy2 + 3) // 4) - ((gy2 + 99) // 100)
            + ((gy2 + 399) // 400) + gd + g_d_m[gm - 1])
    jy = -1595 + (33 * (days // 12053))
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm = 1 + (days // 31)
        jd = 1 + (days % 31)
    else:
        jm = 7 + ((days - 186) // 30)
        jd = 1 + ((days - 186) % 30)
    return jy, jm, jd


def jalali_date_str(dt):
    jy, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
    weekday = WEEKDAYS_FA[dt.weekday()]
    return f"{weekday} {fa(jd)} {MONTHS_FA[jm - 1]} {fa(jy)}"


# ------------------------- پارس کانفیگ‌ها -------------------------

def parse_vmess(link):
    """vmess://  →  payload پایه۶۴ شامل JSON با فیلدهای add/port/..."""
    payload = link[len("vmess://"):]
    data = None
    dec = b64_decode_any(payload)
    if dec:
        try:
            data = json.loads(dec)
        except Exception:
            data = None
    if not isinstance(data, dict):
        # بعضی لینک‌های نادر JSON خام دارند (نه base64)
        try:
            data = ast.literal_eval(urllib.parse.unquote(payload))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
    host = str(data.get("add", "")).strip().strip("[]").lower()
    try:
        port = int(str(data.get("port", "")).strip())
    except (TypeError, ValueError):
        return None
    if not host or not (1 <= port <= 65535):
        return None
    name = str(data.get("ps", "") or "").strip()
    # نام (ps) را از اثر انگشت حذف می‌کنیم تا همان کانفیگ با اسم تازه، تکراری شمرده شود
    canonical = json.dumps({k: v for k, v in data.items() if k != "ps"},
                           sort_keys=True, ensure_ascii=False)
    return {"proto": "vmess", "link": link, "host": host, "port": port,
            "name": name, "fp_src": "vmess|" + canonical,
            "net": str(data.get("net", "tcp") or "tcp").strip().lower(),
            "sec": "tls" if str(data.get("tls", "")).strip().lower() in ("tls", "reality") else ""}


def parse_userinfo(scheme, link):
    """vless://uuid@host:port?...#name   و   trojan://pass@host:port?...#name"""
    sp = urllib.parse.urlsplit(link)
    host = (sp.hostname or "").strip().lower()
    port = sp.port
    if port is None:
        port = 443  # پورت پیش‌فرض vless/trojan
    if not host or not (1 <= port <= 65535):
        return None
    name = urllib.parse.unquote(sp.fragment or "")
    canonical = urllib.parse.urlunsplit(
        (sp.scheme.lower(), sp.netloc, sp.path, sp.query, ""))  # بدون fragment
    try:
        q = urllib.parse.parse_qs(sp.query)
        sec = (q.get("security") or [""])[0].strip().lower()
        net = (q.get("type") or ["tcp"])[0].strip().lower() or "tcp"
    except Exception:
        sec, net = "", "tcp"
    return {"proto": scheme, "link": link, "host": host, "port": port,
            "name": name, "fp_src": canonical, "net": net, "sec": sec}


def parse_ss(link):
    """ss://  →  سه فرمت رایج SIP002 (userinfo پایه۶۴ یا خام، یا کل لینک پایه۶۴)"""
    body = link[len("ss://"):]
    if "#" in body:
        body, _tag = body.split("#", 1)
    if "?" in body:
        body = body.split("?", 1)[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        dec = b64_decode_any(userinfo)
        identity = dec if (dec and ":" in dec) else urllib.parse.unquote(userinfo)
    else:
        dec = b64_decode_any(body)
        if not dec or "@" not in dec:
            return None
        identity, hostport = dec.rsplit("@", 1)
    hp = urllib.parse.urlsplit("//" + hostport)
    host = (hp.hostname or "").strip().lower()
    port = hp.port
    if not host or port is None or not (1 <= port <= 65535):
        return None
    return {"proto": "ss", "link": link, "host": host, "port": port,
            "name": host, "fp_src": "ss|" + identity + "|" + hostport.lower(),
            "net": "tcp", "sec": ""}


def parse_link(link):
    link = link.strip().strip('"').strip("'")
    m = SCHEME_RE.match(link)
    if not m:
        return None
    scheme = m.group(1).lower()
    try:
        if scheme == "vmess":
            return parse_vmess(link)
        if scheme == "ss":
            return parse_ss(link)
        return parse_userinfo(scheme, link)  # vless / trojan
    except Exception:
        return None


# ------------------------- تست TCP -------------------------

def tcp_ping(host, port):
    """اتصال TCP ساده؛ تأخیر به میلی‌ثانیه یا None اگر شکست خورد."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return max(1, int((time.monotonic() - t0) * 1000))
    except OSError:
        return None


# ------------------------- امتیاز «ایران‌پسند بودن» -------------------------
# ⚠️ واقعیت مهم: تست TCP از سرور خارج فقط «زنده بودن» سرور را می‌فهمد؛
# فایروال ایران خیلی از این سرورها را از داخل بلاک/محوش می‌کند (حتی با پینگ خارجی سالم).
# تجربهٔ میدانی می‌گوید از داخل ایران به این ترتیب شانس اتصال بیشتر است:
#   ۱) VLESS Reality (مقاوم به DPI)  ۲) هر چیزی پشت کلادفلر با TLS  ۳) پورت‌های TLS
# و بدترین حالت: IP خام بدون رمزنگاری روی پورت ۸۰ — اولین کسی که بلاک می‌شود.
# پس انتخاب‌ها را با این امتیاز مرتب می‌کنیم (تست TCP همچنان انجام می‌شود؛ این فقط اولویت است).

# بازه‌های رسمی IPv4 کلادفلر (cloudflare.com/ips-v4)
_CF_V4_TEXT = (
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 "
    "141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 "
    "197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 "
    "104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
)


def ip_to_int(ip):
    """IPv4 معتبر → عدد صحیح؛ وگرنه None (دامنه و IPv6 این‌جا پاس نمی‌شوند)."""
    parts = str(ip).split(".")
    if len(parts) != 4:
        return None
    n = 0
    for p in parts:
        if not p.isdigit():
            return None
        v = int(p)
        if v > 255:
            return None
        n = (n << 8) | v
    return n


def _cidr_bounds(cidr):
    base, bits = cidr.split("/")
    start = ip_to_int(base)
    size = 1 << (32 - int(bits))
    return start, start + size - 1


CF_V4_RANGES = [b for b in (_cidr_bounds(c) for c in _CF_V4_TEXT.split()) if b[0] is not None]


def is_cloudflare_ip(host):
    h = str(host).strip("[]")
    if h.lower().startswith("::ffff:"):  # IPv4-mapped IPv6
        h = h[7:]
    n = ip_to_int(h)
    if n is None:
        return False
    return any(a <= n <= b for a, b in CF_V4_RANGES)


TLS_PORTS = (443, 8443, 2053, 2083, 2087, 2096)          # پورت‌های HTTPS/کلادفلر-TLS
PLAIN_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)    # پورت‌های بدون رمز کلادفلر
WEB_TRANSPORTS = ("ws", "grpc", "httpupgrade", "xhttp", "splithttp")


def iran_score(c):
    """هرچه بالاتر، شانس اتصال از داخل ایران بیشتر (تخمینی، بر اساس تجربهٔ میدانی)."""
    host = c["host"]
    sec = c.get("sec")
    if sec is None:  # پشتیبانی از لینک‌های بدون پارامتر ( fallback روی خود لینک)
        m = re.search(r"[?&]security=([a-z0-9]+)", c["link"], re.I)
        sec = m.group(1).lower() if m else ""
    net = c.get("net")
    if net is None:
        m = re.search(r"[?&]type=([a-z0-9]+)", c["link"], re.I)
        net = m.group(1).lower() if m else "tcp"
    score = 0
    if sec == "reality":
        score += 50                      # مقاوم‌ترین در برابر DPI
    elif sec == "tls":
        score += 18
    if is_cloudflare_ip(host):
        score += 14                      # IP کلادفلر = پشت CDN؛ بلاکش یعنی بلاک نصف اینترنت
    elif not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        score += 6                       # دامنه (به‌خصوص پشت CDN) بهتر از IP داده‌سنتری خام
    if net in WEB_TRANSPORTS:
        score += 8                       # ترنسپورت وب‌مانند شبیه ترافیک عادی HTTPS دیده می‌شود
    if c["port"] in TLS_PORTS:
        score += 8
    elif c["port"] in PLAIN_PORTS:
        score -= 6
    raw_ip = str(host).strip("[]")
    if raw_ip.lower().startswith("::ffff:"):
        raw_ip = raw_ip[7:]
    if ip_to_int(raw_ip) is not None and sec in ("", "none"):
        if net in WEB_TRANSPORTS and is_cloudflare_ip(host):
            score -= 2                   # کلادفلر + ws بدون TLS: هنوز قابل قبول
        elif net in WEB_TRANSPORTS:
            score -= 8                   # IP خام + ws بدون TLS
        else:
            score -= 18                  # IP خام + tcp بدون رمزنگاری = اولین قربانی فیلتر
    return score


# ------------------------- حافظه dedupe -------------------------

def load_state():
    if os.path.exists(POSTED_FILE):
        try:
            with open(POSTED_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("items"), dict):
                return data
        except Exception:
            pass
    return {"version": 1, "updated": None, "items": {}}


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(POSTED_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


def prune_state(state):
    """حذف آثار قدیمی‌تر از STATE_MAX_AGE_DAYS روز تا فایل state بی‌نهایت بزرگ نشود."""
    cutoff = (datetime.now(TEHRAN_TZ) - timedelta(days=STATE_MAX_AGE_DAYS)).isoformat(timespec="seconds")
    kept = {}
    for fp, info in state.get("items", {}).items():
        ts = str(info.get("ts", "")) if isinstance(info, dict) else ""
        if ts >= cutoff:
            kept[fp] = info
    state["items"] = kept


# ------------------------- ساخت پست -------------------------

def build_message(selected, date_str, time_str, total_tested=0, total_alive=0):
    """پست چندکانفیگی به سبک @flyv2ray: تیتر + بلوک‌های شماره‌دار کانفیگ + راهنما + فوتر."""
    lines = [
        "👑 <b>امپرس | کانفیگ رایگان</b>",
        f"📅 {date_str} • ⏰ {time_str}",
        "",
        f"🔥 <b>{fa(len(selected))} کانفیگ تازه تست‌شده و سالم — مناسب v2rayNG و NPV Tunnel</b>",
        "",
    ]
    for i, c in enumerate(selected, 1):
        num = NUM_EMOJI[i - 1] if i <= len(NUM_EMOJI) else f"{fa(i)}‌."
        lines.append(f"{num} ⚡️ <b>{proto_title(c)}</b> | ⏱ پینگ {fa(c['latency'])} ms")
        lines.append(f"<code>{html.escape(c['link'], quote=False)}</code>")
        lines.append("")
    lines.append("📲 <b>راهنمای سریع:</b>")
    lines.append("۱️⃣ کانفیگ دلخواه را کپی کن")
    lines.append("۲️⃣ v2rayNG ← دکمه ➕ ← Import config from clipboard")
    lines.append("۳️⃣ NPV Tunnel ← دکمه ➕ ← Import Config")
    lines.append("💡 تایم‌اوت شد؟ تنظیمات v2rayNG ← گزینه Fragment را روشن کن، بعد تست بزن")
    lines.append(f"📎 فایل پیوست پایین پست = همین {fa(len(selected))} کانفیگ برای کپی سریع")
    lines.append("")
    lines.append(f"⬇️ <a href=\"{APP_V2RAYNG_URL}\">دانلود v2rayNG</a> | "
                 f"<a href=\"{APP_NPV_URL}\">دانلود NPV Tunnel</a>")
    lines.append("🌟 کانفیگ را با دوستانت به اشتراک بگذار 👌")
    lines.append("")
    tags = []
    for c in selected:
        t = proto_hashtag(c)
        if t not in tags:
            tags.append(t)
    lines.append((HASHTAGS + " " + " ".join(tags[:3])).strip())
    lines.append("")
    lines.append(FOOTER)
    return "\n".join(lines)


# ------------------------- ارسال به تلگرام -------------------------

def tg_api(method, payload):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_post(text):
    button_url = TUTORIAL_URL or CHANNEL_LINK or "https://t.me/EmpressConfig"
    keyboard = {"inline_keyboard": [[
        {"text": "📌 آموزش اتصال", "url": button_url},
        {"text": "👑 شبکه امپرس", "url": NETWORK_URL},
    ]]}
    payload = {
        "chat_id": CHANNEL_ID,
        "text": text,
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True},
        "reply_markup": keyboard,
    }
    last_err = ""
    for attempt in range(1, 4):
        try:
            resp = tg_api("sendMessage", payload)
            if resp.get("ok"):
                return resp
            last_err = json.dumps(resp, ensure_ascii=False)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            last_err = f"HTTP {e.code}: {body}"
            if e.code == 429:
                wait = 5
                try:
                    wait = int(json.loads(body).get("parameters", {}).get("retry_after", 5))
                except Exception:
                    pass
                log(f"⏳ محدودیت نرخ تلگرام؛ {fa(wait)} ثانیه صبر…")
                time.sleep(wait + 1)
                continue
            if e.code in (400, 401, 403, 404):
                break  # تلاش مجدد بی‌فایده است
        except Exception as e:
            last_err = str(e)
            time.sleep(3)
    hints = {
        "401": "توکن بات اشتباه است (BOT_TOKEN) — از BotFather دوباره چک کن.",
        "403": "بات ادمین کانال نیست یا حق Post Messages ندارد.",
        "404": "آدرس API یا نام متد اشتباه است.",
        "400": "CHANNEL_ID اشتباه است یا بات به کانال دسترسی ندارد (chat not found).",
    }
    hint = ""
    for code, h in hints.items():
        if f"HTTP {code}:" in last_err:
            hint = "💡 " + h
            break
    die(f"ارسال به تلگرام ناموفق بود → {last_err}\n{hint}")


# ------------------------- فایل پیوست کانفیگ‌ها -------------------------

def build_attachment_text(selected, date_str, time_str):
    """فایل .txt با همان کانفیگ‌های پست؛ هر خط = یک کانفیگ (قابل کپی برای هر دو اپ)."""
    head = (
        "👑 امپرس | کانفیگ رایگان V2RayNG\n"
        f"📅 {date_str} • ⏰ {time_str}\n"
        "هر خط = یک کانفیگ سالم — مناسب v2rayNG و NPV Tunnel\n"
        "کپی کن ← در اپ دکمه ➕ ← Import از کلیپ‌بورد\n"
        + "=" * 34 + "\n"
    )
    return head + "\n".join(c["link"] for c in selected) + "\n"


def tg_upload_document(file_bytes, filename, caption, reply_to=None):
    """ارسال فایل با sendDocument (multipart/form-data، بدون کتابخانه خارجی)."""
    boundary = "----EmpressBoundary" + hashlib.sha1(filename.encode()).hexdigest()[:16]
    fields = [("chat_id", CHANNEL_ID), ("caption", caption), ("parse_mode", "HTML")]
    if reply_to:
        fields.append(("reply_parameters", json.dumps(
            {"message_id": reply_to, "allow_sending_without_reply": True})))
    body = b""
    for k, v in fields:
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n"
                 f"{v}\r\n").encode("utf-8")
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
             f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
             ).encode("utf-8") + file_bytes + b"\r\n"
    body += f"--{boundary}--\r\n".encode("utf-8")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_config_file(selected, date_str, time_str, reply_to=None):
    """ساخت و ارسال فایل پیوست کانفیگ‌ها؛ برمی‌گرداند: True/False."""
    filename = "Empress-Configs.txt"
    content = build_attachment_text(selected, date_str, time_str).encode("utf-8")
    caption = (
        f"📎 فایل کانفیگ‌های همین پست — {fa(len(selected))} کانفیگ (هر خط = یک کانفیگ)\n\n"
        "📲 روش استفاده: فایل را باز کن ← خط دلخواه را کپی کن ← "
        "در v2rayNG یا NPV Tunnel دکمه ➕ ← Import از کلیپ‌بورد\n\n"
        "👑 @EmpressConfig"
    )
    try:
        resp = tg_upload_document(content, filename, caption, reply_to=reply_to)
        if resp.get("ok"):
            return True
        log(f"⚠️ ارسال فایل پیوست ناموفق: {json.dumps(resp, ensure_ascii=False)[:200]}")
        return False
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", "replace")
        except Exception:
            err_body = ""
        log(f"⚠️ ارسال فایل پیوست ناموفق (HTTP {e.code}): {err_body[:200]}")
        return False
    except Exception as e:
        log(f"⚠️ ارسال فایل پیوست ناموفق: {e}")
        return False


# ------------------------- اجرای اصلی -------------------------

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    log("👑 امپرس | ربات کانفیگ رایگان V2RayNG — شروع اجرا")
    now = datetime.now(TEHRAN_TZ)
    log(f"🕒 زمان تهران: {now.isoformat(timespec='seconds')}")
    if DRY_RUN:
        log("🧯 حالت DRY_RUN فعاله: فقط پیش‌نمایش، بدون ارسال و بدون تغییر posted.json")

    # ۱) دریافت و پارس منابع
    configs = []
    for src in SOURCES:
        try:
            raw = fetch_bytes(src["url"])
            text = raw.decode("utf-8", "replace")
            text = smart_decode(text)
            links = [ln for ln in
                     (l.strip().strip('"').strip("'") for l in text.splitlines())
                     if SCHEME_RE.match(ln)]
            parsed = [c for c in (parse_link(l) for l in links) if c]
            log(f"📥 {src['name']}: {fa_num(len(parsed))} کانفیگ معتبر "
                f"(از {fa_num(len(links))} لینک، {fa_num(len(raw) // 1024)} KB)")
            configs.extend(parsed)
        except Exception as e:
            log(f"⚠️ منبع در دسترس نبود: {src['name']} → {e}")
    if not configs:
        die("هیچ منبعی در دسترس نبود یا هیچ کانفیگی پارس نشد.")

    # ۲) حذف تکراری داخل همین ران (با اثر انگشت)
    for c in configs:
        c["fingerprint"] = hashlib.sha1(c["fp_src"].encode("utf-8")).hexdigest()
    unique = {}
    for c in configs:
        unique.setdefault(c["fingerprint"], c)
    configs = list(unique.values())
    log(f"🧹 بعد از حذف تکراری‌ها: {fa_num(len(configs))} کانفیگ یکتا")

    # ۳) تست TCP — برای هر host:port فقط یک بار تست می‌زنیم (صرفه‌جویی بزرگ)
    targets = sorted({(c["host"], c["port"]) for c in configs})
    log(f"🧪 تست TCP روی {fa_num(len(targets))} سرور یکتا با {fa(WORKERS)} ورکر "
        f"(تایم‌اوت {fa(int(TCP_TIMEOUT))} ثانیه)…")
    latency = {}
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(tcp_ping, h, p): (h, p) for h, p in targets}
        done = 0
        for fut in as_completed(futures):
            hp = futures[fut]
            r = fut.result()
            if r is not None:
                latency[hp] = r
            done += 1
            if done % 1000 == 0:
                log(f"   … {fa_num(done)}/{fa_num(len(targets))} سرور بررسی شد")
    log(f"✅ تست تمام شد در {fa(int(time.monotonic() - t0))} ثانیه → "
        f"{fa_num(len(latency))} سرور زنده از {fa_num(len(targets))}")

    for c in configs:
        c["latency"] = latency.get((c["host"], c["port"]))
    healthy = [c for c in configs if c["latency"] is not None]
    # مرتب‌سازی: اول امتیاز ایران‌پسند بودن (Reality/کلادفلر/TLS)، بعد تأخیر
    for c in healthy:
        c["iran_score"] = iran_score(c)
    healthy.sort(key=lambda c: (-c["iran_score"], c["latency"], len(c["link"])))
    if not healthy:
        die("هیچ سرور زنده‌ای پیدا نشد؛ کمی بعد دوباره اجرا کن.")

    # ۴) فیلتر پست‌شده‌های قبلی + تنوع سرور
    state = load_state()
    prune_state(state)
    posted_fps = set(state.get("items", {}).keys())
    candidates = []
    seen_fp, seen_host = set(), set()
    for c in healthy:
        fp = c["fingerprint"]
        if fp in posted_fps or fp in seen_fp:
            continue
        hk = (c["host"], c["port"])
        if hk in seen_host:
            continue
        candidates.append(c)
        seen_fp.add(fp)
        seen_host.add(hk)
    log(f"🆕 کاندیدهای جدید (پست‌نشده و غیرتکراری): {fa_num(len(candidates))}")

    # ۵) انتخاب کانفیگ‌ها: اول VLESS_COUNT تا بهترین VLESS (پیش‌فرض ۶)، بعد بقیه اسلات‌ها
    #    از بقیه پروتکل‌ها به ترتیب اولویت — پیش‌فرض نهایی: ۸ کانفیگ = ۶ VLESS + ۲ دیگر
    date_str = jalali_date_str(now)
    time_str = fa(now.strftime("%H:%M"))
    by_proto = {}
    for c in candidates:  # candidates از قبل بر اساس تأخیر مرتب‌اند
        by_proto.setdefault(c["proto"], []).append(c)
    order = [p for p in PROTO_PRIORITY if p in by_proto]
    order += [p for p in by_proto if p not in order]

    selected = []

    def fits(c):
        """اگر با این کانفیگ پیام در سقف طول تلگرام جا شد، اضافه کن؛ وگرنه دورش بریز."""
        trial = selected + [c]
        if tg_len(build_message(trial, date_str, time_str)) <= TG_LIMIT - TG_SAFETY:
            selected.append(c)
            return True
        return False

    # ۵-۱) سهم VLESS — بهترین‌ها از نظر پینگ
    vless_goal = min(VLESS_COUNT, CONFIGS_PER_POST)
    vless_pool = by_proto.get("vless", [])
    while vless_pool and len(selected) < vless_goal:
        c = vless_pool.pop(0)
        fits(c)
    log(f"⚡️ سهم VLESS: {fa(len(selected))} از هدف {fa(vless_goal)}")

    # ۵-۲) پر کردن اسلات‌های باقی‌مانده: رفت‌وبرگشت بین بقیه پروتکل‌ها به ترتیب اولویت
    others = [p for p in order if p != "vless"]
    slot = 0
    while len(selected) < CONFIGS_PER_POST and any(by_proto.get(p) for p in others):
        proto = others[slot % len(others)]
        pool = by_proto.get(proto) or []
        if not pool:
            slot += 1  # این پروتکل کاندید نداشت؛ برو سراغ پروتکل بعدی
            continue
        c = pool.pop(0)
        by_proto[proto] = pool
        fits(c)
        slot += 1
    if not selected:
        die("کاندیدی برای پست پیدا نشد (همه تکراری بودند یا هیچ‌کدام در محدودیت طول جا نشد).")
    if len(selected) < CONFIGS_PER_POST:
        log(f"⚠️ فقط {fa(len(selected))} کانفیگ انتخاب شد (هدف: {fa(CONFIGS_PER_POST)}).")
    for i, c in enumerate(selected, 1):
        log(f"   {i}. {proto_title(c)} | {c['host']}:{c['port']} | "
            f"{c['latency']}ms | امتیاز ایران {c['iran_score']:+d} | طول لینک {len(c['link'])}")

    message = build_message(selected, date_str, time_str)
    button_url = TUTORIAL_URL or CHANNEL_LINK or "https://t.me/EmpressConfig"
    log(f"📏 طول پیام: {tg_len(message)} واحد از ۴۰۹۶")
    log(f"🔘 دکمه شیشه‌ای: [📌 آموزش اتصال] → {button_url}")

    # ۶) ارسال یا پیش‌نمایش
    if DRY_RUN:
        log("────── پیش‌نمایش قابل‌خواندن (آن‌طور که تلگرام نشان می‌دهد) ──────")
        print(html.unescape(message))
        log("────── پایان پیش‌نمایش ──────")
        log("🧯 DRY_RUN تمام شد. چیزی به کانال ارسال نشد و posted.json دست نخورد.")
    else:
        if not BOT_TOKEN or not CHANNEL_ID:
            die("BOT_TOKEN یا CHANNEL_ID تنظیم نشده. سکرت‌های گیت‌هاب را چک کن "
                "(یا برای تست از DRY_RUN=1 استفاده کن).")
        resp = send_post(message)
        msg_id = resp.get("result", {}).get("message_id", "?")
        log(f"🎉 پست با موفقیت در کانال ارسال شد (message_id={msg_id})")
        # ۶-ب) فایل پیوست همان کانفیگ‌ها (به‌صورت ریپلای به پست) — برای کپی سریع در هر دو اپ
        file_ok = send_config_file(selected, date_str, time_str,
                                   reply_to=msg_id if isinstance(msg_id, int) else None)
        if file_ok:
            log("📎 فایل پیوست Empress-Configs.txt هم ارسال شد.")
        # ۷) ثبت در حافظه dedupe → workflow این فایل را با پیام [skip ci] کامیت می‌کند
        now_iso = now.isoformat(timespec="seconds")
        for c in selected:
            state["items"][c["fingerprint"]] = {
                "ts": now_iso, "proto": c["proto"], "host": c["host"], "port": c["port"],
            }
        state["updated"] = now_iso
        save_state(state)
        log(f"💾 {fa(len(selected))} اثر جدید در state/posted.json ثبت شد.")

        # ۸) سابسکریپشن اختصاصی امپرس (فاز ۲): بهترین کانفیگ‌های زنده؛ کاربر یک بار URL را
        #    در v2rayNG/NPV Tunnel وارد می‌کند و همیشه کانفیگ تازه دارد.
        sub_links = [c["link"] for c in healthy[:SUB_MAX_CONFIGS]]
        sub_text = "\n".join(sub_links) + "\n"
        with open(SUB_FILE, "w", encoding="utf-8") as f:
            f.write(sub_text)
        with open(SUB_B64_FILE, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(sub_text.encode("utf-8")).decode("ascii"))
        log(f"📡 سابسکریپشن با {fa(len(sub_links))} کانفیگ زنده در state/sub.txt (و نسخه base64) به‌روز شد.")

    # آمار این ران (برای دیباگ در لاگ اکشنز)
    os.makedirs(STATE_DIR, exist_ok=True)
    stats = {
        "ran_at": now.isoformat(timespec="seconds"),
        "dry_run": DRY_RUN,
        "parsed_unique": len(configs),
        "targets": len(targets),
        "alive": len(healthy),
        "candidates_new": len(candidates),
        "posted": len(selected),
        "message_len": tg_len(message),
    }
    with open(LAST_RUN_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    log("📊 آمار در state/last_run.json ذخیره شد. ✅ تمام")


if __name__ == "__main__":
    main()
