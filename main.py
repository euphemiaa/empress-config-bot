#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
👑 امپرس | کانفیگ رایگان V2RayNG — ربات پست خودکار (فاز ۱)
کانال: https://t.me/EmpressConfig  |  شبکه اصلی: @EmpressNetwork

کارها در هر اجرا (بدون هیچ کتابخانه خارجی — فقط پایتون استاندارد):
  ۱) دریافت لیست کانفیگ از منابع عمومی گیت‌هاب (SOURCES پایین فایل)
  ۲) دیکود base64 در صورت نیاز + پارس لینک‌های vmess / vless / trojan / ss
  ۳) تست TCP به host:port هر سرور (فیلتر اولیه) + تست واقعی پروتکل با موتور Xray:
     برای هر کاندیدای برتر یک پروسهٔ xray با پروکسی SOCKS لوکال بالا می‌آید و یک
     درخواست HTTP واقعی از داخل تونل رد می‌شود؛ کانفیگ‌های «پورت باز ولی مُرده»
     (همان‌هایی که در ایران تایم‌اوت می‌دهند) این‌جا حذف می‌شوند
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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import xray_test  # تستر واقعی پروتکل با موتور Xray (هم‌پوشنه با همین فایل)

# ------------------------- تنظیمات -------------------------

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
CHANNEL_ID = os.environ.get("CHANNEL_ID", "").strip()
CHANNEL_LINK = os.environ.get("CHANNEL_LINK", "").strip() or "https://t.me/EmpressConfig"
DRY_RUN = os.environ.get("DRY_RUN", "0").strip().lower() in ("1", "true", "yes", "y")

WORKERS = int(os.environ.get("WORKERS", "40"))
TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "3"))
SUB_URL = (os.environ.get("SUB_URL", "").strip()
           or "https://raw.githubusercontent.com/euphemiaa/empress-config-bot/master/state/sub_base64.txt")
# ⚙️ موتور تست واقعی (Xray) — اگر باینری نبود، خودکار به تست TCP قدیمی برمی‌گردد
XRAY_TEST = os.environ.get("XRAY_TEST", "1").strip().lower() in ("1", "true", "yes")
XRAY_PATH = os.environ.get("XRAY_PATH", "bin/xray").strip()
XRAY_TEST_LIMIT = max(0, int(os.environ.get("XRAY_TEST_LIMIT", "300")))
XRAY_TIMEOUT = float(os.environ.get("XRAY_TIMEOUT", "9"))
XRAY_WORKERS = max(1, int(os.environ.get("XRAY_WORKERS", "50")))
CONFIGS_PER_POST = max(1, min(15, int(os.environ.get("CONFIGS_PER_POST", "8"))))
VLESS_COUNT = max(0, int(os.environ.get("VLESS_COUNT", "6")))
SUB_MAX_CONFIGS = max(1, int(os.environ.get("SUB_MAX_CONFIGS", "300")))
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
FEEDBACK_FILE = os.path.join(STATE_DIR, "feedback.json")
TUTORIAL_FILE = os.path.join(STATE_DIR, "tutorial.json")

TEHRAN_TZ = timezone(timedelta(hours=3, minutes=30))  # ایران دی‌سایور ندارد


def tutorial_url():
    """لینک پست آموزشی پین‌شده: اول متغیر TUTORIAL_URL، بعد message_id واقعی در
    state/tutorial.json (همان پست آموزشی پین‌شدهٔ کانال)، بعد لینک کانال."""
    env = os.environ.get("TUTORIAL_URL", "").strip()
    if env:
        return env
    try:
        with open(TUTORIAL_FILE, encoding="utf-8") as f:
            mid = int(json.load(f).get("message_id") or 0)
        if mid > 0:
            return f"{(CHANNEL_LINK or 'https://t.me/EmpressConfig').rstrip('/')}/{mid}"
    except Exception:
        pass
    return CHANNEL_LINK or "https://t.me/EmpressConfig"

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
    {
        "name": "mahdibland/V2RayAggregator (Eternity — تست‌شده)",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    },
    {
        "name": "mahdibland/V2RayAggregator (EternityAir — تست‌شده)",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/EternityAir.txt",
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


def proto_title(c, suffix=True):
    """عنوان نمایشی پروتکل؛ برای vless/trojan نوع security هم می‌آید (مثل VLESS Reality).
    با suffix=True نشان‌های ☁️CDN (پشت کلادفلر) و 🔁 (بازیافتی از پست قبلی) هم اضافه می‌شود."""
    label = PROTO_LABEL.get(c["proto"], c["proto"].upper())
    m = re.search(r"[?&]security=([a-z0-9]+)", c.get("link", ""), re.I)
    title = label
    if m:
        sec = m.group(1).lower()
        if sec == "reality":
            title = label + " Reality"
        elif sec == "tls":
            title = label + " TLS"
    elif suffix and c.get("proto") == "vmess":
        if str((c.get("vm") or {}).get("tls", "")).strip().lower() == "tls":
            title = label + " TLS"
    if suffix and is_cloudflare_ip(c.get("host", "")):
        title += " ☁️CDN"
    if suffix and c.get("reused"):
        title = "🔁 " + title
    return title


def proto_hashtag(c):
    t = re.sub(r"[^A-Za-z0-9_]", "_", proto_title(c, suffix=False).replace(" ", "_")).strip("_")
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
            "vm": {k: v for k, v in data.items() if k != "ps"},
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
    q = {k: v[0] for k, v in urllib.parse.parse_qs(sp.query).items()}
    sec = (q.get("security") or "").strip().lower()
    net = (q.get("type") or "tcp").strip().lower() or "tcp"
    return {"proto": scheme, "link": link, "host": host, "port": port,
            "name": name, "fp_src": canonical, "net": net, "sec": sec, "q": q}


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
    method, _, password = identity.partition(":")
    return {"proto": "ss", "link": link, "host": host, "port": port,
            "name": host, "fp_src": "ss|" + identity + "|" + hostport.lower(),
            "method": urllib.parse.unquote(method),
            "password": urllib.parse.unquote(password),
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
    if is_cloudflare_ip(host) or is_cloudflare_ip(c.get("rip")):
        score += 14                      # IP کلادفلر = پشت CDN؛ بلاکش یعنی بلاک نصف اینترنت
    elif not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        score += 6                       # دامنه (به‌خصوص پشت CDN) بهتر از IP داده‌سنتری خام
    score += org_penalty(c.get("org"))   # جریمهٔ سرورهای داخل رنج بلاک/محدودشدهٔ ایران
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


# ------------------------- تشخیص شرکت میزبان (ASN) و جریمهٔ رنج‌های بلاک ایران -------------------------
# 🔑 ایدهٔ کلیدی ضد تایم‌اوت: فیلترینگ ایران رنج کامل برخی ارائه‌دهنده‌ها را بلاک/محدود
# کرده است (شهرت‌ترین: Oracle Cloud؛ سپس DigitalOcean، Hetzner، Linode و Vultr).
# این بلاک‌ها از بیرون ایران دیده نمی‌شوند (تست‌های ما سبز می‌شوند) ولی کاربر ایرانی
# تایم‌اوت می‌گیرد. پس هویت واقعی هر سرور را پیدا می‌کنیم: اول DNS، بعد ip-api (رایگان)
# و به کانفیگ‌های رنج‌های بدبخت جریمهٔ سنگینِ ترتیبی می‌دهیم (حذف کامل نمی‌شوند؛ فقط
# وقتی جایگزین بهتر هست انتخاب نمی‌شوند).

ORG_PENALTY = [
    ("oracle", -45),        # Oracle Cloud: تقریباً همیشه از داخل ایران مرده است
    ("digitalocean", -16),  # محدود/کند در ایران؛ فقط با TLS گاهی جواب می‌دهد
    ("hetzner", -14),
    ("linode", -12),
    ("vultr", -12),
    ("ovh", -10),
]


def org_penalty(org):
    """جریمه بر اساس نام شرکت میزبان؛ بدترین تطبیق ملاک است."""
    o = (org or "").lower()
    if not o:
        return 0
    pen = 0
    for kw, p in ORG_PENALTY:
        if kw in o:
            pen = min(pen, p)
    return pen


def resolve_v4(host):
    """اولین IPv4 دامنه؛ اگر خودش IP بود همان را برمی‌گرداند؛ شکست → None."""
    h = str(host).strip("[]")
    if h.lower().startswith("::ffff:"):
        h = h[7:]
    if ip_to_int(h) is not None:
        return h
    try:
        infos = socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


IPAPI_BATCH = "http://ip-api.com/batch?fields=query,as,org"


def fetch_orgs(ips):
    """نام ASN/شرکت برای دسته‌های ۱۰۰تایی IP از ip-api؛ در دسترس نبود → دیکشنری خالی."""
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        for attempt in (1, 2):
            try:
                req = urllib.request.Request(
                    IPAPI_BATCH, data=json.dumps(chunk).encode("utf-8"),
                    headers={"Content-Type": "application/json",
                             "User-Agent": "EmpressConfigBot/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    for row in json.loads(resp.read().decode("utf-8")):
                        if isinstance(row, dict) and row.get("query"):
                            out[row["query"]] = str(row.get("as") or row.get("org") or "")
                break
            except Exception as e:
                if attempt == 2:
                    log(f"⚠️ ip-api پاسخ نداد ({e})؛ جریمهٔ ASN این ران اعمال نمی‌شود.")
                else:
                    time.sleep(2)
    return out


def refine_with_dns(configs, limit=400):
    """برای بهترین کاندیداها: DNS → ASN → امتیاز مجدد. نتیجه: سرورهای Oracle و
    رفقایش به ته لیست می‌روند و کانفیگ‌های پشت کلادفلر (حتی با دامنه) پاداش می‌گیرند."""
    top = configs[:limit]
    hosts = sorted({c["host"] for c in top})
    log(f"🌍 تشخیص هویت واقعی سرورها (DNS + ASN) برای {fa(len(hosts))} دامنه/IP برتر…")
    t0 = time.monotonic()
    rip = {}
    with ThreadPoolExecutor(max_workers=min(WORKERS, 100)) as pool:
        futs = {pool.submit(resolve_v4, h): h for h in hosts}
        for fut in as_completed(futs):
            rip[futs[fut]] = fut.result()
    ips = sorted({ip for ip in rip.values() if ip})
    orgs = fetch_orgs(ips)
    changed = 0
    for c in top:
        c["rip"] = rip.get(c["host"])
        c["org"] = orgs.get(c.get("rip") or "", "")
        new = iran_score(c)
        if new != c["iran_score"]:
            changed += 1
        c["iran_score"] = new
    oracle_n = sum(1 for c in top if "oracle" in (c.get("org") or "").lower())
    log(f"🌍 ASN: {fa(len(orgs))} IP شناسایی شد در {fa(int(time.monotonic() - t0))} ثانیه؛ "
        f"امتیاز {fa(changed)} کانفیگ بازنگری شد؛ سرور Oracle: {fa(oracle_n)} عدد (به ته لیست می‌روند).")


# ------------------------- بازخورد کاربران (👍/👎) — حقیقت‌سنج از داخل ایران -------------------------
# تست از سرور خارج، فیلترینگ داخل ایران را نمی‌بیند؛ تنها معیار قابل‌اتکا رأی خود
# کاربران است. هر پست دو ردیف دکمهٔ رأی دارد؛ هر ران، رأی‌های ثبت‌شده از طریق
# getUpdates خوانده می‌شود، به رأی‌دهنده جواب می‌دهد و در state/feedback.json می‌نشیند.
# ران بعدی همین رأی‌ها را به امتیاز هر کانفیگ اضافه می‌کند (حلقهٔ یادگیری ۹۰ دقیقه‌ای).

FB_OK_W, FB_BAD_W, FB_CLAMP = 12, 15, 45
_FB = {"offset": 0, "votes": {}}


def load_feedback():
    try:
        with open(FEEDBACK_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("votes"), dict):
            d.setdefault("offset", 0)
            return d
    except Exception:
        pass
    return {"offset": 0, "votes": {}}


def save_feedback(fb):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(fb, f, ensure_ascii=False, indent=1)


def prune_feedback(fb, days=14):
    cutoff = (datetime.now(TEHRAN_TZ) - timedelta(days=days)).isoformat(timespec="seconds")
    fb["votes"] = {k: v for k, v in fb["votes"].items()
                   if str(v.get("last", "")) >= cutoff or not v.get("last")}


def fb_delta(fp):
    """وزن رأی کاربران برای یک اثر انگشت؛ بازهٔ [−۴۵، +۴۵]."""
    v = _FB.get("votes", {}).get((fp or "")[:16])
    if not v:
        return 0
    d = FB_OK_W * int(v.get("ok", 0)) - FB_BAD_W * int(v.get("bad", 0))
    return max(-FB_CLAMP, min(FB_CLAMP, d))


def process_feedback():
    """رأی‌های جدید را می‌خواند، به رأی‌دهنده جواب می‌دهد و state را ذخیره می‌کند."""
    global _FB
    _FB = load_feedback()
    prune_feedback(_FB)
    if not BOT_TOKEN:
        return 0
    processed, offset = 0, int(_FB.get("offset", 0))
    wanted = str(CHANNEL_ID).lstrip("@").lower()
    for _page in range(12):
        try:
            resp = tg_api("getUpdates", {"offset": offset, "timeout": 0, "limit": 100,
                                         "allowed_updates": ["callback_query"]})
        except Exception as e:
            log(f"⚠️ getUpdates ناموفق: {e}")
            break
        if not resp.get("ok"):
            break
        updates = resp.get("result") or []
        if not updates:
            break
        for u in updates:
            offset = max(offset, int(u.get("update_id", 0)) + 1)
            cq = u.get("callback_query") or {}
            m = re.match(r"^([ud]):([0-9a-f]{8,40})$", str(cq.get("data") or ""))
            if not m:
                continue
            chat = ((cq.get("message") or {}).get("chat")) or {}
            uname = str(chat.get("username") or "").lower()
            cid = str(chat.get("id") or "")
            if wanted not in (uname, cid):  # فقط رأی روی پست‌های خود کانال
                continue
            v = _FB["votes"].setdefault(m.group(2), {"ok": 0, "bad": 0, "last": ""})
            v["ok" if m.group(1) == "u" else "bad"] += 1
            v["last"] = datetime.now(TEHRAN_TZ).isoformat(timespec="seconds")
            processed += 1
            try:
                tg_api("answerCallbackQuery", {
                    "callback_query_id": cq.get("id"),
                    "text": "✅ رأیت ثبت شد! رأی کاربران، انتخاب پست بعدی را برای ایران هوشمندتر می‌کند.",
                })
            except Exception:
                pass
    if processed:
        _FB["offset"] = offset
        save_feedback(_FB)
        log(f"🗳 {fa(processed)} رأی تازه ثبت شد (مجموع کانفیگ‌های رأی‌دار: {fa(len(_FB['votes']))}).")
    return processed


def sortkey(c):
    """کلید مرتب‌سازی نهایی: امتیاز ایران + رأی کاربران، بعد پینگ واقعی، بعد کوتاهی لینک."""
    return (-(c["iran_score"] + fb_delta(c["fingerprint"])), c["latency"], len(c["link"]))


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
        trophy = " 🏆" if (c["iran_score"] + fb_delta(c["fingerprint"])) >= 58 else ""
        lines.append(f"{num} ⚡️ <b>{proto_title(c)}</b>{trophy} | ⏱ پینگ {fa(c['latency'])} ms")
        lines.append(f"<code>{html.escape(c['link'], quote=False)}</code>")
        lines.append("")
    lines.append("🏆 = بهترین شانس اتصال در ایران — اول این‌ها را تست کن")
    lines.append("📲 <b>راهنمای سریع:</b>")
    lines.append("۱️⃣ کانفیگ را کپی کن ← در اپ ➕ ← Import از کلیپ‌بورد")
    lines.append("۲️⃣ وصل نشد؟ بعدی را تست کن؛ Fragment را روشن کن — آموزش کامل: پست پین‌شده")
    lines.append("۳️⃣ 🗳 به هر کانفیگ رأی 👍/👎 بده؛ رأی شما پست بعدی را هوشمندتر می‌کند")
    lines.append("۴️⃣ 📡 <b>ساب کامل</b>: فایل All-Configs (صدها کانفیگ سالم) ← کپی ← Import ← با رادار اپ زنده‌ها را پیدا کن")
    lines.append(f"📎 پیوست پایین پست = همین {fa(len(selected))} کانفیگ برای کپی سریع")
    lines.append("")
    lines.append(f"⬇️ <a href=\"{APP_V2RAYNG_URL}\">دانلود v2rayNG</a> | "
                 f"<a href=\"{APP_NPV_URL}\">دانلود NPV Tunnel</a>")
    lines.append("🌟 با دوستانت به اشتراک بگذار 👌")
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

def tg_api(method, payload, timeout=60):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_post(text, selected=None):
    """ارسال پست + دکمه‌ها؛ اگر selected بدهیم، دو ردیف دکمهٔ رأی 👍/👎 هم اضافه می‌شود."""
    kb = []
    if selected:
        row_up, row_down = [], []
        for i, c in enumerate(selected):
            n = NUM_EMOJI[i] if i < len(NUM_EMOJI) else fa(i + 1)
            fp = c["fingerprint"][:16]
            row_up.append({"text": f"👍{n}", "callback_data": f"u:{fp}"})
            row_down.append({"text": f"👎{n}", "callback_data": f"d:{fp}"})
        kb.append(row_up)
        kb.append(row_down)
    kb.append([
        {"text": "📌 آموزش اتصال", "url": tutorial_url()},
        {"text": "📡 ساب کامل", "url": SUB_URL},
    ])
    kb.append([
        {"text": "👑 شبکه امپرس", "url": NETWORK_URL},
    ])
    keyboard = {"inline_keyboard": kb}
    payload = {
        "chat_id": CHANNEL_ID,
        "text": text,
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True},
        "reply_markup": keyboard,
    }
    last_err = ""
    # 🛡 شبکهٔ رانر↔تلگرام گاهی لحظه‌ای قطع می‌شود؛ ۵ تلاش با بک‌افزایشی (تا ~۸۵ ثانیه)
    backoff = (3, 6, 12, 25, 40)
    for attempt in range(1, 6):
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
            wait = backoff[min(attempt - 1, len(backoff) - 1)]
            log(f"⚠️ خطای شبکه در ارسال (تلاش {fa(attempt)} از ۵): {e} → {fa(wait)} ثانیه صبر…")
            time.sleep(wait)
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


# ------------------------- نام‌گذاری برند کانفیگ‌های ساب -------------------------

def brand_link(c, rank):
    """🏷 نام نمایشی (remark) هر کانفیگ ساب را به «امپرس-۰۰۱ | Reality | CDN | 443» تبدیل
    می‌کند تا کاربر موقع تست رادار در اپ، بهترین‌ها را همان اول تشخیص دهد.
    فقط نام نمایشی عوض می‌شود (fragment برای vless/trojan/ss و فیلد ps برای vmess)؛
    خود اتصال دست نمی‌خورد و اگر چیزی خراب شد لینک اصلی برگردانده می‌شود.
    امپرس-۰۰۱ = بالاترین امتیاز ایران‌پسند بودن (Reality/کلادفلر/۴۴۳ + رأی کاربران)."""
    link = c["link"]
    try:
        flags = []
        m = re.search(r"[?&]security=([a-z0-9]+)", link, re.I)
        sec = (m.group(1).lower() if m else c.get("sec")) or ""
        if sec == "reality":
            flags.append("Reality")
        elif sec == "tls":
            flags.append("TLS")
        if is_cloudflare_ip(c.get("host", "")) or is_cloudflare_ip(c.get("rip", "")):
            flags.append("CDN")
        if c.get("port") == 443:
            flags.append("443")
        name = f"امپرس-{rank:03d}" + ((" | " + " | ".join(flags)) if flags else "")
        if link.lower().startswith("vmess://"):
            payload = link[len("vmess://"):]
            dec = b64_decode_any(payload)
            data = json.loads(dec) if dec else None
            if not isinstance(data, dict):
                return link
            data["ps"] = name
            enc = base64.b64encode(json.dumps(
                data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii")
            return "vmess://" + enc
        base = link.split("#", 1)[0]
        return base + "#" + urllib.parse.quote(name, safe="")
    except Exception:
        return link


# ------------------------- فایل پیوست کانفیگ‌ها -------------------------

def build_attachment_text(selected, date_str, time_str):
    """فایل .txt با همان کانفیگ‌های پست؛ هر خط = یک کانفیگ (قابل کپی برای هر دو اپ)."""
    head = (
        "👑 امپرس | کانفیگ رایگان V2RayNG\n"
        f"📅 {date_str} • ⏰ {time_str}\n"
        "هر خط = یک کانفیگ سالم — مناسب v2rayNG و NPV Tunnel\n"
        "کپی کن ← در اپ دکمه ➕ ← Import از کلیپ‌بورد\n"
        "📡 سابسکریپشن کامل (صدها کانفیگ سالم، هر ۹۰ دقیقه تازه):\n"
        + SUB_URL + "\n"
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
    return _upload_or_warn(content, filename, caption, reply_to)


def send_sub_document(sub_links, date_str, time_str, reply_to=None, engine="tcp-only"):
    """
    📡 پیوست «ساب کامل» — همهٔ کانفیگ‌های سالم همین ران.
    این فایل مستقل از دسترسی عمومی ریپو کار می‌کند (اگر گیت‌هاب ریپو را خصوصی
    کند یا raw در دسترس نباشد، کاربران کانال همچنان ساب کامل را از تلگرام می‌گیرند).
    """
    if engine == "xray":
        tested_line = "هر کانفیگ با تونل واقعی Xray تست شده است"
    else:
        tested_line = "هر کانفیگ با تست پورت/سرور از دیتاسنتر تست شده است"
    head = (
        "👑 امپرس | ساب کامل — همهٔ کانفیگ‌های سالم همین ران\n"
        f"📅 {date_str} • ⏰ {time_str}\n"
        f"{fa(len(sub_links))} کانفیگ سالم ({tested_line})\n"
        "🏷 نام هر کانفیگ = امپرس-ردیف + نشانه‌ها؛ امپرس-۰۰۱ یعنی بهترین شانس اتصال در ایران\n"
        "   Reality=مقاوم در برابر فیلترینگ | CDN=پشت کلادفلر | 443=پورت امن\n"
        "روش استفاده: همهٔ خطوط را کپی کن ← در اپ دکمه ➕ ← Import از کلیپ‌بورد\n"
        "بعد در لیست با دکمهٔ تست اپ (رادار/پینگ) سرور زندهٔ لحظهٔ خودت را پیدا کن\n"
        "🔗 نسخهٔ Subscription (اگر ریپو پابلیک باشد؛ هر ۹۰ دقیقه تازه می‌شود):\n"
        + SUB_URL + "\n"
        + "=" * 34 + "\n"
    )
    content = (head + "\n".join(sub_links) + "\n").encode("utf-8")
    caption = (
        f"📡 ساب کامل — {fa(len(sub_links))} کانفیگ سالمِ تست‌شده\n\n"
        "📲 فایل را باز کن ← انتخاب همه ← کپی ← در v2rayNG یا NPV Tunnel دکمه ➕ ← "
        "Import از کلیپ‌بورد ← بعد با دکمهٔ تست اپ (رادار) سرور زنده را پیدا کن\n\n"
        f"🏷 کانفیگ‌ها از بهترین به بعد مرتب‌اند: امپرس-۰۰۱ = بهترین شانس در ایران؛ "
        "Reality و CDN و 443 یعنی مقاوم‌تر در برابر فیلترینگ\n\n"
        "💡 اگر یکی تایم‌اوت داد، ناراحت نشو؛ از بین صدها تای این فایل حتماً چندین سرور "
        "زندهٔ قابل‌اتصال پیدا می‌شود — همه را Import کن و تست بزن (پینگ‌های ۳ تا ۶ ثانیه‌ای هم اتصال سالم یعنی)\n\n"
        "👑 @EmpressConfig"
    )
    return _upload_or_warn(content, "Empress-All-Configs.txt", caption, reply_to)


def _upload_or_warn(content, filename, caption, reply_to):
    """ارسال سند با مدیریت خطا؛ شکست پیوست فایل، پست اصلی را نمی‌کشد."""
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

    # ۰) 🗳 خواندن رأی‌های 👍/👎 کاربران از ران قبلی (حلقهٔ بازخورد ایران)
    fb_processed = process_feedback()

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
    healthy.sort(key=sortkey)
    if not healthy:
        die("هیچ سرور زنده‌ای پیدا نشد؛ کمی بعد دوباره اجرا کن.")

    # ۳-ب) 🔥 تست واقعی پروتکل با موتور Xray — مرحلهٔ کلیدی ضد «تایم‌اوت در ایران».
    # TCP فقط می‌فهمد پورت باز است؛ این‌جا تونل واقعی بسته می‌شود و HTTP واقعی از
    # داخلش رد می‌شود. کانفیگ‌های «پورت باز ولی پروتکل مُرده» حذف می‌شوند.
    engine, xray_tested_n, xray_alive_n = "tcp-only", 0, 0
    xray_bin = None
    for _cand_path in (XRAY_PATH, os.path.join(os.getcwd(), "xray"), "xray"):
        if os.path.isfile(_cand_path) and os.access(_cand_path, os.X_OK):
            xray_bin = _cand_path
            break
    if XRAY_TEST and xray_bin and healthy:
        # انتخاب کاندیداها: بهترین‌ها از نظر امتیاز ایران‌پسند، با سهمیه برای هر پروتکل
        caps = {"vless": 150, "vmess": 60, "trojan": 50, "ss": 40}
        pools = {}
        for c in healthy:
            pools.setdefault(c["proto"], []).append(c)
        protos_order = ([p for p in PROTO_PRIORITY if pools.get(p)]
                        + [p for p in pools if p not in PROTO_PRIORITY])
        pool_cands = []
        while len(pool_cands) < XRAY_TEST_LIMIT and any(pools.get(p) for p in protos_order):
            for p in protos_order:
                if pools.get(p) and sum(1 for x in pool_cands if x["proto"] == p) < caps.get(p, 30):
                    pool_cands.append(pools[p].pop(0))
                if len(pool_cands) >= XRAY_TEST_LIMIT:
                    break
        log(f"🚀 تست واقعی با موتور Xray ({xray_bin}): {fa(len(pool_cands))} کاندیدای برتر، "
            f"{fa(XRAY_WORKERS)} ورکر، تایم‌اوت {fa(int(XRAY_TIMEOUT))} ثانیه…")
        t1 = time.monotonic()
        results = xray_test.run_xray_tests(pool_cands, xray_bin,
                                           workers=XRAY_WORKERS, timeout=XRAY_TIMEOUT)
        xray_tested_n = len(pool_cands)
        alive_list = []
        for c, r in zip(pool_cands, results):
            if r.get("ok"):
                c["latency"] = r["ms"]          # تأخیر واقعی تونل
                c["alive_via"] = "xray"
                alive_list.append(c)
            else:
                c["alive_via"] = "dead:" + str(r.get("why", ""))[:40]
        xray_alive_n = len(alive_list)
        reasons = Counter(str(r.get("why", ""))[:40] for r in results if not r.get("ok"))
        log(f"✅ تست Xray در {fa(int(time.monotonic() - t1))} ثانیه تمام شد → "
            f"{fa(xray_alive_n)} کانفیگ واقعاً زنده (تونل واقعی + HTTP واقعی) از {fa(xray_tested_n)}")
        if reasons:
            log("   🔍 دلایل مرگ: " + ", ".join(f"{k}×{v}" for k, v in reasons.most_common(6)))
        if alive_list:
            healthy = alive_list
            engine = "xray"
            healthy.sort(key=sortkey)
        if len(healthy) < CONFIGS_PER_POST:
            tested_ids = {id(c) for c in pool_cands}
            for c in configs:
                if id(c) in tested_ids or c["latency"] is None:
                    continue
                c["alive_via"] = "tcp-only"
                healthy.append(c)
                if len(healthy) >= CONFIGS_PER_POST:
                    break
            log(f"⚠️ خروجی Xray کم بود؛ با بهترین‌های TCP تا {fa(len(healthy))} تکمیل شد.")
    else:
        log("⚠️ باینری Xray پیدا نشد (XRAY_PATH=" + XRAY_PATH + ") → فقط تست TCP انجام شد.")

    # ۳-ج) 🌍 بازبینی امتیاز با هویت واقعی ASN (Oracle/Hetzner/DO بلاک ایران؛ کلادفلر آزاد)
    refine_with_dns(healthy, limit=400)
    healthy.sort(key=sortkey)

    # ۴) فیلتر پست‌شده‌های قبلی + تنوع سرور
    state = load_state()
    prune_state(state)
    posted_fps = set(state.get("items", {}).keys())
    candidates = []
    skipped_posted = []   # سالم‌های قبلاً پست‌شده؛ فقط اگر کاندید جدید کم آمد بازیافت می‌شوند
    seen_fp, seen_host = set(), set()
    for c in healthy:
        fp = c["fingerprint"]
        if fp in seen_fp:
            continue
        hk = (c["host"], c["port"])
        if hk in seen_host:
            continue
        if fp in posted_fps:
            skipped_posted.append(c)
            continue
        candidates.append(c)
        seen_fp.add(fp)
        seen_host.add(hk)
    log(f"🆕 کاندیدهای جدید (پست‌نشده و غیرتکراری): {fa_num(len(candidates))} "
        f"(رزرو بازیافت: {fa_num(len(skipped_posted))} پست‌شدهٔ سالم)")

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

    # ۵-۳) اگر کاندید جدید کم آمد، بهترین‌های سالمِ پست‌شدهٔ قبلی را با نشان 🔁 بازیافت کن
    reused_n = 0
    if len(selected) < CONFIGS_PER_POST:
        for c in skipped_posted:
            if len(selected) >= CONFIGS_PER_POST:
                break
            if (c["host"], c["port"]) in seen_host:
                continue
            before = len(selected)
            c["reused"] = True
            fits(c)
            reused_n += len(selected) - before
        if reused_n:
            log(f"🔁 {fa(reused_n)} کانفیگ از پست‌های قبلی بازیافت شد (کمبود کاندید جدید).")
    if not selected:
        die("کاندیدی برای پست پیدا نشد (همه تکراری بودند یا هیچ‌کدام در محدودیت طول جا نشد).")
    if len(selected) < CONFIGS_PER_POST:
        log(f"⚠️ فقط {fa(len(selected))} کانفیگ انتخاب شد (هدف: {fa(CONFIGS_PER_POST)}).")
    for i, c in enumerate(selected, 1):
        log(f"   {i}. {proto_title(c)} | {c['host']}:{c['port']} | "
            f"{c['latency']}ms | امتیاز ایران {c['iran_score']:+d} | {c.get('alive_via', '?')}")

    message = build_message(selected, date_str, time_str)
    log(f"📏 طول پیام: {tg_len(message)} واحد از ۴۰۹۶")
    log(f"🔘 دکمه‌ها: [📌 آموزش اتصال] → {tutorial_url()} | رأی‌گیری 👍👎 برای {fa(len(selected))} کانفیگ")

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
        resp = send_post(message, selected)
        msg_id = resp.get("result", {}).get("message_id", "?")
        log(f"🎉 پست با موفقیت در کانال ارسال شد (message_id={msg_id})")
        reply_to = msg_id if isinstance(msg_id, int) else None
        # ۶-ب) فایل پیوست همان کانفیگ‌ها — برای کپی سریع در هر دو اپ
        if send_config_file(selected, date_str, time_str, reply_to=reply_to):
            log("📎 فایل پیوست Empress-Configs.txt هم ارسال شد.")
        # ۶-ج) 📡 پیوست «ساب کامل»: همهٔ کانفیگ‌های تونل-تأییدشدهٔ همین ران مستقیماً در
        #     تلگرام — مستقل از دسترسی عمومی ریپو (اگر گیت‌هاب ریپو را خصوصی/محدود کند
        #     کاربران همچنان ساب کامل را دارند).
        # 🏷 لینک‌های ساب با نام برند «امپرس-ردیف | نشانه‌ها» — رتبهٔ ۱ = بهترین شانس ایران
        sub_links = [brand_link(c, i) for i, c in enumerate(healthy[:SUB_MAX_CONFIGS], 1)]
        if send_sub_document(sub_links, date_str, time_str, reply_to=reply_to,
                             engine=engine):
            log(f"📡 فایل پیوست ساب کامل ({fa(len(sub_links))} کانفیگ) هم ارسال شد.")
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
        sub_text = "\n".join(sub_links) + "\n"
        with open(SUB_FILE, "w", encoding="utf-8") as f:
            f.write(sub_text)
        with open(SUB_B64_FILE, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(sub_text.encode("utf-8")).decode("ascii"))
        log(f"📡 سابسکریپشن با {fa(len(sub_links))} کانفیگ سالم (موتور {engine}) "
            f"با نام برند امپرس-ردیف در state/sub.txt (و نسخه base64) به‌روز شد.")

    # آمار این ران (برای دیباگ در لاگ اکشنز)
    os.makedirs(STATE_DIR, exist_ok=True)
    stats = {
        "ran_at": now.isoformat(timespec="seconds"),
        "dry_run": DRY_RUN,
        "engine": engine,
        "parsed_unique": len(configs),
        "targets": len(targets),
        "alive_tcp": len(latency),
        "alive": len(healthy),
        "xray_tested": xray_tested_n,
        "xray_alive": xray_alive_n,
        "candidates_new": len(candidates),
        "posted": len(selected),
        "reused": reused_n,
        "feedback_in": fb_processed,
        "message_len": tg_len(message),
    }
    with open(LAST_RUN_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    log("📊 آمار در state/last_run.json ذخیره شد. ✅ تمام")


if __name__ == "__main__":
    main()
