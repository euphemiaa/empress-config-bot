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
  ۵) انتخاب بهترین کانفیگ با اولویت پروتکل (پیش‌فرض: اول بهترین VLESS — سبک کانال‌های
     معروف مثل @flyv2ray که هر پست یک کانفیگ تکی می‌گذارند)
  ۶) ساخت پست HTML فارسی: تاریخ شمسی + بلاک <code> + راهنمای سریع v2rayNG و NPV Tunnel
     + لینک دانلود اپ‌ها + دکمه‌های شیشه‌ای + هشتگ + فوتر امپرس
  ۷) ارسال با Bot API (parse_mode=HTML) یا نمایش پیش‌نمایش در حالت DRY_RUN=1

متغیرهای محیطی:
  BOT_TOKEN            توکن بات از BotFather (الزامی برای ارسال واقعی)
  CHANNEL_ID           @EmpressConfig یا -100xxxxxxxxxx
  CHANNEL_LINK         https://t.me/EmpressConfig (لینک دکمه در نبود TUTORIAL_URL)
  TUTORIAL_URL         (اختیاری، فاز ۲) لینک پست آموزشی پین‌شده برای دکمه
  DRY_RUN              1 = فقط پیش‌نمایش؛ بدون ارسال و بدون تغییر posted.json
  WORKERS              تعداد نخ‌های تست TCP (پیش‌فرض 40)
  TCP_TIMEOUT          تایم‌اوت تست به ثانیه (پیش‌فرض 3)
  CONFIGS_PER_POST     تعداد کانفیگ در هر پست (پیش‌فرض 3: بهترین VLESS + VMess + Trojan؛ 1 تا 5)
  SUB_MAX_CONFIGS      تعداد کانفیگ در فایل سابسکریپشن (پیش‌فرض 100)
  PROTO_PRIORITY       اولویت پروتکل‌ها (پیش‌فرض vless,vmess,trojan,ss — یعنی اول بهترین VLESS)
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
TUTORIAL_URL = os.environ.get("TUTORIAL_URL", "").strip()  # فاز ۲: لینک پست آموزشی
DRY_RUN = os.environ.get("DRY_RUN", "0").strip().lower() in ("1", "true", "yes", "y")

WORKERS = int(os.environ.get("WORKERS", "40"))
TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "3"))
CONFIGS_PER_POST = max(1, int(os.environ.get("CONFIGS_PER_POST", "3")))
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

# منابع کانفیگ — همه عمومی و رایگان (آخرین تست زنده: ۲۰۲۶-۱۱-۰۶)
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
]

FOOTER = "👑 شبکه امپرس | 🆔 کانال اصلی: @EmpressNetwork"
HASHTAGS = "#کانفیگ_رایگان #V2RayNG #NPV_Tunnel"

# لینک رسمی دانلود اپ‌ها در گوگل‌پلی (برای خط «دانلود» در پست)
APP_V2RAYNG_URL = "https://play.google.com/store/apps/details?id=com.v2ray.ang"
APP_NPV_URL = "https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv"
NETWORK_URL = "https://t.me/EmpressNetwork"

PROTO_LABEL = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "ss": "Shadowsocks"}
NUM_EMOJI = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣"]


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
            "name": name, "fp_src": "vmess|" + canonical}


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
    return {"proto": scheme, "link": link, "host": host, "port": port,
            "name": name, "fp_src": canonical}


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
            "name": host, "fp_src": "ss|" + identity + "|" + hostport.lower()}


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

def build_message(selected, date_str, time_str, total_tested, total_alive):
    """پست به سبک کانال‌های معروف (الگوی @flyv2ray): تیتر + بلاک کانفیگ + راهنما + فوتر."""
    lines = [
        "👑 <b>امپرس | کانفیگ رایگان</b>",
        f"📅 {date_str} • ⏰ {time_str}",
        "",
        "🔥 <b>تازه تست‌شده و سالم — مناسب v2rayNG و NPV Tunnel</b>",
        "",
    ]
    for c in selected:
        lines.append(f"⚡️ <b>{proto_title(c)}</b> | ⏱ پینگ {fa(c['latency'])} ms")
        lines.append(f"<code>{html.escape(c['link'], quote=False)}</code>")
        lines.append("")
    lines.append("📲 <b>راهنمای سریع:</b>")
    lines.append("۱️⃣ کانفیگ بالا را کپی کن")
    lines.append("۲️⃣ v2rayNG ← دکمه ➕ ← Import config from clipboard")
    lines.append("۳️⃣ NPV Tunnel ← دکمه ➕ ← Import Config")
    lines.append("")
    lines.append(f"⬇️ <a href=\"{APP_V2RAYNG_URL}\">دانلود v2rayNG</a> | "
                 f"<a href=\"{APP_NPV_URL}\">دانلود NPV Tunnel</a>")
    lines.append("🌟 کانفیگ را با دوستانت به اشتراک بگذار 👌")
    lines.append("")
    lines.append((HASHTAGS + " " + proto_hashtag(selected[0])) if selected else HASHTAGS)
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
    healthy.sort(key=lambda c: (c["latency"], len(c["link"])))
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

    # ۵) انتخاب کانفیگ‌ها: اولویت پروتکل (پیش‌فرض: اول بهترین VLESS) + سقف طول تلگرام
    date_str = jalali_date_str(now)
    time_str = fa(now.strftime("%H:%M"))
    by_proto = {}
    for c in candidates:  # candidates از قبل بر اساس تأخیر مرتب‌اند
        by_proto.setdefault(c["proto"], []).append(c)
    order = [p for p in PROTO_PRIORITY if p in by_proto]
    order += [p for p in by_proto if p not in order]

    selected = []
    slot = 0
    while len(selected) < CONFIGS_PER_POST:
        if not any(by_proto.values()):
            break
        proto = order[slot % len(order)]
        pool = by_proto.get(proto) or []
        if not pool:
            slot += 1  # این پروتکل کاندید نداشت؛ برو سراغ پروتکل بعدی
            continue
        c = pool.pop(0)
        by_proto[proto] = pool
        trial = selected + [c]
        if tg_len(build_message(trial, date_str, time_str, len(configs), len(healthy))) <= TG_LIMIT - TG_SAFETY:
            selected = trial
        # else: این کانفیگ خیلی بلند است؛ دور انداختیم و سراغ پروتکل/کاندید بعدی می‌رویم
        slot += 1
    if not selected:
        die("کاندیدی برای پست پیدا نشد (همه تکراری بودند یا هیچ‌کدام در محدودیت طول جا نشد).")
    if len(selected) < CONFIGS_PER_POST:
        log(f"⚠️ فقط {fa(len(selected))} کانفیگ انتخاب شد (هدف: {fa(CONFIGS_PER_POST)}).")
    for i, c in enumerate(selected, 1):
        log(f"   {i}. {proto_title(c)} | {c['host']}:{c['port']} | "
            f"{c['latency']}ms | طول لینک {len(c['link'])}")

    message = build_message(selected, date_str, time_str, len(configs), len(healthy))
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
