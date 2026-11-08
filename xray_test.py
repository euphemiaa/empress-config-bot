#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🚀 تستر واقعی کانفیگ‌ها با موتور Xray — «همان‌کاری که v2rayNG می‌کند»

چرا این فایل وجود دارد؟
  تست TCP فقط می‌فهمد «پورت باز است»؛ ولی خیلی از سرورها پورتشان باز است و
  کانفیگ‌شان مُرده است (UUID منقضی، TLS هندشیک نمی‌شود، کلید Reality نامعتبر،
  مسیر ws اشتباه و…). این‌ها همان کانفیگ‌هایی هستند که در ایران تایم‌اوت می‌دهند.
  این ماژول برای هر کانفیگ یک پروسهٔ واقعی xray با پروکسی SOCKS لوکال بالا
  می‌آورد، تونل کامل پروتکل را می‌سازد و یک درخواست HTTP واقعی از داخل تونل
  رد می‌کند. اگر جواب HTTP نیامد، کانفیگ مرده است — نقطه.

ورودی هر کانفیگ، دیکشنریِ پارس‌شدهٔ main.py است (proto/host/port + q یا vm
یا method/password). خروجی run_xray_tests فهرستی هم‌طول با ورودی است:
  {"ok": True, "ms": 850, "status": "204 No Content"}  یا  {"ok": False, "why": "..."}

فقط پایتون استاندارد — بدون کتابخانهٔ خارجی.
"""

import asyncio
import json
import os
import tempfile
import urllib.parse

# هدف تست: درخواست HTTP ساده از داخل تونل؛ gstatic در همه‌جا پاسخ می‌دهد
TARGET_HOST = "www.gstatic.com"
TARGET_PORT = 80
TARGET_PATH = "/generate_204"

PORT_BASE = 23200  # پورت SOCKS لوکال هر تست = PORT_BASE + شمارهٔ کانفیگ در دسته


def _clean(d):
    """حذف کلیدهای خالی تا کانفیگ xray تمیز بماند."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def _split_alpn(s):
    return [a.strip() for a in (s or "").split(",") if a.strip()]


def _bool_q(v):
    return str(v).strip().lower() in ("1", "true", "yes")


# ------------------------- ساخت streamSettings -------------------------

def _net_settings(net, host, q):
    """تنظیمات ترنسپورت (ws/grpc/httpupgrade/xhttp/h2/tcp-header) از پارامترهای لینک."""
    path = q.get("path") or "/"
    hst = q.get("host") or host
    if net == "ws":
        headers = {"Host": hst} if hst else None
        return {"wsSettings": _clean({"path": path, "headers": headers})}
    if net == "grpc":
        return {"grpcSettings": _clean({
            "serviceName": q.get("serviceName") or q.get("path"),
            "multiMode": "multi" if str(q.get("mode", "")).lower() == "multi" else None,
        })}
    if net == "httpupgrade":
        return {"httpupgradeSettings": _clean({"path": path, "host": hst})}
    if net in ("xhttp", "splithttp"):
        return {"xhttpSettings": _clean({
            "path": path, "host": hst,
            "mode": str(q.get("mode") or "auto").lower(),
        })}
    if net in ("h2", "http"):
        return {"httpSettings": _clean({
            "host": [hst] if hst else None, "path": path,
        })}
    if net == "tcp":
        if str(q.get("headerType", "")).lower() == "http":
            req = _clean({
                "method": "GET",
                "path": [p for p in (path or "/").split(",")] or None,
                "headers": _clean({"Host": hst}),
            })
            return {"tcpSettings": _clean({"request": req}) if req else {}}
        return {}
    return {}


def _security_settings(sec, q, host):
    """tlsSettings / realitySettings از پارامترهای لینک؛ None یعنی قابل تست نیست."""
    sni = q.get("sni") or q.get("host") or host
    fp = q.get("fp") or ("chrome" if sec == "reality" else "")
    alpn = _split_alpn(q.get("alpn"))
    insecure = _bool_q(q.get("allowInsecure") or q.get("insecure"))
    if sec == "tls":
        return {"tlsSettings": _clean({
            "serverName": sni,
            "fingerprint": fp or None,
            "alpn": alpn or None,
            "allowInsecure": True if insecure else None,
        })}
    if sec == "reality":
        pbk = q.get("pbk") or q.get("publicKey")
        if not pbk or not sni:
            return None  # بدون publicKey/sni نمی‌شود Reality را بست؛ v2rayNG هم نمی‌بندد
        return {"realitySettings": _clean({
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": q.get("sid") or "",
            "spiderX": q.get("spx") or "/",
        })}
    return {}


# ------------------------- ساخت outbound -------------------------

def build_outbound(c):
    """لینک پارس‌شدهٔ main.py → دیکشنری outbound سازگار با xray؛ None = غیرقابل ساخت."""
    proto = c["proto"]
    host, port = str(c["host"]).strip("[]"), int(c["port"])
    if proto in ("vless", "trojan"):
        q = c.get("q") or {}
        userinfo = urllib.parse.unquote(
            urllib.parse.urlsplit(c["link"]).username or "")
        if not userinfo:
            return None
        if proto == "vless":
            user = {"id": userinfo, "encryption": "none", "level": 0}
            flow = (q.get("flow") or "").strip()
            if flow:
                user["flow"] = flow
            settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
            sec = (q.get("security") or "none").strip().lower() or "none"
        else:
            settings = {"servers": [{"address": host, "port": port,
                                     "password": userinfo, "level": 0}]}
            sec = (q.get("security") or "tls").strip().lower() or "tls"
        net = (q.get("type") or "tcp").strip().lower() or "tcp"
        stream = {"network": net, "security": sec}
        sec_set = _security_settings(sec, q, host)
        if sec in ("tls", "reality") and sec_set is None:
            return None
        if sec_set:
            stream.update(sec_set)
        stream.update(_net_settings(net, host, q))
        return {"tag": "proxy", "protocol": proto, "settings": settings,
                "streamSettings": _clean(stream)}

    if proto == "vmess":
        vm = c.get("vm") or {}
        uid = str(vm.get("id") or "").strip()
        if not uid:
            return None
        try:
            aid = int(str(vm.get("aid") or 0).strip() or 0)
        except (TypeError, ValueError):
            aid = 0
        scy = str(vm.get("scy") or "auto") or "auto"
        net = str(vm.get("net") or "tcp").strip().lower() or "tcp"
        sec = str(vm.get("tls") or "").strip().lower()
        if sec not in ("tls", "reality"):
            sec = "none"
        q = {k: v for k, v in {
            "path": vm.get("path"), "host": vm.get("host"), "sni": vm.get("sni"),
            "fp": vm.get("fp"), "alpn": vm.get("alpn"),
            "serviceName": vm.get("path") if net == "grpc" else None,
        }.items() if v}
        settings = {"vnext": [{"address": host, "port": port, "users": [
            {"id": uid, "alterId": aid, "security": scy, "level": 0}]}]}
        stream = {"network": net, "security": sec}
        sec_set = _security_settings(sec, q, host)
        if sec in ("tls", "reality") and sec_set is None:
            return None
        if sec_set:
            stream.update(sec_set)
        stream.update(_net_settings(net, host, q))
        return {"tag": "proxy", "protocol": "vmess", "settings": settings,
                "streamSettings": _clean(stream)}

    if proto == "ss":
        method, pwd = c.get("method"), c.get("password")
        if not method or pwd is None:
            return None
        return {"tag": "proxy", "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": port,
                                          "method": method, "password": pwd,
                                          "ota": False, "level": 0}]}}
    return None


# ------------------------- کلاینت SOCKS5 + HTTP -------------------------

async def _http_via_socks(port, timeout):
    """از SOCKS لوکال به gstatic درخواست می‌زند؛ خط وضعیت HTTP یا Exception."""
    rd, wr = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), timeout=2.5)
    try:
        wr.write(b"\x05\x01\x00")  # greeting: بدون احراز هویت
        greeting = await asyncio.wait_for(rd.readexactly(2), timeout=2.5)
        if greeting != b"\x05\x00":
            raise OSError("socks greeting failed")
        addr = TARGET_HOST.encode()
        wr.write(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                 + TARGET_PORT.to_bytes(2, "big"))
        head = await asyncio.wait_for(rd.readexactly(4), timeout=4)
        if head[1] != 0:
            raise OSError(f"socks connect refused ({head[1]})")
        atyp = head[3:4]
        if atyp == b"\x01":
            await rd.readexactly(6)
        elif atyp == b"\x03":
            n = (await rd.readexactly(1))[0]
            await rd.readexactly(n + 2)
        else:
            await rd.readexactly(18)
        req = (f"GET {TARGET_PATH} HTTP/1.1\r\nHost: {TARGET_HOST}\r\n"
               "User-Agent: Mozilla/5.0 (EmpressConfigBot)\r\n"
               "Connection: close\r\n\r\n")
        wr.write(req.encode())
        buf = b""
        while b"\r\n" not in buf and len(buf) < 512:
            chunk = await asyncio.wait_for(rd.read(128), timeout=3.5)
            if not chunk:
                break
            buf += chunk
        if not buf.startswith(b"HTTP/"):
            raise OSError("no HTTP response through tunnel")
        return buf.split(b"\r\n", 1)[0].decode("latin1", "replace").strip()
    finally:
        try:
            wr.close()
        except Exception:
            pass


# ------------------------- تست یک کانفیگ -------------------------

async def _test_one(xray_bin, c, idx, timeout, tmpdir):
    outbound = build_outbound(c)
    if outbound is None:
        return {"ok": False, "why": "unbuildable"}
    port = PORT_BASE + (idx % 20000)
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound, {"tag": "block", "protocol": "blackhole"}],
    }
    cfg_path = os.path.join(tmpdir, f"cfg_{idx}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)

    proc = await asyncio.create_subprocess_exec(
        xray_bin, "run", "-c", cfg_path,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    # صبر تا پورت SOCKS بالا بیاید (حداکثر ~۳ ثانیه)
    up = False
    for _ in range(15):
        if proc.returncode is not None:
            break
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            up = True
            break
        except OSError:
            await asyncio.sleep(0.2)
    if not up:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        err = b""
        try:
            _, err = await asyncio.wait_for(proc.communicate(), timeout=3)
        except Exception:
            pass
        tail = (err or b"").decode("utf-8", "replace").strip().splitlines()
        why = tail[-1][:80] if tail else "xray did not start"
        return {"ok": False, "why": why}

    t0 = asyncio.get_event_loop().time()
    try:
        status = await asyncio.wait_for(_http_via_socks(port, timeout), timeout=timeout)
        ms = max(1, int((asyncio.get_event_loop().time() - t0) * 1000))
        return {"ok": True, "ms": ms, "status": status}
    except asyncio.TimeoutError:
        return {"ok": False, "why": "tunnel timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "why": "socks refused"}
    except OSError as e:
        return {"ok": False, "why": f"io: {str(e)[:60]}"}
    except Exception as e:
        return {"ok": False, "why": f"err: {str(e)[:60]}"}
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(proc.communicate(), timeout=3)
        except Exception:
            pass


# ------------------------- اجرای دسته‌ای -------------------------

def run_xray_tests(configs, xray_bin, workers=50, timeout=9.0, progress_every=40):
    """
    تست موازی فهرست کانفیگ‌ها؛ خروجی = فهرست نتیجه هم‌طول با ورودی.
    هر تست یک پروسهٔ xray مستقل با پورت SOCKS یکتا دارد.
    """
    n = len(configs)
    results = [{"ok": False, "why": "not-run"}] * n
    if n == 0:
        return results

    async def _main():
        sem = asyncio.Semaphore(max(1, workers))
        with tempfile.TemporaryDirectory(prefix="xraytest_") as tmpdir:
            async def guarded(i):
                async with sem:
                    return i, await _test_one(xray_bin, configs[i], i, timeout, tmpdir)

            tasks = [asyncio.create_task(guarded(i)) for i in range(n)]
            done = 0
            for fut in asyncio.as_completed(tasks):
                i, r = await fut
                results[i] = r
                done += 1
                if progress_every and done % progress_every == 0:
                    ok_so_far = sum(1 for x in results if x.get("ok"))
                    print(f"   🚀 Xray: {done}/{n} تست شد → {ok_so_far} زنده", flush=True)

    asyncio.run(_main())
    return results


if __name__ == "__main__":
    # تست سریع مستقل:  python3 xray_test.py "لینک کانفیگ"
    import sys
    if len(sys.argv) > 1:
        import re
        link = sys.argv[1].strip()
        m = re.match(r"^(vmess|vless|trojan|ss)://", link)
        fake = {"proto": m.group(1).lower(), "link": link}
        if fake["proto"] == "vmess":
            import base64
            data = json.loads(base64.b64decode(
                link[8:] + "=" * (-len(link[8:]) % 4)).decode())
            fake.update({"host": data["add"], "port": int(data["port"]), "vm": data})
        else:
            sp = urllib.parse.urlsplit(link)
            fake.update({"host": sp.hostname, "port": sp.port or 443,
                         "q": {k: v[0] for k, v in urllib.parse.parse_qs(sp.query).items()}})
        res = run_xray_tests([fake], sys.argv[2] if len(sys.argv) > 2 else "xray",
                             workers=1, timeout=10)
        print(json.dumps(res[0], ensure_ascii=False))
