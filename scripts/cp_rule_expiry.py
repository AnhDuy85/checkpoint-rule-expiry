#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===========================================================
 CHECK POINT R81.10 VSX — RULE EXPIRY AUDIT (FIXED FINAL)
===========================================================
- Fixed runtime bugs
- Fixed variable mismatches
- Safe expiry parsing
- Telegram alert stable
===========================================================
"""

import argparse
import json
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


# =========================
# COLOR LOGGER
# =========================

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def log(msg, color=C.CYAN):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{C.GRAY}[{ts}]{C.RESET} {color}{msg}{C.RESET}")


# =========================
# CONFIG
# =========================

def load_config(path):
    p = Path(path)

    # Nếu là relative path → resolve từ root project
    if not p.is_absolute():
        root = Path(__file__).resolve().parent.parent
        p = root / path

    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")

    return json.loads(p.read_text(encoding="utf-8"))


# =========================
# CHECK POINT API CLIENT
# =========================

class CP:
    def __init__(self, host, port=443):
        self.base = f"https://{host}:{port}/web_api"
        self.sid = None
        self.ctx = ssl._create_unverified_context()

    def call(self, cmd, payload):
        body = json.dumps(payload).encode()

        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid

        req = urllib.request.Request(
            self.base + cmd,
            data=body,
            headers=headers
        )

        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            raise RuntimeError(str(e))

    def login(self, mgmt):
        log("Login Check Point...", C.YELLOW)

        if mgmt.get("apiKey"):
            r = self.call("/login", {"api-key": mgmt["apiKey"]})
        else:
            r = self.call("/login", {
                "user": mgmt["username"],
                "password": mgmt["password"],
                "read-only": True
            })

        self.sid = r["sid"]
        log("Login OK", C.GREEN)

    def logout(self):
        if self.sid:
            try:
                self.call("/logout", {})
            except:
                pass
            self.sid = None


# =========================
# DATE PARSER
# =========================

def parse_date(s):
    if not s:
        return None

    fmts = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y"
    ]

    for f in fmts:
        try:
            return datetime.strptime(s[:19], f).replace(tzinfo=timezone.utc)
        except:
            continue

    return None


def parse_expiry(obj):
    if not obj:
        return None

    for k in ["valid-until", "expiration-date", "end", "until"]:
        v = obj.get(k)

        if isinstance(v, str):
            return parse_date(v)

        if isinstance(v, dict):
            if v.get("posix"):
                ts = int(v["posix"])
                if ts > 10**12:
                    ts //= 1000
                return datetime.fromtimestamp(ts, tz=timezone.utc)

    return None


# =========================
# SAFE RESOLVE
# =========================

def resolve_ip(obj):
    if not obj:
        return ["Any"]

    if isinstance(obj, str):
        return [obj]

    t = obj.get("type", "")

    if "host" in t:
        return [obj.get("ipv4-address") or obj.get("ip-address", "?")]

    if "network" in t:
        return [obj.get("subnet4", "?")]

    return [obj.get("name", "?")]


def resolve_service(obj):
    if not obj:
        return ["Any"]

    if isinstance(obj, str):
        return [obj]

    t = obj.get("type", "")

    if "tcp" in t:
        return [f"TCP/{obj.get('port', '?')}"]

    if "udp" in t:
        return [f"UDP/{obj.get('port', '?')}"]

    return [obj.get("name", "?")]


# =========================
# ANALYZE
# =========================

def analyze(rules, objects, warn_days):
    now = datetime.now(timezone.utc)

    critical = []
    warning = []

    for r in rules:
        if r.get("type") != "access-rule":
            continue

        expiry = None

        for t in r.get("time", []):
            uid = t if isinstance(t, str) else t.get("uid")
            obj = objects.get(uid, t if isinstance(t, dict) else None)

            expiry = parse_expiry(obj)
            if expiry:
                break

        if not expiry:
            continue

        days = int((expiry - now).total_seconds() / 86400)

        entry = {
            "id": r.get("rule-number"),
            "name": r.get("name"),
            "source": resolve_ip(r.get("source")),
            "dest": resolve_ip(r.get("destination")),
            "service": resolve_service(r.get("service")),
            "expiry": expiry.strftime("%Y-%m-%d"),
            "days": days
        }

        if days <= 1:
            critical.append(entry)
        elif 2 <= days <= warn_days:
            warning.append(entry)

    return critical, warning


# =========================
# REPORT
# =========================

def report(critical, warning, warn_days):
    print("\n" + "=" * 60)
    print("CHECK POINT VSX RULE EXPIRY REPORT")
    print("=" * 60)

    print(f"\n🚨 CRITICAL (≤1 day / expired): {len(critical)}")
    print(f"⚠️ WARNING (2–{warn_days} days): {len(warning)}")


# =========================
# SAVE
# =========================

def save(critical, warning):
    Path("reports").mkdir(exist_ok=True)

    file = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    Path(file).write_text(json.dumps({
        "critical": critical,
        "warning": warning
    }, indent=2))

    log(f"Saved: {file}", C.GREEN)


# =========================
# TELEGRAM
# =========================

def send_telegram(cfg, critical, warning, warn_days):
    tg = cfg.get("telegram", {})
    token = tg.get("token")
    chat_id = tg.get("chat_id")

    if not token or not chat_id:
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def fmt(r):
        return (
            f"• Rule {r['id']} - {r['name']}\n"
            f"  Src: {', '.join(r['source'][:3])}\n"
            f"  Dst: {', '.join(r['dest'][:3])}\n"
            f"  Svc: {', '.join(r['service'][:3])}\n"
            f"  Exp: {r['expiry']} ({r['days']}d)\n"
        )

    msg = []
    msg.append("🛡 <b>CHECK POINT VSX RULE EXPIRY ALERT</b>")
    msg.append(f"🕒 {now}")
    msg.append("━━━━━━━━━━━━━━━━━━")

    if critical:
        msg.append("\n🚨 <b>CRITICAL</b>")
        for r in critical[:10]:
            msg.append(fmt(r))
    else:
        msg.append("\n✅ No critical rules")

    if warning:
        msg.append(f"\n⚠️ <b>WARNING (≤{warn_days} days)</b>")
        for r in warning[:10]:
            msg.append(fmt(r))
    else:
        msg.append("\n✅ No warning rules")

    payload = json.dumps({
        "chat_id": chat_id,
        "text": "\n".join(msg),
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }).encode()

    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        log("Telegram sent", C.GREEN)

    except Exception as e:
        log(f"Telegram error: {e}", C.RED)


# =========================
# MAIN
# =========================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/config_r81.json")
    args = parser.parse_args()

    cfg = load_config(args.config)
    warn_days = cfg.get("days", 5)

    api = CP(cfg["management"]["host"])

    try:
        api.login(cfg["management"])

        rules = []
        objects = {}

        pkgs = api.call("/show-packages", {"limit": 500}).get("packages", [])

        for p in pkgs:
            name = p["name"]

            if cfg.get("packages") and name not in cfg["packages"]:
                continue

            pkg = api.call("/show-package", {"name": name, "details-level": "full"})

            for layer in pkg.get("access-layers", []):
                layer_name = layer if isinstance(layer, str) else layer.get("name")

                offset = 0
                limit = 500

                while True:
                    res = api.call("/show-access-rulebase", {
                        "name": layer_name,
                        "limit": limit,
                        "offset": offset,
                        "details-level": "full",
                        "use-object-dictionary": True
                    })

                    obj_dict = res.get("objects-dictionary", {})
                    if isinstance(obj_dict, dict):
                        for k, v in obj_dict.items():
                            if k not in objects:
                                objects[k] = v

                    for r in res.get("rulebase", []):
                        r["_layer"] = layer_name
                        r["_package"] = name
                        rules.append(r)

                    total = res.get("total", 0)
                    offset += limit
                    if offset >= total:
                        break

        critical, warning = analyze(rules, objects, warn_days)

        report(critical, warning, warn_days)
        save(critical, warning)
        send_telegram(cfg, critical, warning, warn_days)

        log("DONE", C.GREEN)

    finally:
        api.logout()


if __name__ == "__main__":
    main()