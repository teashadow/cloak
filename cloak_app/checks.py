"""API-backed and local OPSEC checks."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import requests

from .config import AUDIT_PATH, load_layers, load_secrets


def hibp_check(email: str) -> dict[str, Any]:
    load_secrets()
    key = os.getenv("HIBP_API_KEY", "").strip()
    headers = {"hibp-api-key": key, "user-agent": "mad-cloak/0.1"} if key else {"user-agent": "mad-cloak/0.1"}
    resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=30)
    if resp.status_code == 404:
        return {"email": email, "ok": True, "breaches": []}
    if resp.status_code == 401:
        return {"email": email, "ok": False, "error": "hibp_unauthorized"}
    resp.raise_for_status()
    data = resp.json()
    return {"email": email, "ok": True, "breaches": [item.get("Name") for item in data]}


def username_check(username: str) -> dict[str, Any]:
    results = []
    for label, url in {
        "github": f"https://github.com/{username}",
        "hackerone": f"https://hackerone.com/{username}",
        "bugcrowd": f"https://bugcrowd.com/{username}",
    }.items():
        try:
            resp = requests.get(url, timeout=20)
            results.append({"platform": label, "url": url, "status": resp.status_code, "present": resp.status_code == 200})
        except requests.RequestException as exc:
            results.append({"platform": label, "url": url, "status": "error", "present": False, "error": str(exc)})
    return {"username": username, "results": results}


def ip_check(ip: str) -> dict[str, Any]:
    load_secrets()
    out: dict[str, Any] = {"ip": ip}
    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
    if shodan_key:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": shodan_key}, timeout=30)
        out["shodan"] = {"status": resp.status_code}
        if resp.status_code == 200:
            data = resp.json()
            out["shodan"].update({"ports": data.get("ports", []), "org": data.get("org"), "vulns": list((data.get("vulns") or {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", [])})
        else:
            out["shodan"]["error"] = resp.text[:240]
    else:
        out["shodan"] = {"error": "missing SHODAN_API_KEY"}

    abuse_key = os.getenv("ABUSEIPDB_KEY", "").strip()
    if abuse_key:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": abuse_key, "Accept": "application/json"},
            timeout=30,
        )
        out["abuseipdb"] = {"status": resp.status_code}
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            out["abuseipdb"].update({"abuseConfidenceScore": data.get("abuseConfidenceScore"), "countryCode": data.get("countryCode"), "usageType": data.get("usageType")})
        else:
            out["abuseipdb"]["error"] = resp.text[:240]
    else:
        out["abuseipdb"] = {"error": "missing ABUSEIPDB_KEY"}
    return out


def git_email_check() -> dict[str, Any]:
    proc = subprocess.run(["git", "config", "--global", "--get", "user.email"], capture_output=True, text=True, check=False)
    return {"configured_email": proc.stdout.strip(), "ok": proc.returncode == 0}


# ── детерминируемые OPSEC-проверки НАШЕЙ гигиены (без внешних ключей) ─────────

def check_git_noreply(email: str | None = None) -> dict[str, Any]:
    """git email обязан быть noreply, иначе личность течёт в каждый коммит (ЗАКОН контура).

    email=None → читаем глобальный git config; иначе проверяем переданный (для теста, не трогая
    реальную систему). Детект точный: не оканчивается на users.noreply.github.com → УТЕЧКА.
    """
    if email is None:
        email = git_email_check()["configured_email"]
    утечка = bool(email) and not email.endswith("users.noreply.github.com")
    return {
        "класс": "git-identity-leak", "email_tail": email.split("@")[-1] if "@" in email else email,
        "вердикт": "УТЕЧКА" if утечка else "чисто",
        "почему": (f"git коммитит НЕ noreply-адресом ({email.split('@')[-1]}) — личность течёт "
                   f"в каждый коммит" if утечка else "git email — noreply, личность не течёт"),
    }


# Паттерны секретов. Значение в отчёт НЕ попадает — только тип и маска (🔴 не печатать секреты).
_СЕКРЕТЫ: list[tuple[str, str]] = [
    (r"ghp_[A-Za-z0-9]{30,}", "github-pat"),
    (r"gho_[A-Za-z0-9]{30,}", "github-oauth"),
    (r"sk_live_[A-Za-z0-9]{20,}", "stripe-secret-live"),
    (r"rk_live_[A-Za-z0-9]{20,}", "stripe-restricted-live"),
    (r"whsec_[A-Za-z0-9]{20,}", "stripe-webhook-secret"),
    (r"AKIA[0-9A-Z]{16}", "aws-access-key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack-token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private-key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt"),
]


def _маска(значение: str) -> str:
    """Показать безопасный след: префикс + длина, без тела секрета."""
    return f"{значение[:6]}…({len(значение)} знаков)"


def scan_secrets(путь: str, *, max_bytes: int = 2_000_000) -> dict[str, Any]:
    """Скан пути на утечку секретов. 🔴 Значения НЕ печатаются — только тип, файл, маска.

    Реальный класс, что бьёт по нам (SELF_GUARD: токены в клиентских логах). Сканируем текстовые
    файлы; бинарные и .git пропускаем. Найден токен → УТЕЧКА.
    """
    import re
    корень = Path(путь).expanduser()
    находки: list[dict[str, str]] = []
    файлы = [корень] if корень.is_file() else [f for f in корень.rglob("*") if f.is_file()]
    компилированы = [(re.compile(p), тип) for p, тип in _СЕКРЕТЫ]
    for f in файлы:
        if "/.git/" in str(f) or f.stat().st_size > max_bytes:
            continue
        try:
            текст = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rx, тип in компилированы:
            m = rx.search(текст)
            if m:
                находки.append({"файл": str(f), "тип": тип, "маска": _маска(m.group(0))})
    return {
        "класс": "secret-in-tree", "путь": str(корень), "файлов": len(файлы),
        "находки": находки, "вердикт": "УТЕЧКА" if находки else "чисто",
        "почему": (f"в дереве найдены секреты: {', '.join(sorted({f['тип'] for f in находки}))}"
                   if находки else "секретов в дереве не найдено"),
    }


def opsec_audit(scan_path: str | None = None, git_email: str | None = None) -> dict[str, Any]:
    """Сводный OPSEC-гейт нашей гигиены: git-noreply + скан секретов. Контракт + вердикт + rc."""
    проверки = [check_git_noreply(git_email)]
    if scan_path:
        проверки.append(scan_secrets(scan_path))
    утечек = sum(1 for p in проверки if p["вердикт"] == "УТЕЧКА")
    return {
        "инструмент": {"имя": "cloak", "цель": scan_path or "git-config"},
        "verdict": "УТЕЧКА" if утечек else "чисто",
        "проверок": len(проверки), "утечек": утечек, "checks": проверки,
        "почему": (f"OPSEC-утечки: {утечек} из {len(проверки)}" if утечек
                   else "операционная гигиена чиста по проверенным классам"),
    }


def run_audit() -> dict[str, Any]:
    layers = load_layers().get("layers", {})
    report: dict[str, Any] = {"layers": [], "git": git_email_check()}
    for name, layer in layers.items():
        item: dict[str, Any] = {"layer": name, "name": layer.get("name"), "platforms": layer.get("platforms", [])}
        if layer.get("email"):
            try:
                item["email_check"] = hibp_check(layer["email"])
            except Exception as exc:
                item["email_check"] = {"email": layer["email"], "ok": False, "error": str(exc)}
        if layer.get("name"):
            item["username_check"] = username_check(str(layer["name"]))
        if layer.get("ip"):
            item["ip_check"] = ip_check(str(layer["ip"]))
        report["layers"].append(item)
    AUDIT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report
