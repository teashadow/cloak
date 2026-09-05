"""CLI for cloak."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import CLOAK_BANNER
from .checks import hibp_check, ip_check, opsec_audit, run_audit, username_check
from .config import LAYERS_PATH, load_layers, save_layers

console = Console()


def _banner() -> None:
    console.print(f"[bold green]{CLOAK_BANNER}[/bold green]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD OPSEC checker."""


@main.command("audit")
@click.option("--scan-path", default=None, help="каталог/файл для скана секретов")
@click.option("--git-email", default=None, help="проверить этот email вместо глобального git config")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-вердикт (контракт пайплайна)")
def audit_cmd(scan_path: str | None, git_email: str | None, as_json: str | None) -> None:
    """🔴 OPSEC-гейт нашей гигиены: git-noreply + скан секретов. code 0 чисто · 1 утечка."""
    d = opsec_audit(scan_path=scan_path, git_email=git_email)
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    t = Table(title=f"cloak OPSEC-аудит · {d['инструмент']['цель']}")
    t.add_column("класс"); t.add_column("вердикт"); t.add_column("почему")
    for c in d["checks"]:
        цвет = "red" if c["вердикт"] == "УТЕЧКА" else "green"
        t.add_row(c["класс"], f"[{цвет}]{c['вердикт']}[/{цвет}]", c["почему"])
    console.print(t)
    # 🔴 находки секретов — только тип+файл+маска, значения не печатаются
    for c in d["checks"]:
        for f in c.get("находки", []):
            console.print(f"  [red]{f['тип']}[/red] в {f['файл']} · {f['маска']}")
    цвет = "red" if d["verdict"] == "УТЕЧКА" else "green"
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")
    raise SystemExit(1 if d["verdict"] == "УТЕЧКА" else 0)


@main.command("layers")
def layers_cmd() -> None:
    """Show configured identity layers."""
    data = load_layers().get("layers", {})
    table = Table(title=f"Identity Layers ({LAYERS_PATH})")
    table.add_column("Layer")
    table.add_column("Name")
    table.add_column("Email/IP")
    for layer_name, layer in data.items():
        table.add_row(layer_name, str(layer.get("name", "")), str(layer.get("email") or layer.get("ip") or ""))
    console.print(table)


@main.command("layer-add")
@click.argument("name")
@click.option("--display-name", default="", help="Human-readable label.")
@click.option("--email", default="", help="Layer email.")
@click.option("--ip", default="", help="Layer IP.")
def layer_add_cmd(name: str, display_name: str, email: str, ip: str) -> None:
    """Add a new layer to the YAML config."""
    data = load_layers()
    data.setdefault("layers", {})
    data["layers"][name] = {
        "name": display_name or name,
        "email": email,
        "ip": ip,
        "platforms": [],
    }
    save_layers(data)
    console.print(f"[green]Added[/green] layer {name} in {LAYERS_PATH}")


@main.command("check-email")
@click.argument("email")
def check_email_cmd(email: str) -> None:
    """Check email against HIBP."""
    console.print_json(data=hibp_check(email))


@main.command("check-username")
@click.argument("username")
def check_username_cmd(username: str) -> None:
    """Check a username on known platforms."""
    console.print_json(data=username_check(username))


@main.command("check-ip")
@click.argument("ip")
def check_ip_cmd(ip: str) -> None:
    """Check IP reputation and Shodan visibility."""
    console.print_json(data=ip_check(ip))


@main.command("audit-layers")
def audit_layers_cmd() -> None:
    """Прежний аудит по слоям идентичности (hibp/username/ip — требует API-ключей)."""
    report = run_audit()
    table = Table(title="Cloak Audit")
    table.add_column("Layer")
    table.add_column("Email")
    table.add_column("IP")
    table.add_column("Notes")
    for item in report["layers"]:
        email_state = "ok"
        if "email_check" in item and item["email_check"].get("breaches"):
            email_state = f"breaches={len(item['email_check']['breaches'])}"
        elif "email_check" in item and not item["email_check"].get("ok", False):
            email_state = f"error={item['email_check'].get('error', 'unknown')}"
        ip_state = ""
        if "ip_check" in item:
            ip_state = str(item["ip_check"].get("ip", ""))
        notes = []
        if "username_check" in item:
            present = [result["platform"] for result in item["username_check"]["results"] if result.get("present")]
            if present:
                notes.append("user-present:" + ",".join(present))
        if report["git"].get("configured_email"):
            notes.append("git=" + report["git"]["configured_email"])
        table.add_row(item["layer"], email_state, ip_state, "; ".join(notes))
    console.print(table)


if __name__ == "__main__":
    main()
