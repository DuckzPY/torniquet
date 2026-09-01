import subprocess

import click

from torniquet import tor_manager, network, audit as audit_mod, profiles, killswitch

tor = tor_manager.TorManager()


def line(label: str, value) -> str:
    return f"{label:<12}{value}"


@click.group()
def cli():
    """torniquet :: anonymity & opsec toolkit"""
    pass


# -- tor lifecycle -------------------------------------------------------

@cli.command()
def start():
    """Start tor and wait for the circuit to bootstrap."""
    click.echo("torniquet :: starting tor")
    try:
        tor.start(on_progress=lambda pct: click.echo(f"[{'#' * (pct // 10):<10}] {pct}%"))
    except Exception as e:
        click.echo(f"error: {e}")
        raise SystemExit(1)
    click.echo("tor is up. circuit ready.")


@cli.command()
def stop():
    """Stop tor."""
    tor.stop()
    click.echo("tor stopped.")


@cli.command()
def status():
    """Show current tor connection status."""
    info = tor.get_status()
    click.echo("\ntorniquet :: tor status")
    click.echo("-------------------")
    if not info.get("running"):
        click.echo(line("state", "down"))
        return
    click.echo(line("state", "up"))
    click.echo(line("pid", info.get("pid", "?")))
    click.echo(line("circuits", info.get("circuits", "?")))
    click.echo(line("socks", f"127.0.0.1:{info['socks_port']}"))
    click.echo(line("ctrl", f"127.0.0.1:{info['control_port']}"))
    if "control_error" in info:
        click.echo(line("warning", info["control_error"]))


# -- identity / network ---------------------------------------------------

@cli.command()
def whoami():
    """Check current exit IP, country, and run a basic DNS leak check."""
    if not tor.is_running():
        click.echo("tor is not running. run 'torniquet start' first.")
        raise SystemExit(1)
    click.echo("\ntorniquet :: identity check")
    click.echo("-----------------------")
    try:
        info = network.get_exit_info()
    except Exception as e:
        click.echo(f"error checking exit info: {e}")
        raise SystemExit(1)
    click.echo(line("ip", info["ip"]))
    click.echo(line("country", info["country"]))
    click.echo(line("asn", info["asn"]))
    leak = network.check_dns_leak()
    click.echo(line("dns", leak["detail"]))


@cli.command()
def rotate():
    """Request a new tor circuit (new exit node)."""
    if not tor.is_running():
        click.echo("tor is not running. run 'torniquet start' first.")
        raise SystemExit(1)
    click.echo("torniquet :: rotating circuit")
    try:
        old = network.get_exit_info().get("country", "unknown")
    except Exception:
        old = "unknown"
    tor.new_circuit()
    try:
        new = network.get_exit_info().get("country", "unknown")
    except Exception:
        new = "unknown"
    click.echo(line("old exit", old))
    click.echo(line("new exit", new))
    click.echo("done.")


# -- audit -----------------------------------------------------------------

@cli.command()
@click.option("--fix", is_flag=True, help="attempt to auto-fix fixable issues")
def audit(fix):
    """Scan this machine for common opsec mistakes."""
    click.echo("\ntorniquet :: opsec audit")
    click.echo("--------------------")
    results = audit_mod.run_audit(fix=fix)
    issues = 0
    for r in results:
        mark = "[x]" if r["ok"] else "[ ]"
        if not r["ok"]:
            issues += 1
        click.echo(f"{mark} {r['name']:<24} {r['detail']}")
    click.echo(f"\n{issues} issue(s) found." + ("" if fix else " run 'torniquet audit --fix' to address fixable ones."))


# -- profiles ----------------------------------------------------------------

@cli.group()
def profile():
    """Manage isolated identity profiles (separate SSH key + GPG keyring)."""
    pass


@profile.command("create")
@click.argument("name")
def profile_create(name):
    """Create a new isolated profile."""
    try:
        result = profiles.create(name)
    except FileExistsError as e:
        click.echo(f"error: {e}")
        raise SystemExit(1)
    click.echo(f"\ntorniquet :: profile created")
    click.echo("------------------------")
    click.echo(line("name", result["name"]))
    click.echo(line("ssh key", result["ssh_key"]))
    click.echo(line("gpg home", result["gnupg_home"]))


@profile.command("list")
def profile_list():
    """List existing profiles."""
    names = profiles.list_profiles()
    active = profiles.active()
    if not names:
        click.echo("no profiles yet. run 'torniquet profile create <name>'.")
        return
    for n in names:
        marker = "*" if n == active else " "
        click.echo(f"{marker} {n}")


@profile.command("use")
@click.argument("name")
def profile_use(name):
    """Switch the active profile (prints env vars to export)."""
    try:
        result = profiles.use(name)
    except FileNotFoundError as e:
        click.echo(f"error: {e}")
        raise SystemExit(1)
    click.echo(f"\ntorniquet :: profile")
    click.echo("----------------")
    click.echo(line("active", result["name"]))
    click.echo("\nrun this to apply in your current shell:")
    click.echo(f'  export GNUPGHOME="{result["GNUPGHOME"]}"')
    click.echo(f'  export SSH_KEY="{result["SSH_KEY"]}"')


# -- killswitch ----------------------------------------------------------

@cli.command("killswitch")
@click.argument("state", type=click.Choice(["on", "off"]))
def killswitch_cmd(state):
    """Block all non-tor traffic (on) or restore normal traffic (off). Requires sudo."""
    try:
        if state == "on":
            killswitch.enable()
            click.echo("killswitch enabled. only loopback + tor ports allowed out.")
        else:
            killswitch.disable()
            click.echo("killswitch disabled. traffic restored.")
    except subprocess.CalledProcessError as e:
        click.echo(f"error applying iptables rules (are you root?): {e}")
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"error: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
