# torniquet

Command-line anonymity and opsec companion for Tor. Wraps Tor's control
port, checks for common leaks, and helps keep identities compartmentalized
— all from one CLI.

## why

Most opsec advice is scattered across blog posts and manual steps.
torniquet turns the common ones into single commands: start Tor, check
your exit node, rotate circuits, audit your machine for common mistakes,
and switch between isolated identity profiles.

## requirements

- Python 3.10+
- Tor installed and on your `PATH`

```bash
# debian/ubuntu
sudo apt install tor

# macos
brew install tor
```

If you installed Tor via your system package manager, it likely also
started a background system service on the default ports. torniquet
manages its own Tor process, so disable the system one first:

```bash
sudo systemctl stop tor@default tor
sudo systemctl disable tor@default tor
```

## install

Using [pipx](https://pipx.pypa.io) (recommended):

```bash
git clone https://github.com/DuckzPY/tor-niquet.git
cd tor-niquet
pipx install -e .
```

Or in a virtualenv:

```bash
git clone https://github.com/DuckzPY/tor-niquet.git
cd tor-niquet
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## quick start

```bash
torniquet start          # launch tor, wait for circuit bootstrap
torniquet whoami         # exit ip, country, asn, basic dns leak check
torniquet rotate         # request a new circuit
torniquet audit          # scan for common opsec mistakes
torniquet stop           # shut down tor
```

## commands

| command           | description                                        |
|--------------------|-----------------------------------------------------|
| `start`            | start tor and wait for circuit bootstrap            |
| `stop`             | stop tor cleanly                                     |
| `status`           | show current connection state                       |
| `whoami`           | show exit ip/country/asn, check dns leaks            |
| `rotate`           | request a new circuit                                |
| `audit`            | scan for leaks (keys in history, open perms, cloud sync folders) |
| `audit --fix`      | attempt to auto-fix found issues                     |
| `profile create`   | create an isolated identity profile (ssh key + gpg keyring) |
| `profile use`      | switch active profile                                |
| `profile list`     | list existing profiles                               |
| `killswitch on`    | block all non-tor traffic (requires sudo)            |
| `killswitch off`   | remove killswitch rules                              |

## config

torniquet stores its state in `~/.torniquet/`:

```
~/.torniquet/
  torrc
  tor.pid
  profiles/
    default/
    work-anon/
```

## security notes

- `audit` only scans for common footguns. It is not a substitute for
  understanding your own threat model.
- `killswitch` uses `iptables` and requires sudo. Review the rules it
  applies (`torniquet/killswitch.py`) before trusting it in a high-stakes
  situation. Linux only.
- The DNS leak check is a heuristic, not a full leak-detection service.
  torniquet routes application DNS through the SOCKS proxy (`socks5h`),
  which is the correct approach, but a rigorous leak test needs a
  resolver-side comparison this tool doesn't yet perform.
- Tor provides network-level anonymity, not application-level. Your
  browser/app fingerprint can still deanonymize you independent of
  anything torniquet does.
- `whoami`'s geo-IP lookup tries a few providers, since some
  rate-limit or block known Tor exit IPs. One of them (`ip-api.com`)
  is queried over plain HTTP, not HTTPS.

## license

MIT
