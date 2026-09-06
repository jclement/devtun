# devtun

**Your remote dev box, but it behaves like localhost.** Ports, secrets, and the browser — over one SSH connection.

```sh
devtun bedev
```

That's the setup.

---

## The problem

You moved development to a real machine, because your laptop fan sounds like a leaf blower and the build takes nine minutes. Sensible. Then:

- `npm run dev` announces `http://localhost:5173/`. **Local** — to the machine you are not sitting at.
- `op read op://Personal/Docker/PAT` fails, because your vault is on your laptop and signing that box in to 1Password means leaving a session on a machine you rebuild every March.
- `gh auth login` tries to open a browser and gets "Couldn't find a suitable web browser."

Three problems, three workarounds, none of which survive closing your laptop lid.

## What devtun does

One SSH connection. Three services on top of it:

| | |
|---|---|
| **tunnels** | Every port the box opens appears on your localhost, on the same port number. Service appears, tunnel appears. |
| **1password** | The box's `op` calls come back to your unlocked vault, one approval at a time. The vault never leaves your laptop. |
| **ssh-agent** | The box signs with your keys — `git push`, `ssh` to another host — one approved signature at a time. Your keys never leave your laptop. |
| **browser** | URLs the box wants opened open on your machine, with the port rewritten to wherever that tunnel actually landed. |

They share the connection, the reconnect logic, the config file, and one screen. Turn any of them off; add a fourth later.

## Install

```sh
brew install jclement/tap/devtun
```

Static binaries — `CGO_ENABLED=0`, no libc drama. Or `go install github.com/jclement/devtun/cmd/devtun@latest`.

## On the remote box

One line in your shell rc. Once. Forever:

```sh
export PATH="$HOME/.devtun/bin:$PATH"
```

devtun offers to add it for you the first time, showing the exact file and the exact block, and remembers if you say no. It refuses to touch a symlinked rc, because a chezmoi- or stow-managed dotfile gets clobbered on the next apply.

Everything else is automatic: devtun uploads its helper to `~/.devtun/` on connect, checks the version every time, and re-uploads when it changes. There is no separate install step to forget.

## Ports: it shows you everything, you hide what you don't want

devtun forwards every remote port at or above 1024 — everything above the range only root can bind. Press `x` on the ones you don't care about and it remembers, per host, forever.

This is deliberate, and it's the opposite of what [autotun](https://github.com/jclement/autotun) did. autotun ignored anything already listening when it connected, which is right for a one-shot session and wrong for a box you reattach to every day: a service that was up before you connected would be invisible, and reattaching gave you a different board than you had five minutes ago. Now the board is the same every time, because it's *yours*.

First attach to a busy box forwards a lot at once. A remote postgres on 5432 will collide with your local one and land on an ephemeral port — you'll see a loud `≠` saying so. Press `x`, once, and it never bothers you again. Or put it in the global hide list and it never bothers you on any box:

```yaml
# ~/.config/devtun/config.yaml
hide: [5432, 6379, 3306]
```

## The interface

```sh
devtun bedev          # colourful log, one line per thing that happens
devtun --tui bedev    # the full interface
devtun --json bedev   # NDJSON, one object per event (automatic when piped)
```

Log mode is the default because most of the time you want this running in a corner and only want to *notice* it when something happens:

```
14:19:44 ⧉  ssh        connected to bedev
14:19:44 ⇄  tun        watching for listening ports on bedev (ss)
14:19:44 ⇄  tun        forwarding 11 ports: 3000 5173 5432 6379 8080 …
                       · 2 remapped (5432→52341 6379→52342) · x hides one for good
14:20:11 ⇄  tun        remote 4000 → 127.0.0.1:4000 (node vite)
14:21:58 🔒 op         bedev wants op://Personal/Docker/PAT — deploy.sh, pid 4412
14:22:01 🔒 op         gave bedev op://Personal/Docker/PAT (5m)
14:22:40 🔒 op         refused bedev op://Private/Root Keys/ssh — denied by rule
14:23:05 ⇄  web        opened http://localhost:5174/ for gh
```

Secrets are violet with a lock; tunnels are cyan. That separation is the entire argument for putting them in one window — you can tell at a glance which lines are about your vault without reading a word.

`--tui` gives you the interactive version:

```
╭─ devtun ▸ bedev ───── ● connected · 3 fwd · 2 hidden · 00:14:22 ─╮
│ ▸Tunnels │ Activity │ Secrets │ Services                        │
├──────────────────────────────────────────────────────────────────┤
│    LOCAL     ↓REMOTE  M  VIA    PROCESS         AGE  CONNS    IN │
│●    3000  ←     3000     http   node vite       14m      2 1.2MB │
│◦    5173  ≠     5173  +  https  node vite --ho   9m      0    0B │
│     8080  ←     8080     ?      python3 -m ht    4m      1  18KB │
│     ————        5432  ✕  ——     postgres              hidden by y│
├─ activity ───────────────────────────────────────────────────────┤
│ 14:22:01 🔒 op   ✓ op://Personal/Docker/PAT  allowed 5m · vite   │
│ 14:20:11 ⇄ tun   opened 5173 → localhost:5174                    │
│ 14:19:44 ⧉ ssh   connected · helper v0.1.0 current               │
╰─ ↑↓ move · x hide · e enter · c config · ? help · esc quit ──────╯
```

`●` means traffic is flowing right now, `◦` means it just showed up, `≠` means the local port isn't the one you asked for. The last three events sit under every tab, so a 1Password approval is never off-screen.

### Keys

| | |
|---|---|
| `↑↓` / `j k`, `g` / `G`, `pgup` / `pgdn` | move |
| `tab` / `1`–`4` | switch tabs |
| `x` | **hide this port** — remembered per host |
| `H` | show hidden ports, so you can unhide |
| `a` | auto → always on → hidden |
| `enter`, `d` | detail |
| `o`, `space` | open in your browser |
| `t` | say http / https — remembered |
| `l` | pin the local port · `n` name it |
| `y` | copy the URL (never a secret value) |
| `c` | settings · `p` pause new tunnels |
| `/` `s` `r` | search, sort, reverse |
| `esc`, `q` | quit — it asks, then dissolves the screen in green rain |

It's clickable too, because it's 2026 and you have a mouse.

## Your SSH keys, without handing them over

`ssh -A` already forwards an agent. The problem is that it is a blind trust
decision: anyone with your uid — or root — on that box can silently authenticate
as you, anywhere, for as long as you are connected, and you never find out.

devtun forwards the same agent through the same approval machinery as your
vault:

```
14:31:02 🔑 key  bedev wants to sign for github.com with SHA256:qN3l… (ed25519)
14:31:04 🔑 key  signed for github.com — allowed this key for github.com this session
14:33:19 🔑 key  ✗ refused signing for gitlab.com — denied by rule
```

`Add`, `Remove`, `Lock` and `Signers` are refused outright — never prompted,
never policy-checked. A remote box has no business modifying your agent, and
handing back a signer would hand back an ungated signing capability. Listing
your keys is allowed and logged, because it does reveal which keys you hold.

Where the destination is knowable, the prompt names it: OpenSSH 8.9+ tells the
agent which host it is authenticating to, and devtun resolves that against your
`known_hosts`. Where it is not — an older `ssh` — the prompt says the
destination is unknown rather than implying a precision it does not have.

It needs a second line in your shell rc, because `ssh` finds its agent through
an environment variable and there is no binary to shadow:

```sh
export SSH_AUTH_SOCK="$HOME/.devtun/devtun-agent.sock"
```

devtun offers to add it with the first one. `--no-agent` turns the service off.

**Grant it per key and destination for the session.** `git push` signs
constantly, and approving each one individually is how you end up switching the
whole thing off by lunchtime.

## Approvals

The first time a new secret is asked for, devtun asks you:

```
  bedev wants op://Personal/Docker/PAT
  command  op read op://Personal/Docker/PAT
  caller   jsc@bedev  deploy.sh  pid 4412
  cwd      /home/jsc/projects/api
           (caller details come from the remote box and are not verified)

> Allow once
  Allow this secret for 5m0s
  Allow this secret for this session
  Allow this secret always
  Allow anything from bedev for 5m0s
  Allow anything from bedev this session
  Deny
```

Narrowest first, so the safe answer is under the cursor and the broad ones take deliberate effort. Under `--tui` this is a modal inside the interface — the thing neither predecessor could do, because a terminal form and a full-screen TUI cannot share a terminal.

**Deny always wins.** A deny rule beats an allow rule and beats a temporary grant, so a rule you wrote to block something cannot be undone by clicking through a prompt later.

```yaml
# ~/.config/devtun/config.yaml
1password:
  rules:
    - {host: "**", subject: "op://Private/Root Keys/**", action: deny}
  accounts:
    default: adipose.1password.com
    by_vault: {Barreleye: barreleyesoftware.1password.com}
```

Only read-only `op` commands are proxied at all — `read`, `item get`, `item list`, and friends. Anything else needs an explicit `allow_commands` entry, because "pass the arguments through" would otherwise hand anyone with a shell on that box `op item delete` against an unlocked vault.

## It survives your laptop

Close the lid, change wifi, drop off the VPN. devtun probes the link every 15 seconds *with a timeout*, because the case that matters isn't a dropped connection — it's a black-holed one, where TCP thinks everything is fine and the packets simply stop. Without the timeout it would sit there looking healthy and dead.

Reconnection backs off 1s → 30s and resets after a connection holds for a minute. Local port assignments, live grants and approvals belong to the process rather than the connection, so a reconnect is invisible: your browser tabs keep working and you are not re-asked for a secret you approved a minute ago.

## Configuration

```
~/.config/devtun/
  config.yaml          global — hide list, deny rules, account routing
  hosts/bedev.yaml     per host — services, ports, approvals
```

One file per host, because the per-host state *is* the interesting state: it's what you hand-edit, diff, and copy to another laptop.

```yaml
# hosts/bedev.yaml
services:
  1password: {enabled: true}
  ssh-agent: {enabled: true}
  browser:   {enabled: false}
ssh-agent:
  rules:
    - {subject: "** → github.com", action: allow}
    - {subject: "** → **", action: deny}     # nowhere else, from this box
tunnels:
  ports:
    3000: {label: frontend, scheme: https, local: 13000}
    5432: {mode: hidden}
```

## Flags

The ones you'll actually use:

| | |
|---|---|
| `--tui` / `--json` / `--plain` | interface, NDJSON, plain log |
| `--only tunnels,browser` | run just some services |
| `-b, --bind` | local bind address (`0.0.0.0` shares on your LAN — the header will shout) |
| `--include` / `--exclude` | port sets, e.g. `3000,8000-9000` |
| `--min-port` / `--max-port` | the window (default `1024`–`65535`) |
| `--same-port` | never remap; a busy local port is an error |
| `--cache` | hold fetched secrets in memory (see below) |
| `--prompt` | `auto`, `tui`, `dialog`, `deny` |
| `--setup` | the remote rc: `ask`, `auto`, `never` |
| `--wait` | keep retrying until the box finishes booting |
| `-i`, `-l`, `-p`, `-J` | as `ssh(1)` |

`ssh_config` is honoured for `HostName`, `User`, `Port`, `IdentityFile`, `IdentitiesOnly`, `IdentityAgent`, `ProxyJump` and `StrictHostKeyChecking` — so `devtun bedev` works if `ssh bedev` works.

### `--cache`

By default no secret material outlives one `op` call. `--cache` keeps values in memory so a script reading the same reference twenty times doesn't cost twenty Touch ID prompts. Two rules keep it honest, both enforced in code with a test each:

- **A cached value never outlives the authorisation that produced it** — entries expire at the *earlier* of the cache TTL and the grant. "Allow once" caches nothing.
- **A cached value is never served without re-authorising** — the cache is read *after* the policy decision, never instead of it.

## What this is not

devtun does not make the remote box trustworthy. Anyone who can run processes as you on it can reach the socket, and the approval prompt is the only thing between them and your vault. This is the same trust model as SSH agent forwarding and deserves the same caution: approve narrowly, prefer per-secret grants, keep TTLs short.

A *changed* host key is refused outright, with no flag to override it. That is the shape of a machine-in-the-middle on a channel whose entire purpose is carrying secrets.

## Development

```sh
mise run dev              # build, boot a throwaway Docker dev box, attach to it
mise run dev -- bedev     # ...or point this build at a real host
mise run check            # lint + test — the gate before shipping
mise run e2e              # the Docker-backed end-to-end suite
mise run build:all        # cross-built helpers into dist/
mise run release          # bump, tag, push
```

`DESIGN.md` is for someone changing this. It explains the service architecture, why there is one socket, and what each subtle thing is defending against.

## Prior art

devtun replaces two tools of mine: [autotun](https://github.com/jclement/autotun) (ports) and [opproxy](https://github.com/jclement/opproxy) (1Password). Both are archived. Running them together meant two SSH connections, two config files, two reconnect supervisors, and two `known_hosts` implementations — and their interfaces could not share a terminal.

## License

MIT © 2026 Jeff Clement. Go nuts.
