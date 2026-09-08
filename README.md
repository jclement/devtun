# devtun

**Remote power. Local feel.**

Your development machine does the work. Your laptop stays cool, quiet, and free to be closed. Ports, secrets, SSH keys and browser windows come to you over one SSH connection.

```sh
devtun bedev
```

That's the setup.

[![How devtun came to exist, in eight panels](https://raw.githubusercontent.com/jclement/devtun/main/origin.png)](https://raw.githubusercontent.com/jclement/devtun/main/origin.png)

---

## The problem

Agentic development means more parallel sessions, more background processes, and more things that need to keep running. A dedicated dev VM or workstation is a better place for all of that: powerful, isolated, always on, and not currently trying to take off from your desk.

So you move development to a real machine. Sensible. Then:

- `npm run dev` announces `http://localhost:5173/`. **Local** — to the machine you are not sitting at.
- `op read op://Personal/Docker/PAT` fails, because your vault is on your laptop, and signing that box in to 1Password means leaving a session on a machine you rebuild every March.
- `git push` needs your SSH key. `ssh -A` will lend it the *whole agent*, silently, to anyone with root there, for as long as you are connected. You will never find out.
- `gh auth login` tries to open a browser and gets "Couldn't find a suitable web browser."

Four problems, four workarounds, none of which survive closing your laptop lid.

## What devtun does

One SSH connection. Five services on top of it:

| | |
|---|---|
| **tunnels** | Every port the box opens appears on your localhost, on the same port number. Start Vite on `127.0.0.1:3000` over there; open `http://127.0.0.1:3000` here. Service appears, tunnel appears. |
| **1password** | The box's `op` calls come back to your unlocked vault, one approval at a time, scoped to the secrets you say yes to. The vault never leaves your laptop. |
| **ssh-agent** | The box signs with your keys — `git push`, `ssh` onward — one approved signature at a time, and you can grant it *this key, for github.com, for ten minutes*. Your keys never leave your laptop. |
| **gpg-agent** | `git commit -S` over there signs with the key over here, through GnuPG's own restricted socket. Off until you ask for it. |
| **browser** | URLs the box wants opened open on **your** machine, with the port rewritten to wherever that tunnel actually landed. |

They share the connection, the reconnect logic, the config file, and one screen. Every one is on or off per host; adding a sixth is a package that implements one interface.

The result is a remote machine that behaves remarkably like localhost. Your agents keep running when you close the lid. Your dev box stays isolated from your personal environment. Your laptop stays cool and quiet. And the tools you actually need are still in reach.

Combined with **VS Code Remote**, **herdr**, or whatever you drive your agents with, remote development stops being a compromise.

## Install

```sh
brew install --cask jclement/tap/devtun
```

A cask rather than a formula because Homebrew distributes prebuilt binaries that
way now. Static — `CGO_ENABLED=0`, no libc drama. Or `go install
github.com/jclement/devtun/cmd/devtun@latest`, or grab a binary from
[releases](https://github.com/jclement/devtun/releases).

```sh
devtun update          # replace this binary with the latest release
devtun update --check  # just say whether one exists
```

It refuses to overwrite a Homebrew-managed install and tells you to `brew
upgrade` instead, because overwriting a file your package manager believes it
owns is how you end up with a version number that is a work of fiction.

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

Ranges work too, in the same syntax as `--exclude`. That matters more than it
sounds: a box that binds a service to port 0 gets whatever the kernel hands out,
so the noisy ports are different every restart and cannot be hidden one at a
time.

```yaml
hide: [5432, "32768-60999"]     # postgres, and the whole ephemeral range
```

The same key works in a host file, for the ports that are noisy on *that* box
and nowhere else — which is most of them:

```yaml
# hosts/bedev.yaml
tunnels:
  hide: ["32768-60999"]         # this box binds its test servers to port 0
```

`x` writes `mode: hidden` against one port; a `hide:` list is how you say it
about a range. devtun never rewrites either list, so a range you wrote stays a
range. To bring one port back from a hidden range, press `a` on it until it says
*on* — an explicit "always" beats every hide list.

## The interface

```sh
devtun bedev          # the interface
devtun --log bedev    # a coloured line per thing that happens
devtun --json bedev   # NDJSON, one object per event (automatic when piped)
```

The interface is the default, because it is what devtun *is*: a board of what is forwarded, what is open in your name, and what just happened. A TUI written into a pipe is line noise, so anything that is not a terminal gets machine-readable output without being asked — no flag overrides that.

`--log` is for when you want it running in a corner and only want to *notice* it when something happens:

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

The interface:

```
╭─ devtun ▸ bedev ───── ● connected · 3 fwd · 2 hidden · 00:14:22 ─╮
│ ▸Tunnels │ Activity │ Access │ Services                         │
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
╰─ ↑↓ move · x hide · b browser · enter detail · c config · ? help ╯
```

A summary strip across the top counts what is live, new, hidden and broken, with total throughput — so "is anything wrong" is one glance rather than thirty rows. A scrollbar and an `n–m of N` in the bottom border say when the list is cut, which matters because forwarding everything above 1024 means a busy box is thirty rows, not five. `●` means traffic is flowing right now, `◦` means it just showed up, `≠` means the local port isn't the one you asked for — and when the table is short enough to leave room, a legend spelling all of that out sits underneath it.

`/` searches, and it is a **fuzzy** match ranked by relevance: `vite` finds `node vite` and puts it above a port that merely sorts earlier. The activity pane sits under every tab, so a 1Password approval is never off-screen; it takes about a quarter of the window, up to eight lines, and gives way entirely on a window too short to spare them.

### Keys

| | |
|---|---|
| `:` | **the command palette** — every action by name, with the key that runs it |
| `↑↓` / `j k`, `g` / `G`, `pgup` / `pgdn` | move |
| `tab`, `← →` / `1`–`4` | switch tabs |
| `x` | **hide this port** — remembered per host |
| `H` | show hidden ports, so you can unhide |
| `a` | auto → always on → hidden |
| `enter`, `d` | detail |
| `b`, `o`, `space` | open in your browser |
| `t` | say http / https — remembered |
| `l` | pin the local port · `n` name it |
| `y` | copy the URL (never a secret value) |
| `c` | settings — sort, and which services run here (`← →` changes a row) |
| `p` | pause new tunnels |
| `/` `s` `r` | search, sort, reverse |
| `r` · `D` | Access tab: revoke a rule or grant · rewrite an allow as a deny |
| `esc`, `q` | quit — it asks, then dissolves the screen in green rain |

Don't learn any of that. Press `:` and type what you want — "hide", "revoke", "browser", "prompt" — and it tells you which tab it lives on and which key runs it. The keyboard is twenty-five keys deep across five tabs and the same letter deliberately means different things on different ones; the palette is how you stop caring, and it teaches its own way out of a job.

It's clickable too, because it's 2026 and you have a mouse — and `m` hands the mouse back to your terminal when you want to select and copy text instead.

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

## Signing commits with the key that never leaves your laptop

`git commit -S` on a dev box needs a private key. The choices are to copy your key there — the thing a YubiKey exists to make impossible — or to stop signing, which is what most people quietly do.

devtun forwards **gpg-agent** instead, using GnuPG's own *extra socket*: the restricted variant meant to be handed to somewhere less trusted, which refuses the commands that manage keys rather than use them.

```sh
# hosts/bedev.yaml — or press e on the Services tab
services:
  gpg-agent: {enabled: true}
```

It is **off until you turn it on**, and it is the only service that is, because it is the only one that changes how other tools on that box behave: it gives the remote a `GNUPGHOME` of devtun's own under `~/.devtun/gnupg`, links the forwarded socket in as `S.gpg-agent`, and imports your **public** keys there — gpg needs the public half to know what it is signing with, and the public half is public. Unset one variable and the box is exactly as it was.

**This one doesn't add a prompt, on purpose.** gpg-agent already asks: an uncached signature raises pinentry on your machine, and the passphrase or the touch on your token *is* the approval. A second prompt in front of it would ask the same question twice, and that is how people learn to click through both. What devtun adds is the record — every connection that box makes to your agent is a line in the security log, including the cached signatures that raise no dialog at all.

## Approvals

The first time a new secret is asked for, devtun asks you:

```
  bedev wants op://Personal/Docker/PAT
  command  op read op://Personal/Docker/PAT
  caller   jsc@bedev  deploy.sh  pid 4412
  cwd      /home/jsc/projects/api
           (caller details come from the remote box and are not verified)

> Yes, once
  Yes, this secret — 5m0s
  Yes, this secret — this session
  Yes, this secret — always (writes a rule)
  Yes to anything from bedev — 5m0s
  Yes to anything from bedev — this session
  No
  No, and stop asking this session
  Never, this secret (writes a deny rule)
```

Narrowest first, and every approval sits above every refusal, so overshooting downward can never land on a "yes". Walking away, pressing escape, or letting it time out all mean *No*. Under `--tui` this is a modal inside the interface — the thing neither predecessor could do, because a terminal form and a full-screen TUI cannot share a terminal.

### Where you get asked

Press `c` for the **Config** tab and it is the first row. Every row there says
which file its value came from — `host`, `global` or `default` — and `g` arms
which of the two your edit lands in, because a settings screen for a tool with
two levels of config that doesn't tell you which one you're looking at is a
settings screen you can't trust. The approvals row also tells you what *this*
machine can actually draw a dialog with, and names what to install if the answer
is nothing.


Three places, and it is a setting rather than only a flag, because the right
answer is a property of the machine you sit at:

| `prompt:` | asks |
|---|---|
| `tui` | in the interface's modal, or as a form in the terminal in log mode |
| `dialog` | in a **desktop dialog**, raised in front of whatever you are doing |
| `auto` | the dialog if this machine can draw one, otherwise the terminal (default) |
| `deny` | nobody. Everything not already covered by a rule is refused |

```yaml
# ~/.config/devtun/config.yaml
prompt: dialog          # everywhere

# ~/.config/devtun/hosts/bedev.yaml
prompt: tui             # ...except this box, which I only touch from a terminal
```

`--prompt` beats both, because the command line is about this run.

There is no bundled GUI toolkit and there is not going to be one: every Go
option that draws its own window wants cgo, and devtun is a static binary you
copy to three operating systems. What every desktop already has is a program
whose whole job is to ask a question, so devtun uses that — **osascript** on
macOS, **zenity**, **kdialog** or **yad** on a Linux desktop, **PowerShell's
Windows Forms** on Windows. None is a dependency: with none of them installed,
`auto` is the terminal and `dialog` tells you which programs it looked for.

A dialog that cannot be drawn — a locked screen, a broken helper, a box you are
on over SSH — falls back to asking in the terminal or in the interface. It never
becomes a silent yes, and it never becomes a silent no either.

**"No" and "Never" are different answers.** *No* refuses this request and leaves no trace. *No, and stop asking* refuses for the rest of the session — the answer for something you keep declining, which previously had no expression at all: the only way to make the prompt stop was to say yes. *Never* writes a deny rule.

**Deny always wins**, at every level: a refusal beats an approval whether it was typed into a file, written by *Never*, or clicked as *stop asking*. Among answers of the same kind the written one wins. So a rule you wrote to block something cannot be undone by clicking through a prompt later — and a standing allow rule does not quietly re-open something you just said no to. That asymmetry is deliberate: an approval given by mistake costs you one secret, a refusal given by mistake costs you a moment's confusion, and the two should not be equally easy to reverse by accident.

The **Access** tab in `--tui` lists everything currently deciding — live grants and refusals with their remaining time, the rules devtun wrote, and the rules from your own config. `r` revokes the first two, and `D` rewrites a rule you regret as a deny, which is the difference between "stop allowing this" and "stop asking me about it". Rules from your config are marked *from your config* and are not editable there: devtun did not write them, and quietly rewriting a file you hand-wrote would be a worse surprise than saying no.

`D` only ever tightens. Turning a deny back into an allow on one keystroke, over whichever row the cursor happens to be on, is precisely the accident that deny-beating-allow exists to prevent — so loosening stays deliberate: revoke the rule, or edit the file.

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

## The board in a browser

```sh
devtun --web on bedev              # a port the kernel picks
devtun --web 127.0.0.1:8765 bedev  # ...or one you can bookmark
```

It **opens in your browser by itself** (`--web-open=false` if you would rather it did not), and prints the URL as well.

**The URL works exactly once.** It carries a token that is traded for a session cookie on the first request and is then dead — so the copy left behind in your browser history, or in a URL-logging extension, is not a way back in. The tab that made the trade keeps working; a second attempt on the same link says so plainly rather than failing with a bare 401. Restart devtun for a fresh one.

Under the interface, `w` opens the board and copies its URL to your clipboard — over OSC 52, so it works through SSH and tmux. That is the answer to "the URL is in the log and I cannot select it": the mouse belongs to the port table, so devtun hands you the link rather than making you drag across one.

The page shows the same board the interface draws: the port table with its live counters, the security log streaming in, and — in two separate panels, because they are two different kinds of thing — the **grants** that are live now and lapsing on their own, and the **rules** that are written down and stay until revoked. You can hide a port, show the hidden ones again, revoke a rule, revoke a grant, and ask for a reconnect. A rule that came from your config file says *edit your config file* instead of offering a button that would refuse. It runs *alongside* whichever interface owns your terminal rather than instead of it, so `--web` and the TUI are a fine combination — one on the second monitor, one in the pane.

**It cannot approve anything, deliberately.** A page that could approve has to be right about tokens, origins, rebinding and replay all at once, and the cost of being subtly wrong there is one of your secrets. Approvals stay where they were: the interface's modal, a desktop dialog, or the terminal.

Three things keep the port honest, because a port on `127.0.0.1` is not private — every process on your machine can reach it, and so can a web page you have open:

- a **token**, on every request;
- the **Host** header has to name loopback, which is what stops DNS rebinding — a hostname somebody else controls, pointed at 127.0.0.1. This holds even if you bind to `0.0.0.0`, so the board stays local whatever address you give it;
- an **Origin** check on anything that changes something, so a page you happened to be reading cannot post to it.

The page is served from the binary — no CDN, no build step, works on a train.

## When something isn't working

```sh
devtun doctor           # this machine: config, op, your agent, a browser, approvals
devtun doctor bedev     # ...and that box: the helper, the shell, every service
```

It checks nothing twice and changes nothing at all — no helper installed, no rc file edited, no config written. A diagnostic that fixes things while looking at them can't tell you what was wrong.

```
this machine
  ✓ devtun       devtun v0.1.6 (3d9db54, 2026-09-07T04:44:51Z)
  ✓ config       /Users/jsc/.config/devtun · 3 host(s)
  ✓ approvals    auto — a desktop dialog, drawn with osascript
  ! 1password    op 2.39.0 at /opt/homebrew/bin/op, but no account answered
    → run `op account add`, or sign in to the app and enable the CLI integration
  ✓ ssh-agent    1 key(s) via /Users/jsc/.gnupg/S.gpg-agent.ssh
  ✓ browser      URLs open with open

bedev
  ✓ ssh          connected to jsc@bedev (linux/amd64)
  ✓ shell        /usr/bin/zsh · /home/jsc/.zshrc
  ! helper       not installed yet
    → it is installed automatically on the next connection, from the v0.1.6 release
  ✓ tunnels      forward every port the remote box opens onto localhost
  ✓ ssh-agent    forward your SSH agent, one approved signature at a time
  ! shell setup  2 line(s) missing from the login shell
    → add to /home/jsc/.zshrc:
    → export PATH="/home/jsc/.devtun/bin:$PATH"
    → export SSH_AUTH_SOCK="/home/jsc/.devtun/devtun-agent.sock"

13 ok · 3 to look at
```

The remote half runs the *same* code a session does — the same connector, the same one-shot probe, the same question put to each service. A doctor that asked its own questions would drift from the thing it is checking, and the failure it missed would be the one that only happens on a real connection.

`--json` gives you the whole report as one object (and is automatic when the output isn't a terminal). It exits non-zero only if something is actually broken: a box without the 1Password CLI is an ordinary box, not a failure.

## Configuration

```
~/.config/devtun/
  config.yaml          global — hide list, deny rules, account routing, prompt
  hosts/bedev.yaml     per host — services, ports, approvals
```

One file per host, because the per-host state *is* the interesting state: it's what you hand-edit, diff, and copy to another laptop.

**Every service is on or off per host, and that's the main dial.** Press `e` on the Services tab, or change it on the **Config** tab, or write it in the host file — all three land in the same place, and it applies from the next connection. `--only tunnels,browser` does it for one run. A box that has no business signing with your keys simply doesn't get the agent; you don't have to say no to it every day.

```yaml
# hosts/bedev.yaml
prompt: dialog
services:
  1password: {enabled: true}
  ssh-agent: {enabled: true}
  browser:   {enabled: false}
ssh-agent:
  rules:
    - {subject: "** → github.com", action: allow}
    - {subject: "** → **", action: deny}     # nowhere else, from this box
browser:
  gate: ask                                  # ask before each site (off by default)
tunnels:
  hide: ["32768-60999"]                    # never, on this box
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
| `--prompt` | `auto`, `tui`, `dialog`, `deny` — overrides `prompt:` in your config |
| `--setup` | the remote rc: `ask`, `auto`, `never` (default: your config, else ask) |
| `--web` | also serve the board in a browser: `on`, or an address (it opens by itself) |
| `--wait` | keep retrying until the box finishes booting |
| `-i`, `-l`, `-p`, `-J` | as `ssh(1)` — and they work on `doctor` and `install` too |

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
