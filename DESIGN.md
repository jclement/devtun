# devtun — design

For someone changing this. `README.md` is for someone running it.

## The problem

Three tools' worth of problem, which is why there were nearly three tools.

A remote dev box needs its ports forwarded, its `op` calls brokered back to a
vault that must not leave the workstation, and its browser requests redirected.
Each of those is a socket, a reconnect supervisor, an `ssh_config` resolver, a
`known_hosts` implementation, a config file and a policy about host identity.
Building them separately means building all six things three times, and running
them together means three SSH connections to one box.

Worse, they cannot share a terminal. opproxy's approval prompt is a `huh` form
that owns the screen; autotun is a Bubble Tea program that owns the screen. The
two could not be in one window even in principle, which meant approvals arrived
somewhere you were not looking.

devtun is one connection, one socket, one screen, and a registry of services on
top.

## Shape

```
cmd/devtun/
  main.go        argv[0] shim dispatch, then the cobra root
  up.go          `devtun <host>` — flags, service assembly, mode selection
  install.go     `devtun install`, `devtun hosts`

internal/
  service/       the Service contract and its optional interfaces
  event/         the activity bus: Class, Level, Sink, bounded history
  session/       the connection lifecycle, facts, control socket, shim sync
  sshx/          transport: ssh_config, auth, host keys, ProxyJump, keepalive
  shim/          the wire, the path conventions, and the remote-side clients
  tunnels/       port discovery and forwarding          (was autotun)
  onepassword/   the vault broker and its policy        (was opproxy)
  browser/       URL rewriting and handoff              (was autotun)
  hostcfg/       global and per-host configuration
  tui/           the interactive interface
  render/        the log and NDJSON renderers
  ui/            every Lipgloss style, and the TTY checks
```

## Key decisions

**1. A service is the unit, and the contract is three methods.** `Meta` says who
you are, `Probe` says whether you can work on this host, `Attach` binds you to a
connection. Everything else a service might want — a TUI pane, a subcommand, a
slice of the control socket, remote setup advice — is an optional interface
discovered by type assertion, so a service pays only for what it uses.

The test of the design is that a fourth service is a package, not a change. The
SSH agent service (see *Deferred*) is the one that will prove or disprove it.

**2. A reconnect is `Close` then `Attach`, never a special case.** A laptop
sleeps and a network comes and goes, so the interesting question is not what
happens on a clean start but what happens on the fiftieth reconnect. Making
reattachment the *only* path means it is exercised constantly rather than being
a rarely-taken branch that rots.

The corollary is where state lives, and it is the rule that matters most in this
codebase: **anything that must survive a reconnect belongs to the `Service`, not
the `Instance`.** Live grants, cached secrets and local port assignments are on
the Service. A reconnect is therefore invisible to policy — you are not re-asked
for a secret you approved a minute ago — and browser tabs keep working because
the same local port numbers are reclaimed.

**3. One socket, and a `Hello` frame routes it.** opproxy's protocol was an `op`
invocation with no room for a discriminator, so a second service would have
meant a second socket, a second path convention and a second line in the user's
shell rc. devtun reads a `Hello` naming a service and hands the connection to
that service's handler, which keeps its own message types after that.

Two consequences worth knowing. The service ids in `shim` are the services' own
`Meta().ID` values rather than names of their own — a second spelling would be a
mapping table that exists only to be got wrong, and whose failure mode is a
connection silently routed nowhere. And the envelope says nothing about what
follows it, so a service wanting a long-lived bidirectional stream needs no
renegotiation; one-request-per-connection remains the rule for `op` because it is
a deliberate isolation property, not an accident of the framing.

**4. The remote setup is one line, and it is a `PATH` entry rather than an
environment variable.** A per-session variable can only reach shells started
after the session began — precisely the wrong property for a tool you attach and
reattach to all day, since the terminal you already had open would never see it.
A fixed socket path plus a `bin` directory of symlinks means the shim can always
find its own way, and can fall through harmlessly when nothing is listening.

devtun *offers* to add that line rather than assuming. We already write to
`~/.devtun` unasked, but that is our directory; a shell rc is the user's file. The
edit is delimited by markers so it is idempotent and removable, is written to a
temporary file and renamed (a truncated rc greets someone with a broken login on
a box they may have no other way into), and is refused outright when the target
is a symlink, because a chezmoi- or stow-managed dotfile is either unwritable or
silently reverted on the next apply.

**4a. The shim looks in both places for the socket.** The session picks the
socket's home from what `$XDG_RUNTIME_DIR` said in the shell it *probed*; the
shim runs in a *different* shell, which may never have been given the same
environment — a `docker exec`, a cron job, an editor's integrated terminal,
anything started before the user's session was set up. When the two disagree the
shim reports "no devtun session" while devtun is running perfectly a metre away,
which is among the least debuggable messages a tool can produce. `DiscoverSocket`
therefore returns the first candidate that *is* a socket rather than the first
that is merely plausible. It costs a `stat`, and it was found by driving the
thing by hand rather than by any test.

**5. The helper is synced on every connect, not installed once.** opproxy made
installation a separate command you had to remember, and forgetting produced a
confusing failure much later. devtun asks the remote binary its version and
re-uploads when it differs. The check is a version handshake rather than a
checksum because the shim is *pretending to be `op`*, and asking "are you ours?"
is the only reliable way to tell it from the real 1Password CLI in the same
`PATH`. After an upload it re-asks, because a binary built for the wrong
architecture uploads perfectly and then fails with "cannot execute binary file".

**6. Ports: discover everything, hide deliberately, remember forever.** This is
the deliberate break from autotun, which snapshotted what was listening at
connect time and treated it as furniture — not forwarded, not even listed.

That is right for a one-shot session and wrong for a box you reattach to daily.
It made a service that was already running invisible, and it made the board
depend on *when* you happened to connect: attach before `npm run dev` and you
see it, attach after and you do not. A board that changes depending on when you
looked is not a board.

So the model inverts. Everything at or above `--min-port` is forwarded; `x` hides
a port and that is persisted per host. `Mode` is the only per-port decision —
`auto`, `on`, `hidden` — and it converges after one session.

The cost is honest and stated in the README: a first attach to a busy box
forwards a lot at once, and a remote database will collide with a local one. The
`≠` marker is loud about it and `x` is one keystroke.

One precedence call worth recording, because it differs from autotun and someone
will wonder. **`--exclude` beats a stored `mode: on`.** autotun let `on` win.
A flag typed in *this* command is a more recent and more deliberate act than a
preference saved last week, and if the stored preference won there would be no
way to suppress a port for a single session without editing config. The general
rule: the command line is about this run and must always be able to win.

**6a. The first scan is summarised; every scan after it is not.** Discovering
everything above the privileged ports means a busy box opens a dozen tunnels in
the same instant, and a dozen lines arriving together reads as something going
wrong rather than something working — on the very first impression devtun makes.
So the opening burst folds into one line naming the ports and the remaps, and
saying that `x` hides one for good. It fires once per session, never on a
reconnect, and only for four or more at once: two ports appearing later is news
about those two ports and is left alone.

**6b. A permanent refusal stops; everything else retries.** The supervisor's
disposition is to keep trying, because laptops sleep and wifi comes back. That
disposition is wrong for a box that will *never* accept the connection — an sshd
with forwarding switched off. Retrying that every thirty seconds looks exactly
like a hang, and the message that would have explained it scrolled past once.
The list of permanent failures is deliberately short: wrongly calling a
transient failure fatal gives up on a box that was about to come back, which is
worse than a few wasted retries. When in doubt, retry.

**6c. The guard parses `op`'s global flags, and refuses ones it does not know.**
This is the correction of the worst defect this project has had. `commandPath`
used to stop at the first argument beginning with a dash, so
`op --account work item delete X` produced an empty command path — which the
caller read as "no command to authorise" and allowed. Every read-only
restriction could be stepped around by prefixing any global option. The shim's
own dispatch had the same blind spot, so `op --account work run -- sh -c …` was
forwarded rather than handled locally, and ran on the workstation: a
vault-holding machine executing a string chosen by a semi-trusted box.

The table in `policy/guard.go` is now the authority on which options precede a
subcommand and which consume a value, and an option that is not in it is
refused rather than skipped. We cannot know whether an unknown flag eats the
next argument, and guessing wrong either hides the real command or invents one
— both fail open. The cost is a line to add when `op` grows a flag. That is the
right trade for a guard that means something.

**7. Authorisation is two layers and the order matters.** The *guard* asks
whether this shape of command may be proxied at all, default-deny against a
read-only allowlist; the *policy* asks whether this host may have this secret.
Guard first, because "pass the arguments through" would otherwise hand anyone
with a shell on the dev box `op item delete` against an unlocked vault.

Subjects, not command lines, are what get approved: `op read op://V/I/F` and
`op item get I --vault V --fields F` are one secret spelled two ways, so one
approval covers both and the prompt shows something a human recognises.

Deny beats allow, and persistent beats live — evaluated across the global and
per-host rule sets as one list. A rule written to block something cannot be
undone by clicking through a prompt later, or the policy file would be advisory.

**8. The zero value of every decision is "no".** `prompt.ChoiceDeny` is the zero
`Choice`, so a prompt that times out, is interrupted, fails to render, or has
nobody to render to all end the same way — not by convention but by the type's
construction. A nil prompter is `Serialize(DenyAll{})`, so the zero value of a
`Service` refuses rather than allows.

**8a. Everything from the remote is text; nothing from it is an instruction.**
Process names, command lines, caller fields and URLs all originate on a
semi-trusted box and all end up in event text a renderer writes to a terminal. A
string is not merely data there: an escape sequence in a process name can move
the cursor, repaint what an approval prompt appears to say, or — with OSC 52 —
write to the clipboard of whoever is reading the log. `event.Sanitize` strips
control characters, C1 escapes and the invisible steering characters (a
bidirectional override can reverse the visible order of a vault reference), and
it is applied at ingestion rather than at each renderer, because there are
several renderers and only one boundary.

**9. Caller information is displayed, never trusted.** The shim reports its user,
host, pid, working directory and parent process, and the prompt shows them
because "`deploy.sh` in `~/projects/api` wants this" is what makes an approval
decision possible. All of it is self-reported by a process on a machine we treat
as semi-trusted, so it is labelled unverified and never reaches a policy
decision. Decisions come from the SSH destination, which is authenticated.

**9a. Live grants are listable, and revocable one at a time.** A standing
"allow anything from bedev for five minutes" is the most consequential state in
the process, and for most of this project's life the only thing you could do
about one was drop every grant at once. `policy.Store.Grants` returns a read-only
copy — the store keeps its own grants unexported so nothing outside can forge
one — and the Secrets tab lists them above the persistent rules, because a rule
is a decision you made deliberately and can read on disk while a grant is one you
clicked through a minute ago and may well have forgotten.

**10. `event.Class` is the whole reason the merge is worth doing.** A secret
leaving your vault and a port being forwarded are not the same kind of news. Put
them in one window without distinguishing them and you have made both harder to
read. `Class` is set once, at the emitter, and every renderer keys its treatment
off it — which is also why a fourth service gets the right presentation for free.

Security is violet with a lock, network is cyan, and the hues are far enough
apart to separate in peripheral vision, which is the only kind of attention a
scrolling log actually gets.

**10a. Two glyph widths, stated rather than measured.** 🔒 is an
emoji-presentation code point and occupies two cells; `⇄` occupies one. Width
libraries disagree about this, and the symptom is subtle — every secret line
sits one column right of every tunnel line, which quietly destroys the alignment
the log exists to have. `ui.GlyphCells` is a table, because we choose the glyphs
and can simply know.

**10b. Safety owns the border, not a chip on it.** When tunnels are bound
somewhere other than loopback the whole top edge is drawn in the danger colour.
A LAN-exposed session is the one condition on screen where the cost of not
noticing is somebody else reaching your dev box, and a warning rendered at the
same weight as `3 fwd` is one you have stopped seeing by the second day.

**11. The bus delivers synchronously, under its lock.** That is only safe because
every subscriber is required to be non-blocking — the renderers write to a
buffered writer and the TUI adapter does a non-blocking send. The property it
buys is that events can never be delivered out of order, which matters when the
order is a security record.

**12. Probe once, under the user's own shell.** `ssh host command` runs a
non-interactive, non-login shell: no `.zshrc`, a bare `PATH`. A box configured
perfectly for the person who logs into it therefore looks unconfigured to a
naive probe — which is how opproxy came to print setup instructions, on every
connection, to someone who had already followed them. Instructions that appear
when nothing is wrong stop being read, which is exactly when it matters that
they are.

So the probe runs under `$SHELL -lc` *and* `-ic`, merged, first answer winning,
bounded by its own timeout because it runs a shell that can do anything. The
output is marker-delimited because an interactive shell prints whatever it likes
— a motd, a version-manager banner — and none of that is ours.

**13. A hung connection is the case that matters.** Not a dropped one. A closed
lid or vanished wifi leaves the TCP session open as far as both ends are
concerned, and a keepalive sent into it never gets an answer. `x/crypto/ssh` has
no deadline on `SendRequest`, so a naive keepalive loop blocks there forever:
nothing returns, the backoff loop never runs, and the session sits looking
healthy and dead. The ping is therefore sent from a goroutine with a timeout,
and there is a test with a server that authenticates and then deliberately never
answers — without the deadline it hangs until the test runner kills it.

**14. Host key algorithms come from what `known_hosts` already records.** A real
`sshd` holds several host keys while `known_hosts` usually records only the one
current when you first connected. OpenSSH reorders to prefer what it knows;
`x/crypto/ssh` does not, and puts ECDSA *ahead* of Ed25519 — the opposite. So a
host recorded by its Ed25519 key gets its ECDSA key presented, and a naive check
calls that a changed host key: a false alarm that reads exactly like a
machine-in-the-middle, on a host that has not changed at all.

There is no API to enumerate a host's recorded keys, but `knownhosts`' mismatch
error carries the list — so offering it freshly generated random bytes reports
back what *is* recorded, using the library's own host matching.

**15. All key authentication lives in one `publickey` method.** `x/crypto/ssh`
records which method *names* it has attempted and never retries one, so a second
`ssh.PublicKeys(...)` after the agent's is dead code — with a failure mode
indistinguishable from "the agent worked and the identity files were ignored".
Agent keys and file keys are therefore offered through a single callback, and
encrypted files become deferred keys so a passphrase is requested only once the
server has said it will accept that key.

**16. Two services, one wire format, two spellings.** `onepassword` and `browser`
each declare their request and response types unexported, and `shim` declares
matching pairs for the remote side. They must change together. This is a
deliberate duplication — the alternative is a shared types package that both the
workstation and the shim import, which couples every service to every other
one — but it needs the comment in both files that says so.

## Threat model

**What this protects.** A dev box that is rebuilt, shared, snapshot or briefly
compromised carries no 1Password session and no service token. An attacker with
access gets, at most, the secrets you approve while they are there — and each is
a prompt you saw and a line in the log.

**What it does not.** Anyone who can run processes as you on the remote box can
reach the socket, and the prompt is the only thing between them and the vault.
Grant "anything from bedev for 5 minutes" while they are watching and they get
anything from bedev for 5 minutes. Root on that box can read the socket too.
Same trust model as agent forwarding, and it deserves the same caution.

**Where the socket lives** matters for exactly that reason: `$XDG_RUNTIME_DIR`
when it is usable (per-user, 0700), otherwise a 0700 directory under `$HOME`.
Never `/tmp` — and that is now checked rather than assumed. The variable is set
by the remote box and devtun goes on to `chmod 700` whatever it names, so
`XDG_RUNTIME_DIR=/tmp` would have put the control socket in a world-writable
directory and, as root, turned shared `/tmp` from 1777 into 0700 on the way.
`usableRuntimeDir` refuses the shared directories and anything relative; the
fallback under `$HOME` is one devtun creates itself and is therefore always safe.
The socket's own 0600 is set after `sshd` creates it and so races with creation;
the private directory does not.

**Host key changes are fatal**, with no override flag. That is the shape of a
machine-in-the-middle on a channel whose purpose is carrying secrets.

**URLs from the remote are never a command line.** `OpenURL` refuses anything
that is not `http`/`https` and passes it as a single argument to a fixed
program, never through a shell — so `; rm -rf ~` in a URL is a URL that fails to
resolve. A loopback port with no tunnel is refused rather than pointed at
whatever *your* machine runs there: opening the wrong service is worse than
opening nothing, because it looks like it worked.

## Known limitations

- **No secret masking in `op run`.** Real `op run` scrubs values from the child's
  output. Doing that means buffering stdout and stderr, which breaks interactive
  programs and progress bars. `--no-masking` is accepted and ignored; assume
  nothing is masked.
- **The remote box must be POSIX.** The probe and setup run `printf`, `uname`,
  `mkdir`, `chmod`, `ln` and `awk` through the login shell. The workstation half
  runs anywhere Go does, Windows included; the shim side needs a unix-like host.
- **`sshd` must permit `AllowStreamLocalForwarding`.** It is the default, but a
  hardened server may have turned it off. The error says so, and names
  `AllowTcpForwarding` too, because OpenSSH gates unix forwards on it as well.
- **`ssh_config` support is partial.** `Host`, `HostName`, `User`, `Port`,
  `IdentityFile`, `IdentitiesOnly`, `IdentityAgent`, `ProxyJump` and
  `StrictHostKeyChecking` are honoured. `Match`, `ProxyCommand`, `ControlMaster`
  and `CertificateFile` are not.
- **FIDO private key files cannot be read directly.** `sk-ssh-ed25519` and
  `sk-ecdsa` as files need libfido2, which means cgo and the end of the static
  binary. Both work fine *through an agent*, which is how they are normally used.
- **No `op` subcommand introspection.** The allowlist is a hand-maintained list
  in `onepassword/policy/guard.go`. A new 1Password CLI command is denied until
  someone adds it — the right default, but the file needs occasional attention.
- **A cached secret can be stale.** A value rotated in 1Password while an entry
  is live is served until its TTL runs out. There is no invalidation signal from
  1Password to hook into.
- **One session per host per process.** Two devtun sessions against one box
  fight over the socket path; the second wins new connections.

## Deferred

**The SSH agent as service #4.** This is the immediate next thing, and the real
test of §1. opproxy described itself as "agent forwarding, inverted", so
forwarding an actual agent is the case this architecture was reverse-engineered
from, and `x/crypto/ssh/agent` supplies both halves.

The value is not the forwarding — `ssh -A` does that. It is that `ForwardAgent`
is today a blind trust decision: anyone with your uid or root on that box can
silently authenticate as you, anywhere, for as long as you are connected, and
you never learn it happened. devtun already owns the four things that fix it —
an approval prompt, persistent per-host policy with deny beating allow, TTL
grants, and a security-classed log.

- `Sign` is gated. `Add`, `Remove`, `RemoveAll` and `Lock` are refused outright:
  a remote box has no business mutating your agent, the same reasoning as the
  guard refusing `--session` and `--config`. `List` is allowed but logged.
- The subject is the key fingerprint plus the destination where it is knowable.
  OpenSSH 8.9+ sends `session-bind@openssh.com` carrying the destination host
  key, which is how it implements its own agent restrictions; when it is present
  the prompt can name github.com, and when it is absent the prompt must say so
  rather than implying a precision it does not have.
- Grants must default to per (key, destination) for a session, or `git push`
  generates enough prompts that the service is switched off within the hour.
- **It does not fit the `Hello` envelope, and this document used to claim it
  would.** An `ssh` client connects to `SSH_AUTH_SOCK` and immediately speaks the
  agent binary protocol; it will never send devtun's greeting frame, and nothing
  can make it. So the agent needs its own remote socket — either a second
  reverse forward, or a small resident adapter that speaks agent protocol on one
  side and Hello on the other. Both cost the "one socket" property in §3.

  That is worth stating plainly because §1 advertises the service seam as
  extensible, and this is the first real test of the claim. The verdict is
  mixed: the *lifecycle* half (Meta/Probe/Attach/Instance, reconnection, config,
  events) genuinely does absorb a new service without changes. The *transport*
  half does not, and neither does the authorisation machinery — approval,
  grants, deny-precedence and policy persistence all live inside
  `internal/onepassword` rather than in anything reusable. An agent broker wants
  every one of them. Lifting them into a shared `internal/authz` is the work
  this service will actually require, and pretending otherwise would mean
  discovering it halfway through.
- It costs the "one line forever" property: `ssh` finds its agent through
  `SSH_AUTH_SOCK` and there is no binary to shadow, so the rc block becomes two
  lines with a fixed socket path.

**Other services** — a forwarded Docker socket, an AWS SSO broker, GPG. The seam
is the deliverable, not a fourth service.

**Several hosts in one interface.** `session` is already per-host and nothing
prevents it; the first cut is one host per process, as both predecessors were.
