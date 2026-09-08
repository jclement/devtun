# Changelog

Notable changes, newest first. Versions are [semver](https://semver.org); while
this is 0.x, a minor bump may break something.

## Unreleased

### Fixed

A TUI expert audited the interface at seven window sizes; these are what it
found, each verified before it was fixed.

- **You could not select or copy anything.** Mouse reporting was on with no way
  off, so the terminal handed drags to devtun and its own selection was dead —
  which made every URL on screen unreachable. `m` now releases the mouse.
- **The help was clipped at every height from 34 to 47 rows**, an ordinary
  40-row terminal included: the threshold was 34 and the box was 48 lines, and
  the line it cut was `? or esc to close`. The help did not say how to dismiss
  the help. It is now chosen by measuring, in two columns when there is width
  for them, with a short form for a window that can take neither.
- **Overlays truncated their own load-bearing sentences.** At 60 columns the
  approval modal cut "caller details come from the remote box and are not
  ve" — the words saying the provenance is unverified, on the most
  security-critical surface in the app. Overlays wrap now.
- **`y` on a live grant copied the empty string** and wiped the clipboard while
  the toast said "copied". It read `.rule`, and a grant keeps its subject in
  `.grant`; grants are the first rows on that tab.
- **The "connection lost" box was not modal.** A click still moved the cursor
  and `x` still hid a port, behind a box saying the link was gone.
- **Every security line sat one column right of every other line** — in the
  interface only, while the log file got it right, breaking the rule the code
  states: a line read in one must look like the same line read in the other.
  `🔒` is two cells and `⇄` is one. The abbreviation table was also duplicated
  and had drifted: neither copy knew about the SSH agent, so with a four-wide
  column every signing event rendered as `ssh…` — indistinguishable from `ssh`,
  which means the SSH session. There is one table now, and it is five wide.
- **The narrow key bar dropped `? help` and `esc quit` first**, leaving a
  first-run user at 45 columns with nothing on screen saying how to learn the
  keyboard or how to get out. Those two are now the last to go.
- The activity pane no longer draws a labelled separator over blank rows on a
  fresh connection; the sort arrow is `▲`/`▼` and points the right way; the
  detail box shows `mode: auto` instead of omitting the field the whole
  hide-and-show model turns on.

### Added

- **`R` reconnects from anywhere.** `r` meant reverse-sort, revoke, or
  reconnect depending on whether the link happened to be up — and there was no
  way at all to force a reconnect while connected, though the web board had one.

### Fixed

- **The web board opens itself**, and `w` in the interface opens it and copies
  its URL. It printed a forty-character URL with a token in it into a log the
  mouse cannot select — the mouse belongs to the port table — which is the worst
  of both: unmemorable, and uncopyable. `--web-open=false` opts out.
- The comic in the README is an absolute URL and clicks through to the full
  image, so it renders wherever the README is read rather than only on GitHub.

## v0.1.7

### Changed

- **The authorisation apparatus is one thing, `authz.Gate`.** The store, the
  prompter, the broker and the ritual of adopting a host's own rules on the
  first attach existed twice — once for the vault, once for the agent — as near
  copies that had already drifted once. Services now hold a Gate and disagree
  about the only thing they actually disagree about: what a subject is.
- **The Access tab finds brokers by interface**, in registry order, rather than
  by naming the two services the interface happens to import. That is the same
  lesson as the prompter: a list written by hand is a list a fifth service is
  forgotten from, and a broker missing from that tab is access nobody can see or
  take back.

### Added

- **`--web`: the board in a browser.** The same port table, rules, grants and
  security log, served on loopback and streamed with server-sent events. It runs
  alongside whichever interface owns the terminal rather than instead of it.

  It can hide a port, unhide one, revoke a rule or a grant, and ask for a
  reconnect — all of which either narrow what the remote can do or change what
  you are looking at. It cannot approve anything: a page that could has to be
  right about tokens, origins, rebinding and replay at once, and the cost of
  being subtly wrong there is somebody's secret.

  A port on 127.0.0.1 is not private, so: a token on every request (in the URL
  once, then a cookie), a Host header that has to name loopback — which is what
  stops DNS rebinding, and holds even when bound to 0.0.0.0 — and an Origin
  check on anything that changes something. The page is served from the binary.
- **A GPG agent bridge.** `git commit -S` on the remote signs with the key on
  your laptop, over GnuPG's *extra socket* — the restricted variant meant to be
  forwarded, which refuses the commands that manage keys rather than use them.
  devtun gives the box a `GNUPGHOME` of its own under `~/.devtun/gnupg`, links
  the socket in as `S.gpg-agent`, and imports your public keys there; the secret
  half never leaves this machine, which is the whole point.

  It adds no prompt, deliberately: gpg-agent already asks, and the passphrase or
  the touch on a token *is* the approval. What devtun adds is the record — every
  connection that box makes to your agent, including the cached signatures that
  raise no dialog at all.

  It is the first service that is **off until a host turns it on** (`OptIn` on
  its Meta), because it is the only one that changes how other tools on that box
  behave. Registered rather than omitted, so it is visible on the Services tab
  with everything else — a feature you have to already know about has no way in.
- **The browser bridge can be gated**, with `gate: ask` in a host file or the
  global config (or `--gate ask` for one run). Off by default: the dial for that
  service is the service itself, on or off per host, and a prompt for a window a
  command you just typed asked for is a prompt that gets answered without being
  read. When it is on, the subject is the *site* — one "always" answer covers
  the dozen redirects of a login flow — and its rules appear on the Access tab
  beside the others.

## v0.1.6

### Fixed

- **The frame lost its top line.** The approval bell was rung with
  `tea.Printf("\a")`, which prints a line *above* the program — scrolling the
  frame up by one and eating the header with it. The bell is written straight to
  the terminal now and disturbs nothing.

### Changed

- **The activity pane scales with the window.** It was three lines at every
  size: a waste on a tall terminal and, on a short one, three port rows you
  could not see. It now takes about a quarter of the frame, up to eight lines,
  and gives way entirely below the height where the table needs every row.
- **The Secrets tab is called Access**, because that is what it is: the rules on
  disk and the live grants, for the vault and the agent alike, with `r` to take
  one back. Called Secrets, the person looking for a rule viewer did not find
  it.
- **Left and right walk the tabs**, and step a settings row through its options
  in both directions. Nothing used them before, and they are what a hand reaches
  for before it finds `tab`/`shift+tab`.
- **The settings popup switches services on and off**, alongside the sort order
  and each service's own settings — `c` is where people look for "turn that off
  for this box". The Services tab keeps its toggle: it is where the reason a
  service cannot run here is written.

### Added

- **`devtun doctor`.** With no arguments it checks this machine — the config it
  reads, the 1Password CLI, which agent it would forward and what that agent is
  holding, whether a URL can actually be opened, and where an approval would
  appear. Given a host it also connects and checks that end: the helper, the
  login shell, and whether each service can run there.

  It changes nothing — no helper installed, no rc file edited — because a
  diagnostic that fixes things while looking at them cannot tell you what was
  wrong. The remote half is the session's own code path, so what doctor
  verifies is what a real connection does rather than a second implementation
  that can drift from it.
- The connection flags (`-i`, `-l`, `-p`, `-J`, `--host-key`, …) now work after
  a subcommand as well as before it: `devtun doctor -i key -p 2222 bedev`. A
  command for people who are already stuck should not reject the flags they
  reach for.
- **Desktop approval dialogs on every platform, and a `prompt:` setting to ask
  for them.** macOS had one; Linux and Windows had a terminal form. devtun now
  raises a dialog with whatever the machine has — osascript, zenity, kdialog,
  yad, or PowerShell's Windows Forms — because devtun's window is usually not
  the one you are looking at, and a secret request that sits unnoticed behind a
  browser is a prompt that has failed at its job. No GUI toolkit is bundled and
  none will be: they all want cgo, and this is a static binary that runs on
  three operating systems.

  `prompt: dialog` in `config.yaml`, or in a host file for one box; `--prompt`
  still wins. Under the interface a dialog replaces the modal when asked for,
  and the modal remains its fallback for the day the dialog cannot be drawn — a
  prompt that cannot be shown must not become an answer nobody gave. `deny` is
  now honoured under the interface too, where the modal used to be installed
  over it.
- **`D` on the Access tab rewrites a rule as a deny.** Revoking an allow you
  regret leaves devtun asking about it again; often what you mean is "and stop
  asking". It only tightens — a deny becoming an allow under the cursor is the
  accident deny-beats-allow exists to prevent, so that stays an edit of the file.
- **`b` opens the selected port in a browser**, alongside `o` and space. It is
  the letter people guess, and now the one the key bar advertises.
- **A per-host `hide` list**, in a host file's `tunnels:` section, in the same
  syntax as the global one. The noisy ports are usually a property of the box
  rather than of your taste, and `x` can only hide one port at a time — a range
  is the only thing that converges on a machine that binds to port 0. devtun
  never rewrites either list, and a list that will not parse is said out loud
  rather than silently read as empty.

## v0.1.5

### Changed

- **The global `hide` list accepts ranges**, in the same syntax as `--exclude`:
  `hide: "32768-60999"`, or a list mixing ports and ranges. A box that binds
  services to port 0 gets whatever the kernel hands out, so the noisy ports are
  different on every restart and could not be hidden one at a time.
- `authz.Broker` now owns the consult-policy-then-ask-a-human sequence, which
  had been a near-copy in each broker. The copies had already drifted once: a
  fix for an answer racing the prompt deadline went into one and had to be
  carried to the other by hand.

### Added

- Tests for the assembled service registry in `cmd/devtun`. Every bug that
  reached a release lived in the wiring rather than in a package — each package
  was correct and well tested, and nothing looked at how they fit together.
- An end-to-end test that downloads the helper instead of being handed one.

## v0.1.4

### Fixed

- **The SSH agent refused every signature under the interface, with no prompt.**
  `tui.Run` installed its approval modal on the 1Password service and nothing
  else, so the agent kept the prompter it was built with — `Serialize(DenyAll)`,
  which is the right default for a broker with nobody to ask and exactly why
  forgetting to install one fails silently. Brokers are found by interface now,
  so a fifth cannot be forgotten the way the fourth was.
- `known_hosts` defaults to the usual places rather than only what
  `--known-hosts` names, so a signing destination can be named instead of shown
  as a bare host-key fingerprint.

## v0.1.3

### Fixed

- **devtun kept asking for a `PATH` line that was already there.** The remote
  probe asks the login shell then the interactive one and takes the first
  non-empty answer — right for "does this box have `op`", wrong for `PATH`,
  where a login shell answers with a perfectly good PATH that simply lacks
  devtun's directory. It beat the interactive shell's answer, so somebody who
  had put the line in `.zshrc` exactly where the instructions said was told
  forever that they had not. PATH is unioned across both shells now.

### Changed

- **The interactive interface is the default.** `--log` gives a coloured line
  per event instead. Anything that is not a terminal still gets
  machine-readable output without being asked, and no flag overrides that.
- The first-scan summary lists ports in order. `Sync` iterates a map, so the
  same box printed a different line every run.

## v0.1.2

### Fixed

- **The helper download 404'd on every request.** The download path is built
  from the git tag (`v0.1.2`) while the asset filenames use the bare version
  (`0.1.2`); v0.1.1 used the bare version for both.

## v0.1.1

### Fixed

- **A release install could not put a helper on a remote box**, so 1Password and
  the SSH agent simply never started — while tunnels kept working, which made
  devtun look fine. The helper has to run on the *remote* platform, and there
  was no way to obtain one except cross-building from a checkout. It is now
  downloaded from this build's own release, pinned to that version and checked
  against the checksums published beside it.

## v0.1.0

First release. One SSH connection to a development box with four services on it:

- **tunnels** — every port the box opens appears on your localhost
- **1password** — the box's `op` calls reach your vault, one approval at a time
- **ssh-agent** — the box signs with your keys, one approved signature at a time
- **browser** — URLs the box tries to open, open here instead

Supersedes [autotun](https://github.com/jclement/autotun) and
[opproxy](https://github.com/jclement/opproxy), both archived. The notable
behavioural change from autotun: every port at or above `--min-port` is
forwarded and you hide what you do not want, remembered per host, rather than
whatever was already listening being ignored.
