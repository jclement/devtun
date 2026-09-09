# Changelog

Notable changes, newest first. Versions are [semver](https://semver.org); while
this is 0.x, a minor bump may break something.

## v0.1.15

Two independent reviews — one reading the code and running the interface, one
reading only the code — found these. Each was reproduced before it was fixed.

### Fixed

- **A malformed host file read as an empty one.** Host files load lazily and
  `Err()` reports only what has been read, so the refusal gate at startup was
  looking at the global file alone. A broken `hosts/<host>.yaml` therefore lost
  its deny rules and hide ranges in silence and devtun carried on with wider
  access than the file asked for — the exact failure that gate exists to
  prevent, arriving through the door it was not watching. `doctor` had the same
  blind spot.
- **Every broker was given 1Password's global rules.** One slice was read from
  the `1password:` section and handed to all three, so a global 1Password deny —
  the shape the README recommends — also refused every SSH signature and every
  browser open, while `ssh-agent:` and `browser:` rules written in the global
  file were read by nobody. Each broker now reads its own section.
- **Nothing you decided was on disk until a clean exit.** `x` to hide, a service
  toggle, and — worst — a `Never` deny rule only marked the file dirty and
  waited for the process to quit tidily. A refusal you believe is protecting you
  has to survive `kill -9`. Writes are durable now; the fear the old comment
  recorded (a busy port table rewriting YAML every two seconds) does not happen,
  because every writer is a human action.
- **A second devtun on one box silently broke the first.** The newcomer took the
  socket over and the first session kept running — still calling itself
  connected, its services still listed as ready — while sshd routed nothing to
  it ever again. It now refuses, with `--take-over` for a first session that has
  gone away without releasing the socket. The probe reads `/proc/net/unix`,
  which every Linux box has: the first version asked `nc` and then `socat`, the
  test container has neither, and "cannot tell" was being read as "go ahead".
- **`space` did nothing**, anywhere it was advertised — open in browser, step a
  Config value, answer an approval. Bubble Tea reports a space press as the key
  named `space`, and every handler matched the literal `" "`.
- **`--web <address>` was silently moved** when the port was busy. The flag that
  distinguishes a named address from the default one was written, promised in
  the README, and never actually passed.
- **The `?` help was garbled at 100 columns and wider**: the key column was
  padded to exactly the width of its widest entry, so `tab, ← →, 1-5` ran into
  `switch tab`, and long descriptions overran into the right-hand column.
- **Every selected row on Activity, Access, Services and Config ended in a `…`**
  that meant nothing had been cut. They padded to the full frame width and the
  scroll track then clamped that last cell away. On the Access tab it read as
  "there is more to this rule".
- **The web board still said it could not approve**, on the same screen as the
  approval dialog it can answer.
- A flaky SSH test that read the server's record of a client banner without
  waiting for the server to have written it. It went red once in a full
  `-race ./...` and passed five runs of its own package, which is the signature
  of a timing race and not of a defect — but a suite you cannot trust when it is
  red is worth less than one test.

## v0.1.14

### Changed

- **`--web` makes the terminal a log and the board the surface.** A board and
  the interface are two implementations of one thing, and running both is
  redundant rather than complementary — the interface costs the alt screen, the
  mouse and your scrollback, which is worth paying to interact there and worth
  nothing if you are interacting in a browser. A log is a different thing: a
  record you can scroll, select, grep and pipe, which is what you actually want
  beside a board. `--tui --web` still gives both, for one on each monitor.

### Added

- **`--web` works bare**, and defaults to `127.0.0.1:8422` so the board can be
  bookmarked. That port gives way to a free one when something already has it —
  a second devtun on one machine is an ordinary thing to want — while an address
  you name is honoured or reported, never quietly moved.

### Fixed

- **A data race on the board's URL.** `Run` wrote it from its own goroutine
  while the caller polled `URL()` from another, with no synchronisation, in
  shipped code. Found by a new test that raced them the way `devtun --web`
  already did.

## v0.1.13

### Fixed

- **The web board was dimmed by a grey overlay at all times.** The approval
  dialog's backdrop is `display: grid`, and the `hidden` attribute is only
  `display: none` in the browser's own stylesheet — which any author rule
  outranks. So the backdrop stayed on screen over everything while the page's
  own script correctly believed it was hidden. One `[hidden] { display: none
  !important }` makes the whole class of that bug impossible, and a test keeps
  it there.
- **doctor said 1Password was fine on a machine where every request would be
  refused.** It ran `op account list` — which reads a file on disk and succeeds
  with no session at all — while claiming in its own comment to be testing that
  op "will answer". It runs `op whoami` now, which needs a live session, and
  tells apart the three states that have three different fixes: not installed,
  installed with no account, and configured but not signed in. The last is the
  common one and used to pass silently.

### Added

- **`devtun doctor` reports whether an approval will actually be heard.** It
  already said where a request would appear; a machine that cannot make a sound
  is the other half of the same question, and a request nobody hears is one that
  times out — which reads as a refusal nobody made. A silent machine is a
  warning with something to do about it, not a failure.

### Changed

- `DESIGN.md` caught up with the last two releases: the approval desk and what
  makes it safe to answer over HTTP, the no-emoji rule and the padding
  arithmetic its removal retired, and why the question is a centred popup that
  makes a noise rather than a pair of bands. The section letters in §10 were
  renumbered, having grown a second `10b` and a second `10c`.

## v0.1.12

### Changed

- **A waiting approval is a popup in the middle of the screen**, on all three
  surfaces: the terminal, the desktop dialog, and the web board. It was briefly
  a pair of bands down the top and bottom edges, on the theory that you would
  want the board visible while deciding. In front of a real terminal that theory
  was simply wrong — edges are where an interface puts what you are meant to
  ignore, and a question that has stopped the world belongs in the middle of it.
  The terminal's box has a heavy red double frame rather than the violet one it
  shares with the help, because it is the only overlay that is a question rather
  than something to dismiss.
- **The answers are numbered on every surface**, and the numbers work. Somebody
  interrupted by a red box should not have to count rows with the arrow keys
  before they can say no.

### Added

- **A sound when a request arrives**, and a specific one rather than the
  terminal bell. Half of terminals have the bell off and the other half use it
  for tab completion, so a request announced by a bell is a request that times
  out unheard — and a timeout reads as a refusal nobody made. macOS plays its
  own sound, a Linux desktop uses whatever it has, Windows two short tones, and
  the web board synthesises the same two notes rather than fetching a file,
  because the page must work with the network unplugged. The bell is still rung
  alongside, since a terminal that badges its tab is doing exactly the job.

## v0.1.11

### Added

- **Approvals can be answered from the web board.** The same question appears in
  the terminal and on the board at once, and whichever is answered first wins —
  the other withdraws. devtun runs in a window you are not looking at, which is
  the whole premise; a board that could show you a secret being asked for and
  then send you elsewhere to say yes turned every approval into a race against
  its own timeout.

  This reverses a deliberate refusal, and the reasoning it reverses was: a page
  that can approve has to be right about tokens, origins, rebinding and replay
  at once. Three of those were already handled. Replay is answered in
  `internal/approval`: a request carries an unguessable id, spent on first use,
  and a choice is checked against the menu built for that one request. "Approve
  whatever is pending" is not an operation — between reading the board and
  clicking, the pending one may be a different question. `prompt: deny` still
  denies; the desk wraps outside the backend choice, so a session told to answer
  nothing does not become answerable by opening a browser tab.
- **A waiting approval is two red bands rather than a modal.** The request
  across the top, the answers across the bottom, and the port table and log
  still readable between them — because what the box is doing right now is
  often exactly what you want to see while deciding whether it may have a
  secret. Every answer is on screen, wrapped over as many rows as it takes: a
  security menu that shows one option and "5 of 9" is asking somebody to decide
  blind. The answers are numbered, and the numbers work.

### Fixed

- **A session no longer deletes a socket it does not own.** Two devtun sessions
  pointed at the same box share one socket path; the second takes it over,
  which is deliberate — but the first one's shutdown then ran an unconditional
  `rm -f` and deleted the *second's* socket. The survivor kept running, still
  reporting itself connected, while every `op` on the remote said there was no
  session at all. Shutdown now leaves alone a socket something is listening on.
- **A session notices when its socket is taken away.** The other half of the
  same failure: a reverse-forwarded socket can be removed with nothing on this
  side knowing, leaving a listener sshd will never route to again. That is the
  worst shape a failure can have — working, according to the thing that is
  broken. A check every thirty seconds ends the connection so the supervisor
  republishes it, and says so in the log.
- **No more colour emoji.** The security class was `🔒` and the SSH agent `🔑`,
  and they cost twice over: they rendered in the terminal's colour-emoji font,
  at a different weight and baseline from the `⇄` and `◱` beside them, which
  looked wrong on a monospace board — and they are two cells wide while width
  libraries report one, so every security line sat a column right of every
  other line. They are `❖` and `◈` now, every glyph is one cell, both renderers
  dropped the padding arithmetic that existed to work around the old ones, and
  a test fails on any emoji added anywhere in devtun.

## v0.1.10

### Fixed

- On a Linux desktop with no dialog program, the Config tab's approvals row
  listed three things to install and the ellipsis ate the last one. Commas
  instead of "or" buy the six columns that makes the difference. The test that
  should have caught it was itself measuring at a width where the help — which
  is by design the first thing a narrow terminal drops — could not fit, so it
  passed on macOS, where there is only ever one name to print, and failed on
  Linux.

## v0.1.9

### Added

- **The Tunnels tab is a board rather than a list.** A summary strip counting
  what is live, new, hidden and broken with total throughput; a scrollbar and an
  `n–m of N` count, because forwarding everything above 1024 makes thirty rows
  the normal case and nothing on screen said the list was cut; a bind error
  wrapped onto a second line instead of truncated to `listen tcp 12`, which is
  the one row where the text *is* the content; and a legend for `≠ ✕ + ● ◦ !` in
  the space under a short table, which is exactly when somebody new is looking.
  The scrollbar lives in the shared list renderer, so every tab has one.
- **Searching is fuzzy and ranked.** `vite` finds `node vite` and puts it above
  a port that merely sorts earlier. The Activity tab matches fuzzily but keeps
  time order — a scrollback reordered by score stops being a scrollback.

- **A command palette on `:`.** Every action devtun has, searchable by name,
  each showing the tab it lives on and the key that runs it. Choosing one
  switches to that tab first, so the row it acts on is in front of you rather
  than on a screen you never saw.

  The keyboard is about twenty-five keys deep across five tabs, and the same
  letter deliberately means different things on different ones — `r` is
  reverse-sort here and revoke there. That is fine for hands that know it and
  hostile to everyone else, and the honest answer to "the help is a wall of
  text" is not a shorter wall. Showing the key next to every entry is what makes
  the palette teach its own way out of a job.

  Each entry runs the tab's own key handler rather than reimplementing it, so
  the two cannot drift, and a test walks the tabs' handlers and fails on any key
  the catalogue has forgotten.

### Fixed

- **The bottom border's right-hand chip vanished at some widths.** The key bar
  sized its own budget to six cells of chrome while the border reserves eight —
  four for the corners and their edge segments, then two more around each
  label — so at eight widths between 60 and 140, including 77 and 88, the bar
  fitted its own budget, overran the border's, and the chip was dropped. That
  chip is where the scroll position and the Config tab's edit target live.

## v0.1.8

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

- **The web board's URL is good for exactly one use.** It is traded for a
  session cookie on the first request and is then dead, so the copy in your
  browser history — which auto-opening now puts there, and which the page's own
  address-bar tidy-up cannot reach — is not a way back in. The cookie is a
  *different* secret from the token, which is the part that matters: were it the
  same one, the token out of history would still work as a bearer credential and
  the one-shot would buy nothing. A second attempt on a spent link says so
  instead of failing with a bare 401.
- **The web board is worth leaving open.** Grants and rules are two panels
  rather than one list, each saying what kind of thing it holds — a grant is
  live and lapsing, with a countdown; a rule is written down until revoked. A
  rule from your config file says *edit your config file* rather than offering a
  button that would refuse. `show N hidden` brings hidden ports back, which the
  page had no way to do even though the endpoint existed. Losing the devtun
  process is now visible and clears itself when it comes back, and a reconnected
  event stream no longer silently duplicates every line it replays.
- **A Config tab** — `c`, or `5`. The settings that had no interface at all now
  have one: where approvals appear (`prompt:`), which services run on this host,
  the per-host and global `hide:` lists, and whether devtun offers to edit the
  remote shell rc.

  Every row says **which file its value came from** — `host`, `global`, or
  `default` — and `g` arms which level your edit lands in. A configuration
  screen for a tool with two levels of config that does not say which one you
  are looking at is one you cannot trust, and that provenance is most of the
  point.

  The approvals row reports what this machine can actually do: with no dialog
  program installed it names the ones it looked for, rather than offering a
  setting that will silently not work. Changing it takes effect immediately —
  somebody changing where approvals appear is somebody who is missing them, and
  "reconnect first" tells them to miss one more.

  The `c` popup it replaces is gone.
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
