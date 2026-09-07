# Changelog

Notable changes, newest first. Versions are [semver](https://semver.org); while
this is 0.x, a minor bump may break something.

## Unreleased

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
