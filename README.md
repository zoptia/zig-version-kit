# zig-version-kit (`zvk`)

Cross-platform installer for [Zig](https://ziglang.org/) — both stable releases
and the latest nightly, on macOS, Linux, and Windows. Single command,
idempotent, written in Zig itself.

```
zvk install                    # latest stable -> `zig` on PATH (auto-installs zls)
zvk install nightly            # latest master -> `zig-nightly` on PATH
zvk update all                 # refresh both channels
```

## Install

### macOS / Linux

```sh
curl -fsSL https://raw.githubusercontent.com/zoptia/zig-version-kit/main/install.sh | sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/zoptia/zig-version-kit/main/install.ps1 | iex
```

The installer downloads a small `zvk` binary from the latest GitHub Release,
copies it into `~/.zoptia/zig/bin/`, adds that directory to your PATH, and runs
`zvk install` to fetch the latest stable Zig. After that, `zig` and `zvk` are
both on your PATH.

## Quickstart: from zero to Claude Code LSP

End-to-end walkthrough on a fresh machine:

**1.** Run the installer (above). When it finishes you have `zig` 0.X.Y, `zls`
0.X.0, and `~/.zoptia/zig/claude-plugin/` on disk.

**2.** Tell Claude Code which Zig is active. Add this line to your
`~/.claude/CLAUDE.md` (create it if it doesn't exist):

```markdown
@~/.zoptia/zig/CLAUDE.md
```

**3.** Wire zls into Claude Code's LSP. Open Claude Code in any project and
run these two slash commands (one-time):

```
/plugin marketplace add ~/.zoptia/zig/claude-plugin
/plugin install zvk-zig@zvk
```

**4.** Open a `.zig` file in Claude Code. Ask Claude a semantic question, e.g.
"what's the signature of `std.fs.File.read` in the version we're using?" — it
should answer using the LSP `hover` tool against zls, not by grepping.

**5.** When Zig releases a new version, `zvk update` refreshes everything;
then in Claude Code run `/plugin marketplace update zvk` to pick up the new
plugin metadata.

## Default behavior is conservative

`zvk install` with no arguments installs the **latest stable release** and
exposes it as `zig`. Master nightly is opt-in:

```sh
zvk install nightly      # exposes nightly as `zig-nightly`
```

| Command       | Source                      | Channel  |
|---------------|-----------------------------|----------|
| `zig`         | latest stable on ziglang.org| release  |
| `zig-nightly` | master on ziglang.org       | nightly  |

Both can be installed simultaneously and updated independently.

## Commands

```
zvk install [release|nightly] [--no-zls]  Install Zig (default: release; release auto-installs zls)
zvk install zls                           Install/refresh zls matched to active release Zig
zvk update  [release|nightly|zls|all]     Re-run install for the given target(s)
zvk use <channel> <version>               Point a channel at an installed version
zvk uninstall <version>                   Remove an installed version
zvk list                                  List installed versions and channel state
zvk which [channel]                       Show active version for a channel
zvk status [--json]                       Print full state (text or JSON)
zvk lsp-config                            Print Claude Code .lsp.json snippet to stdout
zvk self-install                          Copy zvk to ~/.zoptia/zig/bin/ + setup PATH
zvk self-update [--dry-run|--force]       Replace zvk with the latest GitHub Release
zvk version
zvk help
```

## How it works

1. Reads <https://ziglang.org/download/index.json> for the latest version,
   tarball URL, and sha256.
2. Skips work if that version is already installed.
3. Otherwise downloads, verifies sha256, fetches `<tarball>.minisig` and
   verifies the Ed25519 signature against the Zig project's [official public key][zig-key],
   then extracts to `~/.zoptia/zig/versions/<version>/` — using `std.compress.xz`
   and `std.tar` from the Zig stdlib (no system `tar`, no `jq`, no `python`).
4. Maintains channel symlinks (`~/.zoptia/zig/channels/{release,nightly}`) and
   bin symlinks (`~/.zoptia/zig/bin/{zig,zig-nightly}`).
5. For the release channel, queries
   <https://api.github.com/repos/zigtools/zls/releases/latest> and installs zls
   if its tag's major.minor matches the just-installed Zig (soft-fails when zls
   hasn't caught up yet — a frequent few-day window after each Zig release).
   No `zls-nightly`: zls master tracks Zig master with a 1–3 day lag and a
   sometimes-broken LSP gives wrong answers worse than no LSP.
6. Generates per-channel REFERENCE.md and a Claude Code marketplace plugin
   under `~/.zoptia/zig/claude-plugin/` (see "Claude Code integration").
7. Adds `~/.zoptia/zig/bin` to PATH in your shell rc (`zsh` / `bash` / `fish`)
   idempotently.

[zig-key]: https://ziglang.org/download/

## Layout

```
~/.zoptia/zig/
├── bin/
│   ├── zvk                    # the manager itself
│   ├── zig          → ../channels/release/zig
│   ├── zig-nightly  → ../channels/nightly/zig
│   └── zls          → ../zls/0.16.0/zls       # release-matched zls
├── channels/
│   ├── release      → ../versions/0.16.0
│   └── nightly      → ../versions/0.17.0-dev.xxx+yyy
├── versions/
│   ├── 0.16.0/
│   └── 0.17.0-dev.xxx+yyy/
├── zls/
│   └── 0.16.0/zls
├── release/
│   └── REFERENCE.md           # release stdlib map + langref + zls notes
├── nightly/
│   └── REFERENCE.md           # nightly drift warnings + online sources
├── claude-plugin/             # Claude Code marketplace; install once, see below
└── CLAUDE.md                  # small index, points at the above; auto-generated
```

## Claude Code integration

`zvk` generates everything Claude Code needs to know which Zig and which LSP
to use, in two layers:

**Layer 1 — context files** (loaded into Claude's prompt). Add this line to
your `~/.claude/CLAUDE.md`:

```markdown
@~/.zoptia/zig/CLAUDE.md
```

`~/.zoptia/zig/CLAUDE.md` is a small index. It points at deeper per-channel
references (`<root>/release/REFERENCE.md`, `<root>/nightly/REFERENCE.md`)
that Claude reads on demand — those contain the stdlib topic map, langref
location, and (for nightly) the online sources to consult since std drifts
daily.

**Layer 2 — LSP plugin** (semantic queries inside Claude Code). After
`zvk install`, run these in Claude Code once:

```
/plugin marketplace add ~/.zoptia/zig/claude-plugin
/plugin install zvk-zig@zvk
```

This wires `zls` into Claude Code's LSP for `.zig` files, so hover,
goToDefinition, findReferences, etc. all work. After future `zvk update`,
refresh with `/plugin marketplace update zvk` (the plugin's `version`
field is auto-bumped to match the active Zig release).

`zvk lsp-config` prints the raw `.lsp.json` snippet to stdout if you'd
rather wire LSP into a project-level `.claude/` config manually.

Disable the auto-generated context files with `ZVK_NO_CLAUDE_MD=1`.

### Verifying LSP is connected

In a Claude Code session inside a Zig project, ask:

> What's the type of `b.allocator` in `std.Build`?

If LSP is wired up correctly, Claude calls the `LSP` tool (`hover` or
`goToDefinition` on `b.allocator`) and answers from zls. If LSP is *not*
connected, Claude falls back to grepping the local stdlib — both give
right answers, but only the first proves the plugin is live. You can also
check the plugin is registered with `/plugin list` in Claude Code.

### Troubleshooting

- **`/plugin marketplace add` says "not a valid marketplace"** — check that
  `~/.zoptia/zig/claude-plugin/.claude-plugin/marketplace.json` exists. If
  not, run `zvk install` again to regenerate.
- **`/plugin install` succeeds but Claude doesn't use LSP** — confirm
  `which zls` resolves (it should point at `~/.zoptia/zig/bin/zls`) and that
  `zls --version` runs. The plugin's `.lsp.json` calls bare `zls`, so it must
  be on PATH for Claude Code's spawned LSP process to find it.
- **Zig release just dropped, `zvk install` says "no zls match yet"** —
  expected. zls usually publishes a matching tag within a few days. Re-run
  `zvk install zls` then.
- **Want to undo everything** — `rm -rf ~/.zoptia/zig`, remove the line in
  your shell rc that ends in `# Added by zig-version-kit (zvk)`, and
  `/plugin uninstall zvk-zig` in Claude Code.

## Environment variables

| Var                    | Effect                                                      |
|------------------------|-------------------------------------------------------------|
| `ZVK_ROOT`             | Override install root (default: `~/.zoptia/zig`)            |
| `ZVK_NO_MODIFY_PATH`   | Skip writing to your shell rc                               |
| `ZVK_NO_CLAUDE_MD`     | Skip writing CLAUDE.md, REFERENCE.md, and the Claude Code plugin |
| `ZVK_NO_ZLS`           | Skip the auto zls install during `zvk install`              |
| `ZVK_NO_MINISIGN`      | Skip Ed25519 signature verification on tarballs (not recommended) |
| `ZVK_VERSION`          | Pin a `zvk` release tag in `install.sh` / `install.ps1`     |

## Build from source

Requires Zig 0.17.0-dev or newer.

```sh
git clone https://github.com/zoptia/zig-version-kit
cd zig-version-kit
zig build
./zig-out/bin/zvk self-install     # places it on PATH
zvk install                        # fetch latest stable Zig
```

## License

[MIT](LICENSE)
