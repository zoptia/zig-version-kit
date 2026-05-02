# zig-version-kit (`zvk`)

Cross-platform installer for [Zig](https://ziglang.org/) — both stable releases
and the latest nightly, on macOS, Linux, and Windows. Single command,
idempotent, written in Zig itself.

```
zvk install                    # latest stable -> `zig` on PATH
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
zvk install [release|nightly]            Install Zig (default: release)
zvk update  [release|nightly|all]        Re-run install for the given channel(s)
zvk use <channel> <version>              Point a channel at an installed version
zvk uninstall <version>                  Remove an installed version
zvk list                                 List installed versions and channel state
zvk which [channel]                      Show active version for a channel
zvk status [--json]                      Print full state (text or JSON)
zvk self-install                         Copy zvk to ~/.zoptia/zig/bin/ + setup PATH
zvk self-update [--dry-run|--force]      Replace zvk with the latest GitHub Release
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
5. Adds `~/.zoptia/zig/bin` to PATH in your shell rc (`zsh` / `bash` / `fish`)
   idempotently.

[zig-key]: https://ziglang.org/download/

## Layout

```
~/.zoptia/zig/
├── bin/
│   ├── zvk                    # the manager itself
│   ├── zig          → ../channels/release/zig
│   └── zig-nightly  → ../channels/nightly/zig
├── channels/
│   ├── release      → ../versions/0.16.0
│   └── nightly      → ../versions/0.17.0-dev.xxx+yyy
├── versions/
│   ├── 0.16.0/
│   └── 0.17.0-dev.xxx+yyy/
└── CLAUDE.md                  # auto-generated; see "Claude Code integration"
```

## Claude Code integration

After every `install` / `update` / `use` / `uninstall`, `zvk` writes a fresh
`~/.zoptia/zig/CLAUDE.md` describing the active versions and how to invoke
them. Add the following line to your `~/.claude/CLAUDE.md` to give Claude
Code automatic awareness of which Zig is active:

```markdown
@~/.zoptia/zig/CLAUDE.md
```

Disable with `ZVK_NO_CLAUDE_MD=1`.

## Environment variables

| Var                    | Effect                                                      |
|------------------------|-------------------------------------------------------------|
| `ZVK_ROOT`             | Override install root (default: `~/.zoptia/zig`)            |
| `ZVK_NO_MODIFY_PATH`   | Skip writing to your shell rc                               |
| `ZVK_NO_CLAUDE_MD`     | Skip writing `~/.zoptia/zig/CLAUDE.md`                      |
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
