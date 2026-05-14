const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");

const index_url = "https://ziglang.org/download/index.json";

pub const Channel = enum {
    nightly,
    release,

    pub fn fromString(s: []const u8) ?Channel {
        if (std.mem.eql(u8, s, "nightly")) return .nightly;
        if (std.mem.eql(u8, s, "release")) return .release;
        return null;
    }
};

/// PATH-exposed command name for each channel. `release` is the conservative default
/// and gets the unqualified `zig`; `nightly` is opt-in via `zig-nightly`.
pub fn binNameFor(channel: Channel) []const u8 {
    return switch (channel) {
        .release => "zig",
        .nightly => "zig-nightly",
    };
}

/// Default channel when the user runs commands without specifying one.
pub const default_channel: Channel = .release;
pub const default_channel_name: []const u8 = "release";

pub fn currentTarget() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => switch (builtin.os.tag) {
            .linux => "x86_64-linux",
            .macos => "x86_64-macos",
            .windows => "x86_64-windows",
            else => @compileError("unsupported os"),
        },
        .aarch64 => switch (builtin.os.tag) {
            .linux => "aarch64-linux",
            .macos => "aarch64-macos",
            .windows => "aarch64-windows",
            else => @compileError("unsupported os"),
        },
        else => @compileError("unsupported cpu arch"),
    };
}

pub fn defaultRoot(allocator: std.mem.Allocator, env: *std.process.Environ.Map) ![]u8 {
    if (env.get("ZVK_ROOT")) |r| return try allocator.dupe(u8, r);
    // POSIX uses HOME; Windows uses USERPROFILE. Check both so a single binary
    // works across platforms without the caller pre-setting HOME.
    const home = env.get("HOME") orelse env.get("USERPROFILE") orelse return error.NoHome;
    return try std.fs.path.join(allocator, &.{ home, ".zoptia", "zig" });
}

/// Filename of the zvk executable on the current platform.
inline fn zvkBinaryName() []const u8 {
    return if (builtin.os.tag == .windows) "zvk.exe" else "zvk";
}

/// One resolved entry from index.json — version + platform-specific tarball metadata.
/// All fields are owned by the supplied allocator.
pub const Entry = struct {
    version: []u8,
    tarball: []u8,
    shasum: []u8,

    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
        allocator.free(self.tarball);
        allocator.free(self.shasum);
    }
};

pub fn fetchIndex(allocator: std.mem.Allocator, io: Io) ![]u8 {
    return downloadToMemory(allocator, io, index_url);
}

/// Stream a URL response body into a heap buffer. Caller frees.
pub fn downloadToMemory(allocator: std.mem.Allocator, io: Io, url: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var body: Io.Writer.Allocating = .init(allocator);
    errdefer body.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body.writer,
    });

    if (result.status != .ok) return error.HttpFailure;

    return body.toOwnedSlice();
}

pub fn sha256Hex(data: []const u8) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return std.fmt.bytesToHex(out, .lower);
}

/// Zig project's official minisign public key, used to sign tarballs at
/// ziglang.org/download/ and ziglang.org/builds/. Source:
/// https://ziglang.org/download/
const zig_minisign_pubkey_b64 = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";

/// Verify a minisign signature against `file_data` using the supplied base64-encoded
/// public key. Supports both raw Ed25519 (`Ed`) and BLAKE2b-prehashed Ed25519 (`ED`)
/// — Zig nightly tarballs use the prehashed form.
///
/// Only the file signature (line 2) is verified; the global/trusted-comment signature
/// (line 4) is not checked in this v1 implementation.
pub fn verifyMinisign(
    file_data: []const u8,
    minisig_text: []const u8,
    pubkey_b64: []const u8,
) !void {
    const decoder = std.base64.standard.Decoder;
    const Ed25519 = std.crypto.sign.Ed25519;
    const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

    // Parse pubkey: 2-byte algo "Ed" + 8-byte key_id + 32-byte pubkey, base64-encoded.
    var pk_buf: [42]u8 = undefined;
    const pk_size = try decoder.calcSizeForSlice(pubkey_b64);
    if (pk_size != pk_buf.len) return error.InvalidPubkeyLength;
    try decoder.decode(&pk_buf, pubkey_b64);
    if (!std.mem.eql(u8, pk_buf[0..2], "Ed")) return error.UnsupportedPubkeyAlgo;
    const pk_key_id = pk_buf[2..10];
    const pk_bytes: [32]u8 = pk_buf[10..42].*;

    // Parse minisig text: line 2 is the signature (after stripping leading "untrusted comment:").
    var lines = std.mem.splitScalar(u8, minisig_text, '\n');
    _ = lines.next() orelse return error.MalformedMinisig; // untrusted comment
    const sig_b64 = lines.next() orelse return error.MalformedMinisig;

    var sig_buf: [74]u8 = undefined;
    const sig_size = try decoder.calcSizeForSlice(sig_b64);
    if (sig_size != sig_buf.len) return error.InvalidSignatureLength;
    try decoder.decode(&sig_buf, sig_b64);
    const sig_algo = sig_buf[0..2];
    const sig_key_id = sig_buf[2..10];
    const sig_bytes: [64]u8 = sig_buf[10..74].*;

    if (!std.mem.eql(u8, pk_key_id, sig_key_id)) return error.KeyIdMismatch;

    const pubkey = try Ed25519.PublicKey.fromBytes(pk_bytes);
    const sig = Ed25519.Signature.fromBytes(sig_bytes);

    if (std.mem.eql(u8, sig_algo, "ED")) {
        // Prehashed: BLAKE2b-512 of file, then verify Ed25519 over digest.
        var hasher = Blake2b512.init(.{});
        hasher.update(file_data);
        var digest: [64]u8 = undefined;
        hasher.final(&digest);
        try sig.verify(&digest, pubkey);
    } else if (std.mem.eql(u8, sig_algo, "Ed")) {
        try sig.verify(file_data, pubkey);
    } else {
        return error.UnsupportedSignatureAlgo;
    }
}

/// mkdir -p the parent directory of `abs_file`.
fn ensureParentDir(io: Io, abs_file: []const u8) !void {
    if (std.fs.path.dirname(abs_file)) |parent| {
        try std.Io.Dir.createDirPath(.cwd(), io, parent);
    }
}

pub fn writeFileAbs(io: Io, abs_path: []const u8, data: []const u8) !void {
    try ensureParentDir(io, abs_path);
    try std.Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = abs_path,
        .data = data,
    });
}

/// Returns true if `<dir>/zig` exists (treats the directory as a complete install).
fn isInstalled(io: Io, version_dir_abs: []const u8) bool {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const zig_path = std.fmt.bufPrint(&buf, "{s}/zig", .{version_dir_abs}) catch return false;
    std.Io.Dir.accessAbsolute(io, zig_path, .{}) catch return false;
    return true;
}

/// Extract a tar.xz tarball from memory into `dest_dir_abs`, stripping `strip_components` levels.
fn extractTarXz(
    gpa: std.mem.Allocator,
    io: Io,
    tarball: []const u8,
    dest_dir_abs: []const u8,
    strip_components: u32,
) !void {
    try std.Io.Dir.createDirPath(.cwd(), io, dest_dir_abs);
    var dir = try std.Io.Dir.openDirAbsolute(io, dest_dir_abs, .{});
    defer dir.close(io);

    var src_reader = std.Io.Reader.fixed(tarball);

    const decomp_buf = try gpa.alloc(u8, 1 << 16);
    var decomp = try std.compress.xz.Decompress.init(&src_reader, gpa, decomp_buf);
    defer decomp.deinit();

    try std.tar.extract(io, dir, &decomp.reader, .{ .strip_components = strip_components });
}

/// Idempotent symlink: deletes existing link at `link_abs` if any, then creates one pointing to `target`.
/// `target` is taken verbatim — usually a path relative to `link_abs`'s directory.
fn replaceSymlink(io: Io, target: []const u8, link_abs: []const u8) !void {
    std.Io.Dir.deleteFile(.cwd(), io, link_abs) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try std.Io.Dir.symLink(.cwd(), io, target, link_abs, .{});
}

/// Snapshot of the current Zig environment, used by both `zvk status` and the
/// auto-generated `~/.zoptia/zig/CLAUDE.md`.
pub const Status = struct {
    install_root: []const u8,
    bin_dir: []const u8,
    zvk_path: []const u8,
    release: ?ChannelEntry,
    nightly: ?ChannelEntry,
    installed: []const []const u8,

    pub const ChannelEntry = struct {
        version: []const u8,
        bin_command: []const u8,
        bin_path: []const u8,
    };
};

pub fn collectStatus(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map) !Status {
    const root = try defaultRoot(arena, env);
    const bin_dir = try std.fs.path.join(arena, &.{ root, "bin" });
    const zvk_path = try std.fs.path.join(arena, &.{ bin_dir, zvkBinaryName() });

    return .{
        .install_root = root,
        .bin_dir = bin_dir,
        .zvk_path = zvk_path,
        .release = try resolveChannelEntry(arena, io, root, .release),
        .nightly = try resolveChannelEntry(arena, io, root, .nightly),
        .installed = try listInstalledVersions(arena, io, root),
    };
}

fn resolveChannelEntry(arena: std.mem.Allocator, io: Io, root: []const u8, channel: Channel) !?Status.ChannelEntry {
    const ver = (try readActiveVersion(arena, io, root, channel)) orelse return null;
    const cmd = binNameFor(channel);
    const path = try std.fs.path.join(arena, &.{ root, "bin", cmd });
    return .{ .version = ver, .bin_command = cmd, .bin_path = path };
}

fn listInstalledVersions(arena: std.mem.Allocator, io: Io, root: []const u8) ![]const []const u8 {
    const versions_dir = try std.fs.path.join(arena, &.{ root, "versions" });
    var dir = std.Io.Dir.openDirAbsolute(io, versions_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer dir.close(io);

    var list: std.ArrayList([]const u8) = .empty;
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        try list.append(arena, try arena.dupe(u8, entry.name));
    }
    return list.toOwnedSlice(arena);
}

pub fn runStatus(
    arena: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    args: []const []const u8,
    stdout: *Io.Writer,
) !void {
    const json_mode = args.len > 0 and (std.mem.eql(u8, args[0], "--json") or std.mem.eql(u8, args[0], "-j"));
    const status = try collectStatus(arena, io, env);
    if (json_mode) {
        try printStatusJson(status, stdout);
    } else {
        try printStatusText(status, stdout);
    }
}

fn printStatusText(s: Status, w: *Io.Writer) !void {
    try w.print("Active Zig versions:\n", .{});
    if (s.release) |r| {
        try w.print("  {s:<13}  {s:<32}  (release, the default)\n", .{ r.bin_command, r.version });
    } else {
        try w.print("  {s:<13}  (not installed)                   (release, the default)\n", .{"zig"});
    }
    if (s.nightly) |n| {
        try w.print("  {s:<13}  {s:<32}  (nightly, opt-in)\n", .{ n.bin_command, n.version });
    } else {
        try w.print("  {s:<13}  (not installed)                   (nightly, opt-in)\n", .{"zig-nightly"});
    }
    try w.print("\nInstall root: {s}\n", .{s.install_root});
    try w.print("zvk binary:   {s}\n", .{s.zvk_path});
    try w.print("\nInstalled versions ({d}):\n", .{s.installed.len});
    if (s.installed.len == 0) {
        try w.print("  (none)\n", .{});
    } else {
        for (s.installed) |v| try w.print("  {s}\n", .{v});
    }
    try w.print(
        \\
        \\Claude Code: add `@{s}/CLAUDE.md` to your `~/.claude/CLAUDE.md`
        \\to give Claude Code context on which Zig versions are active.
        \\
    , .{s.install_root});
}

fn printStatusJson(s: Status, w: *Io.Writer) !void {
    try w.print(
        \\{{
        \\  "zvk_version": "{s}",
        \\  "install_root": "{s}",
        \\  "bin_dir": "{s}",
        \\  "zvk_path": "{s}",
        \\  "default_channel": "{s}",
        \\
    , .{ zvk_version, s.install_root, s.bin_dir, s.zvk_path, @tagName(default_channel) });

    try w.print("  \"channels\": {{\n", .{});
    try printChannelJson(w, "release", s.release, true);
    try printChannelJson(w, "nightly", s.nightly, false);
    try w.print("  }},\n", .{});

    try w.print("  \"installed_versions\": [", .{});
    for (s.installed, 0..) |v, i| {
        if (i > 0) try w.print(", ", .{});
        try w.print("\"{s}\"", .{v});
    }
    try w.print("]\n}}\n", .{});
}

fn printChannelJson(w: *Io.Writer, name: []const u8, entry: ?Status.ChannelEntry, has_more: bool) !void {
    const tail: []const u8 = if (has_more) "," else "";
    if (entry) |e| {
        try w.print(
            "    \"{s}\": {{ \"version\": \"{s}\", \"command\": \"{s}\", \"path\": \"{s}\" }}{s}\n",
            .{ name, e.version, e.bin_command, e.bin_path, tail },
        );
    } else {
        try w.print("    \"{s}\": null{s}\n", .{ name, tail });
    }
}

/// Auto-write `<install_root>/CLAUDE.md` reflecting the current state. Called after
/// install / use / uninstall. Users who add `@~/.zoptia/zig/CLAUDE.md` to their global
/// Claude Code config get current-state context on every session.
///
/// The file is intentionally small — it's loaded into Claude's context on every
/// session, so deeper content goes into per-channel `<channel>/REFERENCE.md`
/// files that Claude reads on demand.
pub fn writeStatusClaudeMd(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map) !void {
    if (env.get("ZVK_NO_CLAUDE_MD")) |_| return;

    const status = try collectStatus(arena, io, env);
    try std.Io.Dir.createDirPath(.cwd(), io, status.install_root);

    const md_path = try std.fs.path.join(arena, &.{ status.install_root, "CLAUDE.md" });
    var file = try std.Io.Dir.createFile(.cwd(), io, md_path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw: Io.File.Writer = .init(file, io, &buf);
    const w = &fw.interface;

    try w.writeAll(
        \\# Zig environment (managed by zvk)
        \\
        \\Auto-generated. Do not edit — overwritten on next `zvk` command.
        \\Disable with `ZVK_NO_CLAUDE_MD=1`.
        \\
        \\## Which command to invoke
        \\
        \\| Command         | Version                                  | Channel  |
        \\|-----------------|------------------------------------------|----------|
        \\
    );
    try renderChannelRow(w, status.release, "release", "(not installed)");
    try renderChannelRow(w, status.nightly, "nightly", "(not installed)");

    try w.writeAll(
        \\
        \\**Decision rule for a project**: read its `build.zig.zon`'s
        \\`minimum_zig_version`. If that value is ≤ the `zig` row above, use
        \\bare `zig`. If higher (typically a `0.X.Y-dev.NNN+HASH` string), use
        \\`zig-nightly`.
        \\
        \\## Deeper references (read on demand)
        \\
        \\
    );
    try w.print("- Release stdlib + langref + zls notes: `{s}/release/REFERENCE.md`\n", .{status.install_root});
    try w.print("- Nightly stdlib + drift warnings + online sources: `{s}/nightly/REFERENCE.md`\n", .{status.install_root});

    try w.writeAll(
        \\
        \\## Inspect / change state
        \\
        \\- `zvk status` — current channel mappings, installed versions, bin paths
        \\- `zvk use <channel> <version>` — repoint a channel at an installed version
        \\- `zvk update [release|nightly|zls|all]` — refresh
        \\
    );

    try w.print("\nInstall root: `{s}`\n", .{status.install_root});

    try w.flush();
}

/// Write `<install_root>/<channel>/REFERENCE.md` — the per-channel deep guide.
/// Skipped when ZVK_NO_CLAUDE_MD is set.
pub fn writeChannelReference(
    arena: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    channel: Channel,
    version: []const u8,
) !void {
    if (env.get("ZVK_NO_CLAUDE_MD")) |_| return;

    const root = try defaultRoot(arena, env);
    const ch_dir = try std.fs.path.join(arena, &.{ root, @tagName(channel) });
    try std.Io.Dir.createDirPath(.cwd(), io, ch_dir);

    const md_path = try std.fs.path.join(arena, &.{ ch_dir, "REFERENCE.md" });
    var file = try std.Io.Dir.createFile(.cwd(), io, md_path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw: Io.File.Writer = .init(file, io, &buf);
    const w = &fw.interface;

    const ver_dir = try std.fs.path.join(arena, &.{ root, "versions", version });
    const cmd = binNameFor(channel);

    try w.print("# `{s}` — {s} {s}\n\nAuto-generated. Do not edit.\n\n", .{ cmd, @tagName(channel), version });

    switch (channel) {
        .release => {
            try w.writeAll(
                \\## When to use
                \\
                \\Use this when a project's `build.zig.zon` `minimum_zig_version`
                \\is ≤ the version above. API is frozen for this Zig release —
                \\online docs and the local stdlib agree.
                \\
                \\## Local references (authoritative for this build)
                \\
                \\
            );
            try w.print("- Compiler: `{s}/zig`\n", .{ver_dir});
            try w.print("- Language reference: `{s}/doc/langref.html`\n", .{ver_dir});
            try w.print("- stdlib source root: `{s}/lib/std/`\n", .{ver_dir});
            try writeStdlibTopicMap(w, ver_dir);
            try w.print("\n## Online references\n\n", .{});
            try w.print("- Frozen std docs: https://ziglang.org/documentation/{s}/std/\n", .{version});
            try w.print("- Language ref: https://ziglang.org/documentation/{s}/\n", .{version});

            try w.writeAll(
                \\
                \\## Language server (zls)
                \\
                \\zls for this Zig release is installed alongside (`~/.zoptia/zig/bin/zls`).
                \\When Claude Code's LSP plugin is enabled (see `<root>/claude-plugin/`),
                \\semantic queries (hover, goToDefinition, findReferences) use zls and
                \\should be preferred over reading source for type-level questions.
                \\
            );
        },
        .nightly => {
            try w.writeAll(
                \\## When to use
                \\
                \\Use this when a project's `build.zig.zon` `minimum_zig_version`
                \\is a `0.X.Y-dev.NNN+HASH` string higher than the release above.
                \\
                \\## ⚠ std drifts daily
                \\
                \\Nightly std API changes between rebuilds — names, signatures, and
                \\modules are reorganized without notice. The **local** stdlib is the
                \\only source guaranteed to match the compiler being invoked. Online
                \\docs may already be ahead of (or behind) this exact build.
                \\
                \\## Local references (authoritative for this build)
                \\
                \\
            );
            try w.print("- Compiler: `{s}/zig`\n", .{ver_dir});
            try w.print("- Language reference: `{s}/doc/langref.html`\n", .{ver_dir});
            try w.print("- stdlib source root: `{s}/lib/std/`\n", .{ver_dir});
            try writeStdlibTopicMap(w, ver_dir);

            try w.writeAll(
                \\
                \\## Online references (may be ahead of this local build)
                \\
                \\- Master std docs: https://ziglang.org/documentation/master/std/
                \\- Draft 0.17 release notes (running log of breaking changes):
                \\  https://ziglang.org/download/0.17.0/release-notes.html
                \\- Recent std commits (use to diagnose "broke since last update"):
                \\  https://github.com/ziglang/zig/commits/master/lib/std
                \\- Source on GitHub: https://github.com/ziglang/zig/tree/master/lib/std
                \\
                \\## Known volatile areas (as of project bootstrap)
                \\
                \\- `std.Io` — Reader/Writer, File, Dir all reorganized
                \\- `std.process` — `Init` parameter, Environ.Map
                \\- Build system — `b.createModule`, root_module field
                \\- HTTP client — moved under `std.Io`
                \\
                \\## Why no zls here
                \\
                \\zls master tracks Zig master with a 1–3 day lag and breaks during
                \\upstream std refactors. We don't install a `zls-nightly` because a
                \\sometimes-broken LSP gives wrong answers worse than no LSP. Grep
                \\the local `lib/std/` directly, or check the online sources above.
                \\
            );
        },
    }

    try w.flush();
}

fn writeStdlibTopicMap(w: *Io.Writer, ver_dir: []const u8) !void {
    try w.writeAll("\n## stdlib topic map (grep starting points)\n\n");
    try w.print("- I/O           → `{s}/lib/std/Io.zig`, `{s}/lib/std/Io/`\n", .{ ver_dir, ver_dir });
    try w.print("- Filesystem    → `{s}/lib/std/fs.zig`, `{s}/lib/std/fs/`\n", .{ ver_dir, ver_dir });
    try w.print("- HTTP          → `{s}/lib/std/http.zig`, `{s}/lib/std/http/`\n", .{ ver_dir, ver_dir });
    try w.print("- Process / env → `{s}/lib/std/process.zig`\n", .{ver_dir});
    try w.print("- Build system  → `{s}/lib/std/Build.zig`, `{s}/lib/std/Build/`\n", .{ ver_dir, ver_dir });
    try w.print("- Crypto        → `{s}/lib/std/crypto/`\n", .{ver_dir});
    try w.print("- Compression   → `{s}/lib/std/compress/`, `{s}/lib/std/tar.zig`\n", .{ ver_dir, ver_dir });
    try w.print("- JSON          → `{s}/lib/std/json/`\n", .{ver_dir});
    try w.print("- Formatting    → `{s}/lib/std/fmt.zig`\n", .{ver_dir});
    try w.print("- Containers    → `{s}/lib/std/array_list.zig`, `{s}/lib/std/hash_map.zig`\n", .{ ver_dir, ver_dir });
    try w.print("- Allocators    → `{s}/lib/std/heap/`, `{s}/lib/std/mem/Allocator.zig`\n", .{ ver_dir, ver_dir });
    try w.print("- Threading     → `{s}/lib/std/Thread/`\n", .{ver_dir});
}

/// Generate the Claude Code marketplace plugin under `<root>/claude-plugin/`.
/// Layout matches the documented schema:
///
///     claude-plugin/
///     ├── .claude-plugin/marketplace.json
///     └── zvk-zig/
///         ├── .claude-plugin/plugin.json   (version = current zig release)
///         └── .lsp.json                    (zls server)
///
/// Bumping `version` in plugin.json on each install signals "update available"
/// to Claude Code's `/plugin marketplace update zvk-zig` flow.
pub fn writeClaudePlugin(
    arena: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    zig_release_version: []const u8,
) !void {
    if (env.get("ZVK_NO_CLAUDE_MD")) |_| return;

    const root = try defaultRoot(arena, env);
    const plugin_root = try std.fs.path.join(arena, &.{ root, "claude-plugin" });
    const market_dir = try std.fs.path.join(arena, &.{ plugin_root, ".claude-plugin" });
    const plugin_dir = try std.fs.path.join(arena, &.{ plugin_root, "zvk-zig" });
    const plugin_meta_dir = try std.fs.path.join(arena, &.{ plugin_dir, ".claude-plugin" });

    try std.Io.Dir.createDirPath(.cwd(), io, market_dir);
    try std.Io.Dir.createDirPath(.cwd(), io, plugin_meta_dir);

    const market_path = try std.fs.path.join(arena, &.{ market_dir, "marketplace.json" });
    const market_json =
        \\{
        \\  "name": "zvk",
        \\  "owner": { "name": "Zoptia" },
        \\  "description": "Zig toolchain integration for Claude Code, generated by zvk",
        \\  "plugins": [
        \\    {
        \\      "name": "zvk-zig",
        \\      "source": "./zvk-zig",
        \\      "description": "Zig LSP via zls (matched to the active release Zig)"
        \\    }
        \\  ]
        \\}
        \\
    ;
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = market_path, .data = market_json });

    const plugin_json_path = try std.fs.path.join(arena, &.{ plugin_meta_dir, "plugin.json" });
    const plugin_json = try std.fmt.allocPrint(
        arena,
        \\{{
        \\  "name": "zvk-zig",
        \\  "description": "Zig LSP via zls (matched to the active release Zig)",
        \\  "version": "{s}"
        \\}}
        \\
    ,
        .{zig_release_version},
    );
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = plugin_json_path, .data = plugin_json });

    const lsp_path = try std.fs.path.join(arena, &.{ plugin_dir, ".lsp.json" });
    const lsp_json =
        \\{
        \\  "zls": {
        \\    "command": "zls",
        \\    "extensionToLanguage": {
        \\      ".zig": "zig"
        \\    }
        \\  }
        \\}
        \\
    ;
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = lsp_path, .data = lsp_json });
}

/// Print a one-shot integration hint after install/update. Idempotent — the
/// commands shown are safe to run again. Skipped when ZVK_NO_CLAUDE_MD is set.
fn printIntegrationHint(
    arena: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    channel: Channel,
    stdout: *Io.Writer,
) !void {
    if (env.get("ZVK_NO_CLAUDE_MD")) |_| return;
    if (channel != .release) return;

    const root = try defaultRoot(arena, env);
    const plugin_path = try std.fs.path.join(arena, &.{ root, "claude-plugin" });
    // Verify the plugin actually exists before advertising it. (writeClaudePlugin
    // should have created it, but if ZVK_NO_CLAUDE_MD was set, skip the hint.)
    std.Io.Dir.accessAbsolute(io, plugin_path, .{}) catch return;

    try stdout.print(
        \\
        \\[zvk] Claude Code integration generated at: {s}
        \\      To enable LSP in Claude Code (one-time):
        \\          /plugin marketplace add {s}
        \\          /plugin install zvk-zig@zvk
        \\      After future `zvk update`, refresh with:
        \\          /plugin marketplace update zvk
        \\
    , .{ plugin_path, plugin_path });
}

fn renderChannelRow(w: *Io.Writer, entry: ?Status.ChannelEntry, channel_name: []const u8, missing_label: []const u8) !void {
    const cmd = if (entry) |e| e.bin_command else binNameForLabel(channel_name);
    const ver = if (entry) |e| e.version else missing_label;
    var cell_buf: [32]u8 = undefined;
    const cell = try std.fmt.bufPrint(&cell_buf, "`{s}`", .{cmd});
    try w.print("| {s:<15} | {s:<40} | {s:<8} |\n", .{ cell, ver, channel_name });
}

fn binNameForLabel(channel_name: []const u8) []const u8 {
    if (std.mem.eql(u8, channel_name, "release")) return "zig";
    if (std.mem.eql(u8, channel_name, "nightly")) return "zig-nightly";
    return channel_name;
}

/// Read the channel symlink and return the active version (the basename of its target),
/// or null if the channel is not set. Result is owned by `arena`.
pub fn readActiveVersion(arena: std.mem.Allocator, io: Io, root: []const u8, channel: Channel) !?[]const u8 {
    const link_path = try std.fs.path.join(arena, &.{ root, "channels", @tagName(channel) });
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.readLinkAbsolute(io, link_path, &buf) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const target = buf[0..n];
    return try arena.dupe(u8, std.fs.path.basename(target));
}

pub fn runList(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map, stdout: *Io.Writer) !void {
    const root = try defaultRoot(arena, env);

    try stdout.print("Channels:\n", .{});
    inline for (.{ Channel.nightly, Channel.release }) |ch| {
        const name = @tagName(ch);
        if (try readActiveVersion(arena, io, root, ch)) |ver| {
            try stdout.print("  {s:<8} -> {s}\n", .{ name, ver });
        } else {
            try stdout.print("  {s:<8} (not set)\n", .{name});
        }
    }

    try stdout.print("\nInstalled versions:\n", .{});
    const versions_dir = try std.fs.path.join(arena, &.{ root, "versions" });
    var dir = std.Io.Dir.openDirAbsolute(io, versions_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try stdout.print("  (none)\n", .{});
            return;
        },
        else => return err,
    };
    defer dir.close(io);

    var iter = dir.iterate();
    var any = false;
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        try stdout.print("  {s}\n", .{entry.name});
        any = true;
    }
    if (!any) try stdout.print("  (none)\n", .{});
}

/// Hardcoded zvk version. Must match `version` in build.zig.zon and used by
/// `zvk version` and `zvk self-update`.
pub const zvk_version = "0.0.4";

/// Latest-release API URL for self-update.
const release_api_url = "https://api.github.com/repos/zoptia/zig-version-kit/releases/latest";

fn currentAssetName(arena: std.mem.Allocator) ![]const u8 {
    const arch: []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
        else => return error.UnsupportedArch,
    };
    return switch (builtin.os.tag) {
        .linux => std.fmt.allocPrint(arena, "zvk-{s}-linux-musl", .{arch}),
        .macos => std.fmt.allocPrint(arena, "zvk-{s}-macos", .{arch}),
        .windows => std.fmt.allocPrint(arena, "zvk-{s}-windows-gnu.exe", .{arch}),
        else => error.UnsupportedOS,
    };
}

/// Download the latest zvk binary from GitHub Releases and atomically replace
/// `<install_root>/bin/zvk`. Safe to run while zvk is itself running on POSIX
/// (rename is atomic; the running process keeps its inode reference).
pub fn runSelfUpdate(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    args: []const []const u8,
    stdout: *Io.Writer,
) !void {
    var dry_run = false;
    var force = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--dry-run")) dry_run = true;
        if (std.mem.eql(u8, a, "--force") or std.mem.eql(u8, a, "-f")) force = true;
    }

    const root = try defaultRoot(arena, env);
    const bin_dir = try std.fs.path.join(arena, &.{ root, "bin" });
    const target = try std.fs.path.join(arena, &.{ bin_dir, zvkBinaryName() });

    try stdout.print("[zvk] querying {s}\n", .{release_api_url});
    try stdout.flush();

    const json_text = try downloadToMemory(gpa, io, release_api_url);
    defer gpa.free(json_text);

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, json_text, .{});
    defer parsed.deinit();

    const tag_val = parsed.value.object.get("tag_name") orelse return error.NoTagInResponse;
    const latest = std.mem.trimStart(u8, tag_val.string, "v");

    try stdout.print("[zvk] current: {s}, latest: {s}\n", .{ zvk_version, latest });
    try stdout.flush();

    if (!force and std.mem.eql(u8, latest, zvk_version)) {
        try stdout.print("[zvk] already at latest version\n", .{});
        return;
    }

    const asset_name = try currentAssetName(arena);
    const assets_val = parsed.value.object.get("assets") orelse return error.NoAssetsInResponse;

    var dl_url: ?[]const u8 = null;
    for (assets_val.array.items) |a| {
        const name_val = a.object.get("name") orelse continue;
        if (std.mem.eql(u8, name_val.string, asset_name)) {
            const url_val = a.object.get("browser_download_url") orelse continue;
            dl_url = try arena.dupe(u8, url_val.string);
            break;
        }
    }
    const url = dl_url orelse {
        try stdout.print("[zvk] no asset matching '{s}' in release {s}\n", .{ asset_name, latest });
        return error.NoMatchingAsset;
    };

    if (dry_run) {
        try stdout.print("[zvk] dry-run: would download {s}\n", .{url});
        try stdout.print("[zvk] dry-run: would atomically replace {s}\n", .{target});
        return;
    }

    try stdout.print("[zvk] downloading {s}\n", .{url});
    try stdout.flush();
    const data = try downloadToMemory(gpa, io, url);
    defer gpa.free(data);
    try stdout.print("[zvk] downloaded {d} bytes\n", .{data.len});
    try stdout.flush();

    // Atomic replace via createFileAtomic (writes to a tmp neighbor, then renames over).
    try std.Io.Dir.createDirPath(.cwd(), io, bin_dir);
    var atomic = try std.Io.Dir.createFileAtomic(.cwd(), io, target, .{
        .permissions = .executable_file,
        .make_path = true,
        .replace = true,
    });
    defer atomic.deinit(io);

    var write_buf: [64 * 1024]u8 = undefined;
    var fw = atomic.file.writer(io, &write_buf);
    try fw.interface.writeAll(data);
    try fw.interface.flush();
    try atomic.replace(io);

    try stdout.print("[zvk] updated {s}: {s} -> {s}\n", .{ target, zvk_version, latest });
}

/// Copy the currently-running zvk binary into `<root>/bin/zvk` and ensure PATH is set.
pub fn runSelfInstall(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    stdout: *Io.Writer,
) !void {
    const current_exe = try std.process.executablePathAlloc(io, arena);
    const root = try defaultRoot(arena, env);
    const bin_dir = try std.fs.path.join(arena, &.{ root, "bin" });
    const target = try std.fs.path.join(arena, &.{ bin_dir, zvkBinaryName() });

    if (std.mem.eql(u8, current_exe, target)) {
        try stdout.print("[zvk] already installed at {s}\n", .{target});
    } else {
        try std.Io.Dir.createDirPath(.cwd(), io, bin_dir);
        try std.Io.Dir.copyFileAbsolute(current_exe, target, io, .{});
        try stdout.print("[zvk] installed to {s}\n", .{target});
    }

    try setupPath(arena, gpa, io, env, bin_dir, stdout);
    try stdout.print("[zvk] done\n", .{});
}

pub fn runUse(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map, args: []const []const u8, stdout: *Io.Writer) !void {
    if (args.len < 2) {
        try stdout.print("usage: zvk use <channel> <version>\n", .{});
        try stdout.flush();
        std.process.exit(2);
    }
    const channel = Channel.fromString(args[0]) orelse {
        try stdout.print("zvk: unknown channel '{s}' (expected 'nightly' or 'release')\n", .{args[0]});
        try stdout.flush();
        std.process.exit(2);
    };
    const version = args[1];

    const root = try defaultRoot(arena, env);
    const version_dir = try std.fs.path.join(arena, &.{ root, "versions", version });

    if (!isInstalled(io, version_dir)) {
        try stdout.print(
            "zvk: version '{s}' is not installed (run: zvk install {s})\n",
            .{ version, version },
        );
        try stdout.flush();
        std.process.exit(1);
    }

    const channel_link = try std.fs.path.join(arena, &.{ root, "channels", @tagName(channel) });
    const target = try std.fs.path.join(arena, &.{ "..", "versions", version });
    try std.Io.Dir.createDirPath(.cwd(), io, try std.fs.path.join(arena, &.{ root, "channels" }));
    try replaceSymlink(io, target, channel_link);
    try writeStatusClaudeMd(arena, io, env);

    try stdout.print("channel '{s}' -> {s}\n", .{ @tagName(channel), version });
}

pub fn runUninstall(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map, args: []const []const u8, stdout: *Io.Writer) !void {
    if (args.len < 1) {
        try stdout.print("usage: zvk uninstall <version>\n", .{});
        try stdout.flush();
        std.process.exit(2);
    }
    const version = args[0];

    const root = try defaultRoot(arena, env);
    const version_dir = try std.fs.path.join(arena, &.{ root, "versions", version });

    if (!isInstalled(io, version_dir)) {
        try stdout.print("zvk: version '{s}' is not installed\n", .{version});
        try stdout.flush();
        std.process.exit(1);
    }

    // Refuse if any channel currently points at this version.
    inline for (.{ Channel.nightly, Channel.release }) |ch| {
        if (try readActiveVersion(arena, io, root, ch)) |active| {
            if (std.mem.eql(u8, active, version)) {
                try stdout.print(
                    "zvk: '{s}' is the active version for channel '{s}'; switch first with `zvk use {s} <other>`\n",
                    .{ version, @tagName(ch), @tagName(ch) },
                );
                try stdout.flush();
                std.process.exit(1);
            }
        }
    }

    try std.Io.Dir.deleteTree(.cwd(), io, version_dir);
    try writeStatusClaudeMd(arena, io, env);
    try stdout.print("removed {s}\n", .{version});
}

/// `update` is essentially `install` for the requested channel(s).
/// Accepts "nightly", "release", "zls", or "all".
pub fn runUpdate(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    args: []const []const u8,
    stdout: *Io.Writer,
) !void {
    var target_arg: []const u8 = default_channel_name;
    for (args) |a| {
        if (!std.mem.startsWith(u8, a, "--")) {
            target_arg = a;
            break;
        }
    }
    if (std.mem.eql(u8, target_arg, "zls")) {
        try runUpdateZls(arena, gpa, io, env, stdout);
        return;
    }
    if (std.mem.eql(u8, target_arg, "all")) {
        try run(arena, gpa, io, env, &.{"release"}, stdout);
        try run(arena, gpa, io, env, &.{"nightly"}, stdout);
        return;
    }
    try run(arena, gpa, io, env, args, stdout);
}

pub fn runWhich(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map, args: []const []const u8, stdout: *Io.Writer) !void {
    const channel_arg: []const u8 = if (args.len > 0) args[0] else default_channel_name;
    const channel = Channel.fromString(channel_arg) orelse {
        try stdout.print("zvk: unknown channel '{s}' (expected 'nightly' or 'release')\n", .{channel_arg});
        try stdout.flush();
        std.process.exit(2);
    };

    const root = try defaultRoot(arena, env);
    const ver = (try readActiveVersion(arena, io, root, channel)) orelse {
        try stdout.print("{s}: (not installed)\n", .{@tagName(channel)});
        return;
    };

    const bin_path = try std.fs.path.join(arena, &.{ root, "bin", binNameFor(channel) });

    try stdout.print("{s}: {s}\n  {s}\n", .{ @tagName(channel), ver, bin_path });
}

/// Append `~/.zoptia/zig/bin` to the user's shell rc, idempotently.
/// Returns true if a new line was written, false if PATH was already configured (or unsupported shell).
fn setupPath(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    bin_dir: []const u8,
    stdout: *Io.Writer,
) !void {
    if (env.get("ZVK_NO_MODIFY_PATH")) |_| return;

    // Windows PATH is managed by install.ps1 (via [Environment]::SetEnvironmentVariable
    // with User scope). Don't try to write POSIX-style export lines into a Unix rc file
    // that doesn't exist on Windows.
    if (builtin.os.tag == .windows) {
        try stdout.print("[zvk] on Windows; PATH should be configured by install.ps1\n", .{});
        return;
    }

    const home = env.get("HOME") orelse return;
    const shell = env.get("SHELL") orelse {
        try stdout.print("[zvk] SHELL not set; add to PATH manually:\n  export PATH=\"{s}:$PATH\"\n", .{bin_dir});
        return;
    };
    const shell_name = std.fs.path.basename(shell);

    const RcKind = enum { posix, fish };
    var rc_path: []const u8 = undefined;
    var line: []const u8 = undefined;
    var kind: RcKind = .posix;

    if (std.mem.eql(u8, shell_name, "fish")) {
        rc_path = try std.fs.path.join(arena, &.{ home, ".config", "fish", "conf.d", "zvk.fish" });
        line = try std.fmt.allocPrint(arena, "set -gx PATH \"{s}\" $PATH\n", .{bin_dir});
        kind = .fish;
    } else if (std.mem.eql(u8, shell_name, "bash")) {
        const filename: []const u8 = if (builtin.os.tag == .macos) ".bash_profile" else ".bashrc";
        rc_path = try std.fs.path.join(arena, &.{ home, filename });
        line = try std.fmt.allocPrint(arena, "export PATH=\"{s}:$PATH\"\n", .{bin_dir});
    } else if (std.mem.eql(u8, shell_name, "zsh")) {
        rc_path = try std.fs.path.join(arena, &.{ home, ".zshrc" });
        line = try std.fmt.allocPrint(arena, "export PATH=\"{s}:$PATH\"\n", .{bin_dir});
    } else {
        try stdout.print("[zvk] shell '{s}' not auto-configured; add to PATH manually:\n  export PATH=\"{s}:$PATH\"\n", .{ shell_name, bin_dir });
        return;
    }

    // Read existing rc (if any) and check whether bin_dir is already mentioned.
    const existing: []u8 = std.Io.Dir.readFileAlloc(.cwd(), io, rc_path, gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => @constCast(""),
        else => return err,
    };
    const existing_owned = existing.len > 0;
    defer if (existing_owned) gpa.free(existing);

    if (std.mem.indexOf(u8, existing, bin_dir) != null) {
        try stdout.print("[zvk] PATH already configured in {s}\n", .{rc_path});
        return;
    }

    // Build the new content: existing + marker comment + export line.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, existing);
    if (existing.len > 0 and existing[existing.len - 1] != '\n') try buf.append(gpa, '\n');
    try buf.appendSlice(gpa, "\n# Added by zig-version-kit (zvk)\n");
    try buf.appendSlice(gpa, line);

    try ensureParentDir(io, rc_path);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = rc_path, .data = buf.items });

    try stdout.print("[zvk] added {s} to PATH in {s}\n", .{ bin_dir, rc_path });
    try stdout.print("[zvk] restart your shell or run: exec $SHELL -l\n", .{});
}

pub fn resolveEntry(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    channel: Channel,
    target: []const u8,
) !Entry {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;

    const key: []const u8 = switch (channel) {
        .nightly => "master",
        .release => blk: {
            var best: ?[]const u8 = null;
            var best_parts: [3]u32 = .{ 0, 0, 0 };
            var it = obj.iterator();
            while (it.next()) |entry| {
                if (std.mem.eql(u8, entry.key_ptr.*, "master")) continue;
                const parts = parseSemver(entry.key_ptr.*) catch continue;
                if (best == null or semverGt(parts, best_parts)) {
                    best = entry.key_ptr.*;
                    best_parts = parts;
                }
            }
            break :blk best orelse return error.NoRelease;
        },
    };

    const ch = obj.get(key) orelse return error.ChannelNotFound;
    const ch_obj = ch.object;

    const version_str: []const u8 = if (ch_obj.get("version")) |v| v.string else key;

    const target_val = ch_obj.get(target) orelse return error.UnsupportedTarget;
    const target_obj = target_val.object;
    const tarball_str = (target_obj.get("tarball") orelse return error.MissingTarball).string;
    const shasum_str = (target_obj.get("shasum") orelse return error.MissingShasum).string;

    return .{
        .version = try allocator.dupe(u8, version_str),
        .tarball = try allocator.dupe(u8, tarball_str),
        .shasum = try allocator.dupe(u8, shasum_str),
    };
}

fn parseSemver(s: []const u8) ![3]u32 {
    var parts: [3]u32 = .{ 0, 0, 0 };
    var i: usize = 0;
    var it = std.mem.tokenizeScalar(u8, s, '.');
    while (it.next()) |p| : (i += 1) {
        if (i >= 3) return error.TooManyParts;
        parts[i] = try std.fmt.parseInt(u32, p, 10);
    }
    if (i < 3) return error.TooFewParts;
    return parts;
}

fn semverGt(a: [3]u32, b: [3]u32) bool {
    if (a[0] != b[0]) return a[0] > b[0];
    if (a[1] != b[1]) return a[1] > b[1];
    return a[2] > b[2];
}

pub fn run(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    args: []const []const u8,
    stdout: *Io.Writer,
) !void {
    var channel_arg: []const u8 = default_channel_name;
    var no_zls = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--no-zls")) {
            no_zls = true;
        } else if (std.mem.startsWith(u8, a, "--")) {
            try stdout.print("zvk: unknown flag '{s}'\n", .{a});
            try stdout.flush();
            std.process.exit(2);
        } else {
            channel_arg = a;
        }
    }
    const channel = Channel.fromString(channel_arg) orelse {
        try stdout.print("zvk: unknown channel '{s}' (expected 'nightly' or 'release')\n", .{channel_arg});
        try stdout.flush();
        std.process.exit(2);
    };

    const target = currentTarget();
    const root = try defaultRoot(arena, env);

    try stdout.print("[zvk] target: {s}\n", .{target});
    try stdout.print("[zvk] channel: {s}\n", .{@tagName(channel)});
    try stdout.print("[zvk] install root: {s}\n", .{root});
    try stdout.print("[zvk] fetching index from {s}\n", .{index_url});
    try stdout.flush();

    const index_text = try fetchIndex(gpa, io);
    defer gpa.free(index_text);

    const entry = try resolveEntry(arena, index_text, channel, target);

    try stdout.print("[zvk] version: {s}\n", .{entry.version});
    try stdout.flush();

    const version_dir = try std.fs.path.join(arena, &.{ root, "versions", entry.version });

    if (isInstalled(io, version_dir)) {
        try stdout.print("[zvk] {s} already installed at {s}\n", .{ entry.version, version_dir });
    } else {
        try stdout.print("[zvk] tarball: {s}\n", .{entry.tarball});
        try stdout.print("[zvk] downloading...\n", .{});
        try stdout.flush();

        const tarball = try downloadToMemory(gpa, io, entry.tarball);
        defer gpa.free(tarball);

        try stdout.print("[zvk] downloaded {d} bytes\n", .{tarball.len});
        try stdout.flush();

        const actual_hex = sha256Hex(tarball);
        if (!std.mem.eql(u8, &actual_hex, entry.shasum)) {
            try stdout.print(
                "[zvk] error: sha256 mismatch\n  expected: {s}\n  actual:   {s}\n",
                .{ entry.shasum, actual_hex },
            );
            try stdout.flush();
            return error.ShaMismatch;
        }
        try stdout.print("[zvk] sha256 verified\n", .{});

        // Minisign verification (Ed25519 over BLAKE2b-512 of tarball, against Zig's pubkey).
        // Opt out via ZVK_NO_MINISIGN=1.
        if (env.get("ZVK_NO_MINISIGN")) |_| {
            try stdout.print("[zvk] minisign verification skipped (ZVK_NO_MINISIGN set)\n", .{});
        } else {
            const minisig_url = try std.fmt.allocPrint(arena, "{s}.minisig", .{entry.tarball});
            try stdout.print("[zvk] fetching {s}\n", .{minisig_url});
            try stdout.flush();
            const minisig_text = try downloadToMemory(gpa, io, minisig_url);
            defer gpa.free(minisig_text);

            verifyMinisign(tarball, minisig_text, zig_minisign_pubkey_b64) catch |err| {
                try stdout.print("[zvk] error: minisign verification failed: {s}\n", .{@errorName(err)});
                try stdout.flush();
                return err;
            };
            try stdout.print("[zvk] minisign verified\n", .{});
        }

        try stdout.print("[zvk] extracting to {s}\n", .{version_dir});
        try stdout.flush();
        try extractTarXz(gpa, io, tarball, version_dir, 1);
    }

    // Channel symlink: <root>/channels/<channel> -> ../versions/<version>
    const channels_dir = try std.fs.path.join(arena, &.{ root, "channels" });
    try std.Io.Dir.createDirPath(.cwd(), io, channels_dir);
    const channel_link = try std.fs.path.join(arena, &.{ channels_dir, @tagName(channel) });
    const channel_target = try std.fs.path.join(arena, &.{ "..", "versions", entry.version });
    try replaceSymlink(io, channel_target, channel_link);
    try stdout.print("[zvk] channel '{s}' -> {s}\n", .{ @tagName(channel), entry.version });

    // Bin symlink: <root>/bin/{zig|zig-nightly} -> ../channels/<channel>/zig
    const bin_dir = try std.fs.path.join(arena, &.{ root, "bin" });
    try std.Io.Dir.createDirPath(.cwd(), io, bin_dir);
    const bin_name = binNameFor(channel);
    const bin_link = try std.fs.path.join(arena, &.{ bin_dir, bin_name });
    const bin_target = try std.fs.path.join(arena, &.{ "..", "channels", @tagName(channel), "zig" });
    try replaceSymlink(io, bin_target, bin_link);
    try stdout.print("[zvk] {s}/{s} ready\n", .{ bin_dir, bin_name });

    try setupPath(arena, gpa, io, env, bin_dir, stdout);

    // zls is only paired with the release channel (matches stable Zig). Nightly
    // tracks Zig master, where zls master lags upstream and is too unreliable
    // to install by default — we point users at online refs instead.
    if (channel == .release and !no_zls and env.get("ZVK_NO_ZLS") == null) {
        installZlsForRelease(arena, gpa, io, env, entry.version, stdout) catch |err| {
            try stdout.print(
                "[zvk] zls install skipped: {s} (re-run with `zvk install zls` later)\n",
                .{@errorName(err)},
            );
        };
    }

    try writeStatusClaudeMd(arena, io, env);
    try writeChannelReference(arena, io, env, channel, entry.version);
    if (channel == .release) try writeClaudePlugin(arena, io, env, entry.version);

    try printIntegrationHint(arena, io, env, channel, stdout);

    try stdout.print("[zvk] done\n", .{});
}

// ============================================================================
// zls (Zig Language Server) integration
//
// zls release tags follow Zig's minor version (zls 0.X.0 pairs with zig 0.X.*).
// We install zls only for the release channel and only when the latest zls
// release matches the just-installed Zig's major.minor — soft-fail otherwise.
// ============================================================================

const zls_release_api_url = "https://api.github.com/repos/zigtools/zls/releases/latest";

/// zls's official minisign public key, used to sign tarballs at
/// github.com/zigtools/zls/releases/. Source:
/// https://github.com/zigtools/zls (project README / signing docs)
const zls_minisign_pubkey_b64 = "RWR+9B91GBZ0zOjh6Lr17+zKf5BoSuFvrx2xSeDE57uIYvnKBGmMjOex";

/// Asset filename pattern: zls-<arch>-<os>.tar.xz (linux/macos), .zip (windows).
fn zlsAssetName(arena: std.mem.Allocator, target: []const u8) ![]const u8 {
    if (std.mem.endsWith(u8, target, "-windows")) {
        return std.fmt.allocPrint(arena, "zls-{s}.zip", .{target});
    }
    return std.fmt.allocPrint(arena, "zls-{s}.tar.xz", .{target});
}

/// Extract major.minor from "0.16.0" or "0.17.0-dev.224+abc" (returns .{ 0, 17 }).
fn parseMajorMinor(s: []const u8) !struct { u32, u32 } {
    var it = std.mem.tokenizeAny(u8, s, ".-+ ");
    const major_s = it.next() orelse return error.InvalidVersion;
    const minor_s = it.next() orelse return error.InvalidVersion;
    return .{ try std.fmt.parseInt(u32, major_s, 10), try std.fmt.parseInt(u32, minor_s, 10) };
}

const ZlsAsset = struct {
    version: []u8,
    download_url: []u8,
    sha256_hex: []u8,

    pub fn deinit(self: ZlsAsset, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
        allocator.free(self.download_url);
        allocator.free(self.sha256_hex);
    }
};

/// Query GitHub for the latest zls release and pick the asset for the current target.
/// Returns null if no asset for this platform exists in the latest release.
fn fetchLatestZlsAsset(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    target: []const u8,
) !?ZlsAsset {
    const json_text = try downloadToMemory(gpa, io, zls_release_api_url);
    defer gpa.free(json_text);

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, json_text, .{});
    defer parsed.deinit();

    const tag_val = parsed.value.object.get("tag_name") orelse return error.NoTagInResponse;
    const version = std.mem.trimStart(u8, tag_val.string, "v");

    const want_name = try zlsAssetName(arena, target);
    const assets_val = parsed.value.object.get("assets") orelse return error.NoAssetsInResponse;

    for (assets_val.array.items) |a| {
        const name_val = a.object.get("name") orelse continue;
        if (!std.mem.eql(u8, name_val.string, want_name)) continue;
        const url_val = a.object.get("browser_download_url") orelse continue;

        // GitHub's "digest" field looks like "sha256:abc..." — strip the prefix.
        var sha_hex: []const u8 = "";
        if (a.object.get("digest")) |d| {
            const s = d.string;
            if (std.mem.startsWith(u8, s, "sha256:")) sha_hex = s["sha256:".len..];
        }

        return .{
            .version = try arena.dupe(u8, version),
            .download_url = try arena.dupe(u8, url_val.string),
            .sha256_hex = try arena.dupe(u8, sha_hex),
        };
    }
    return null;
}

/// Top-level install: check version match, download, verify, extract, symlink.
fn installZlsForRelease(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    zig_version: []const u8,
    stdout: *Io.Writer,
) !void {
    const target = currentTarget();
    const root = try defaultRoot(arena, env);

    try stdout.print("[zvk] checking zls for zig {s}...\n", .{zig_version});
    try stdout.flush();

    const asset = (try fetchLatestZlsAsset(arena, gpa, io, target)) orelse {
        try stdout.print("[zvk] zls: no release asset for {s} yet\n", .{target});
        return;
    };

    const zig_mm = try parseMajorMinor(zig_version);
    const zls_mm = try parseMajorMinor(asset.version);
    if (zig_mm[0] != zls_mm[0] or zig_mm[1] != zls_mm[1]) {
        try stdout.print(
            "[zvk] zls: latest release is {s}, no match for zig {s} (zls usually catches up within days)\n",
            .{ asset.version, zig_version },
        );
        return;
    }

    const zls_dir = try std.fs.path.join(arena, &.{ root, "zls", asset.version });
    const zls_bin_path = try std.fs.path.join(arena, &.{ zls_dir, "zls" });
    if (std.Io.Dir.accessAbsolute(io, zls_bin_path, .{})) {
        try stdout.print("[zvk] zls {s} already installed\n", .{asset.version});
    } else |_| {
        try stdout.print("[zvk] downloading {s}\n", .{asset.download_url});
        try stdout.flush();
        const tarball = try downloadToMemory(gpa, io, asset.download_url);
        defer gpa.free(tarball);

        if (asset.sha256_hex.len == 64) {
            const actual = sha256Hex(tarball);
            if (!std.mem.eql(u8, &actual, asset.sha256_hex)) {
                try stdout.print("[zvk] zls sha256 mismatch\n  expected: {s}\n  actual:   {s}\n", .{ asset.sha256_hex, actual });
                return error.ShaMismatch;
            }
            try stdout.print("[zvk] zls sha256 verified\n", .{});
        }

        // Minisign: opt-out via ZVK_NO_MINISIGN. Fetched lazily so a missing
        // .minisig file (or zls switching keys) doesn't break installs.
        if (env.get("ZVK_NO_MINISIGN")) |_| {
            try stdout.print("[zvk] zls minisign verification skipped (ZVK_NO_MINISIGN set)\n", .{});
        } else {
            const minisig_url = try std.fmt.allocPrint(arena, "{s}.minisig", .{asset.download_url});
            const minisig_text = downloadToMemory(gpa, io, minisig_url) catch |err| {
                try stdout.print("[zvk] zls minisign fetch failed ({s}); continuing on sha256 only\n", .{@errorName(err)});
                try extractZlsArchive(gpa, io, tarball, zls_dir, asset.download_url);
                try linkZlsBin(arena, io, root, asset.version, stdout);
                return;
            };
            defer gpa.free(minisig_text);
            verifyMinisign(tarball, minisig_text, zls_minisign_pubkey_b64) catch |err| {
                try stdout.print("[zvk] zls minisign verification failed: {s}\n", .{@errorName(err)});
                return err;
            };
            try stdout.print("[zvk] zls minisign verified\n", .{});
        }

        try extractZlsArchive(gpa, io, tarball, zls_dir, asset.download_url);
    }

    try linkZlsBin(arena, io, root, asset.version, stdout);
}

fn linkZlsBin(
    arena: std.mem.Allocator,
    io: Io,
    root: []const u8,
    zls_version: []const u8,
    stdout: *Io.Writer,
) !void {
    const bin_dir = try std.fs.path.join(arena, &.{ root, "bin" });
    try std.Io.Dir.createDirPath(.cwd(), io, bin_dir);
    const link = try std.fs.path.join(arena, &.{ bin_dir, "zls" });
    const target = try std.fs.path.join(arena, &.{ "..", "zls", zls_version, "zls" });
    try replaceSymlink(io, target, link);
    try stdout.print("[zvk] zls {s} ready ({s})\n", .{ zls_version, link });
}

/// Extract tar.xz (linux/macos). Windows .zip is not yet supported — we print
/// a friendly message and return.
fn extractZlsArchive(
    gpa: std.mem.Allocator,
    io: Io,
    tarball: []const u8,
    dest_dir_abs: []const u8,
    source_url: []const u8,
) !void {
    if (std.mem.endsWith(u8, source_url, ".zip")) {
        // TODO: implement zip extraction for Windows zls. For now, callers on
        // Windows hit this path and we fail loud — install path treats this as
        // a soft failure and continues.
        return error.ZipExtractionNotSupported;
    }
    try extractTarXz(gpa, io, tarball, dest_dir_abs, 0);
}

/// `zvk install zls` — explicit zls install for the active release Zig.
pub fn runInstallZls(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    stdout: *Io.Writer,
) !void {
    const root = try defaultRoot(arena, env);
    const zig_ver = (try readActiveVersion(arena, io, root, .release)) orelse {
        try stdout.print("[zvk] no release Zig installed; run `zvk install` first\n", .{});
        return;
    };
    try installZlsForRelease(arena, gpa, io, env, zig_ver, stdout);
    try writeClaudePlugin(arena, io, env, zig_ver);
}

/// `zvk update zls` — same as `zvk install zls` (idempotent re-fetch).
pub fn runUpdateZls(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    stdout: *Io.Writer,
) !void {
    try runInstallZls(arena, gpa, io, env, stdout);
}

/// `zvk lsp-config` — print the recommended .lsp.json snippet to stdout for
/// users who want to wire LSP into Claude Code without using the marketplace
/// (e.g. dropping it directly into a project's .claude/ plugin).
pub fn runLspConfig(stdout: *Io.Writer) !void {
    try stdout.writeAll(
        \\{
        \\  "zls": {
        \\    "command": "zls",
        \\    "extensionToLanguage": {
        \\      ".zig": "zig"
        \\    }
        \\  }
        \\}
        \\
    );
}
