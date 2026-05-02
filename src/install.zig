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
    const home = env.get("HOME") orelse return error.NoHome;
    return try std.fs.path.join(allocator, &.{ home, ".zoptia", "zig" });
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
    const zvk_path = try std.fs.path.join(arena, &.{ bin_dir, "zvk" });

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
        \\  "zvk_version": "0.0.1",
        \\  "install_root": "{s}",
        \\  "bin_dir": "{s}",
        \\  "zvk_path": "{s}",
        \\  "default_channel": "{s}",
        \\
    , .{ s.install_root, s.bin_dir, s.zvk_path, @tagName(default_channel) });

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
        \\This file is auto-generated by `zvk install` / `zvk update` / `zvk use` /
        \\`zvk uninstall`. Do not edit by hand — your changes will be overwritten on
        \\the next zvk command. To stop generating it, set `ZVK_NO_CLAUDE_MD=1`.
        \\
        \\## Active Zig versions
        \\
        \\| Command         | Version                                  | Channel  |
        \\|-----------------|------------------------------------------|----------|
        \\
    );
    try renderChannelRow(w, status.release, "release", "(not installed)");
    try renderChannelRow(w, status.nightly, "nightly", "(not installed)");

    try w.writeAll(
        \\
        \\The default `zig` command points to the latest stable release. Nightly is
        \\opt-in via the `zig-nightly` command.
        \\
        \\## How to apply
        \\
        \\- For project code that compiles on stable Zig, just use `zig build` etc.
        \\- For projects requiring Zig nightly features (e.g. `std.Io`, the new
        \\  `pub fn main(init: std.process.Init)` signature), invoke as
        \\  **`zig-nightly`** instead of bare `zig`.
        \\- To update: `zvk update release` / `zvk update nightly` / `zvk update all`.
        \\- To switch which version is active in a channel:
        \\  `zvk use <channel> <version>`.
        \\
        \\## Inspect state
        \\
        \\Run `zvk status` (or `zvk status --json` for machine-readable output)
        \\to see current channel mappings, installed versions, and bin paths.
        \\
    );

    try w.print("\nInstall root: `{s}`\n", .{status.install_root});

    try w.flush();
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
pub const zvk_version = "0.0.2";

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
    const target = try std.fs.path.join(arena, &.{ bin_dir, "zvk" });

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
    const target = try std.fs.path.join(arena, &.{ bin_dir, "zvk" });

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

/// `update` is essentially `install` for the requested channel(s). Accepts "nightly", "release", or "all".
pub fn runUpdate(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    args: []const []const u8,
    stdout: *Io.Writer,
) !void {
    const target_arg: []const u8 = if (args.len > 0) args[0] else default_channel_name;
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
    const channel_arg: []const u8 = if (args.len > 0) args[0] else default_channel_name;
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
    try writeStatusClaudeMd(arena, io, env);

    try stdout.print("[zvk] done\n", .{});
}
