const std = @import("std");
const Io = std.Io;
const install = @import("install.zig");

const version = install.zvk_version;

const usage =
    \\zvk - Zig version kit
    \\
    \\Usage:
    \\  zvk install [release|nightly]            Install Zig (default: release)
    \\  zvk update  [release|nightly|all]        Re-run install for the given channel(s)
    \\  zvk use <channel> <version>              Point a channel at an installed version
    \\  zvk uninstall <version>                  Remove an installed version
    \\  zvk list                                 List installed versions and channel state
    \\  zvk which [channel]                      Show active version for a channel
    \\  zvk status [--json]                      Print full state (text or JSON)
    \\  zvk self-install                         Copy zvk to ~/.zoptia/zig/bin/ + setup PATH
    \\  zvk self-update [--dry-run|--force]      Replace zvk with the latest GitHub Release
    \\  zvk version                              Print zvk version
    \\  zvk help                                 Show this help
    \\
    \\PATH commands installed:
    \\  zig            -> active release       (the conservative default)
    \\  zig-nightly    -> active nightly       (opt-in via `zvk install nightly`)
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file.interface;
    defer stdout.flush() catch {};

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_file: Io.File.Writer = .init(.stderr(), init.io, &stderr_buffer);
    const stderr = &stderr_file.interface;
    defer stderr.flush() catch {};

    if (args.len < 2) {
        try stdout.writeAll(usage);
        return;
    }

    const cmd = args[1];

    if (eq(cmd, "install")) {
        try install.run(
            init.arena.allocator(),
            init.gpa,
            init.io,
            init.environ_map,
            args[2..],
            stdout,
        );
    } else if (eq(cmd, "list") or eq(cmd, "ls")) {
        try install.runList(init.arena.allocator(), init.io, init.environ_map, stdout);
    } else if (eq(cmd, "which")) {
        try install.runWhich(init.arena.allocator(), init.io, init.environ_map, args[2..], stdout);
    } else if (eq(cmd, "use")) {
        try install.runUse(init.arena.allocator(), init.io, init.environ_map, args[2..], stdout);
    } else if (eq(cmd, "uninstall") or eq(cmd, "remove") or eq(cmd, "rm")) {
        try install.runUninstall(init.arena.allocator(), init.io, init.environ_map, args[2..], stdout);
    } else if (eq(cmd, "update")) {
        try install.runUpdate(
            init.arena.allocator(),
            init.gpa,
            init.io,
            init.environ_map,
            args[2..],
            stdout,
        );
    } else if (eq(cmd, "self-install")) {
        try install.runSelfInstall(init.arena.allocator(), init.gpa, init.io, init.environ_map, stdout);
    } else if (eq(cmd, "self-update")) {
        try install.runSelfUpdate(init.arena.allocator(), init.gpa, init.io, init.environ_map, args[2..], stdout);
    } else if (eq(cmd, "status") or eq(cmd, "info")) {
        try install.runStatus(init.arena.allocator(), init.io, init.environ_map, args[2..], stdout);
    } else if (eq(cmd, "version") or eq(cmd, "--version") or eq(cmd, "-v")) {
        try stdout.print("zvk {s}\n", .{version});
    } else if (eq(cmd, "help") or eq(cmd, "--help") or eq(cmd, "-h")) {
        try stdout.writeAll(usage);
    } else {
        try stderr.print("zvk: unknown command '{s}'\n\n{s}", .{ cmd, usage });
        try stderr.flush();
        std.process.exit(2);
    }
}

inline fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
