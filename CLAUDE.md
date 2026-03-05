# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build all targets (server_e, client_e, renux)
make

# Build individual targets
make server_e
make client_e
make renux
make renux_master

# Clean
make clean

# Full install (compiles + installs renux to /usr/local/bin + registers systemd service)
./setup.sh
```

## Run

```bash
# Server (port 8080, prompts for admin password on startup)
./server_e

# Client
./client_e <server_ip> <port>
# e.g.: ./client_e 127.0.0.1 8080

# Monitoring agent (runs as daemon, reads config from /etc/renux.conf)
sudo ./renux

# Master server (listens on port 9000, aggregates agent logs)
./renux_master
```

## Architecture

The project has three independent executables with distinct roles:

### `server_e` + `client_e` — Remote Linux Admin Tool
The server (`server/server.c`) uses **`kqueue` on macOS / `epoll` on Linux** (compile-time `#ifdef __APPLE__`) for a single-threaded event loop handling up to 128 clients. Authentication happens before any command is processed: the client sends `username,password`, the server hashes the password with `hash_string()` (`utils/ssl_utils.c`) and compares against a hash set at startup.

After login, the client sends text commands; the server dispatches them in `server/service.c`:
- `getu` — list users
- `<user>:getinfo` / `<user>:get_proc` / `<user>:get_quota` / `<user>:set_quota:<soft>:<hard>:<fs>` — per-user operations
- `trace <user>` — search `/var/log/renux.log` for activity
- `get_fstab_quota_list` — list quota-enabled filesystems

Multi-response commands terminate with `"END_OF_LIST\n"` as a sentinel.

The client (`client/client.c`) spawns a `receive_handler` thread that runs alongside the main input loop. Shared state (`menu_user_list`, `quota_fs_list`, mode flags) is protected by `menu_lock` (pthread mutex). The client has three receive modes toggled by volatile bools: `is_menu_mode`, `is_fs_list_mode`, `is_trace_mode`.

Both sides use `ncurses` TUI; `server/tui.c` and `client/tui.c` are separate implementations.

### `renux` — Monitoring Agent (`monitoring/monitor.cpp`)
C++17. Runs as a systemd service on monitored hosts. On start it:
1. Reads `/etc/renux.conf` for `MASTER_IP` and `MASTER_PORT`
2. Auto-detects its own IP via `getifaddrs()`
3. Injects a `PROMPT_COMMAND` hook into every user's `.bashrc` to log shell commands to `~/.renux_history`
4. Watches `/root` and `/home/**` with **inotify** for file events
5. On file change, runs `diff` and logs the diff to `/var/log/renux.log`
6. Streams logs to `renux_master` in the format `LOG|<agent_ip>|<message>\n`

When invoked as `renux trace <keyword>`, it searches the local log file and prints matching entries — this is called remotely by `server_e` via `popen()`.

### `renux_master` — Central Log Server (`monitoring/master.cpp`)
C++17. Multi-threaded TCP server on port 9000. Each agent gets its own `std::thread`. Logs are written to `central_renux.log`. The interactive command shell (detached thread) supports: `list`, `trace <IP>`, `all`, `exit`.

## Key Design Patterns

- **`END_OF_LIST` protocol**: server sends this sentinel after multi-line responses; client receive thread uses mode flags to accumulate lines into arrays before displaying
- **Cross-platform event loop**: `#ifdef __APPLE__` / `#elif __linux__` blocks throughout `server/server.c` — always maintain both branches when editing
- **`hash_string()`** in `utils/ssl_utils.c` is a djb2 variant used for password hashing — **not** cryptographic; the name `ssl_utils` is misleading
- `main.c` at root is a stub ("Developing Now") — not part of the build

## Known Issues (see PLAN.md for V2.0 roadmap)

- `service.c` uses `popen()` with user-supplied strings → Command Injection risk
- `ssl_utils.c` contains only a hash function; no actual TLS anywhere
- `monitor.cpp` drops logs silently when disconnected from master (no buffering)
- `Makefile` has no security hardening flags
