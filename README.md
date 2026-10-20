<div align="center">

# VShell

**Reverse-Engineering Research · Go**

An incomplete, independent re-implementation study of the VShell v3.0 framework, based on binary analysis and behavioral verification.

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

> **Research notice:** An incomplete, unofficial reverse-engineering study for authorized security research only. It is not affiliated with the original author, does not include the original software license, and does not guarantee behavioral or protocol compatibility.

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![Research](https://img.shields.io/badge/focus-reverse%20engineering-64748b)](#reverse-engineering-status)
[![License](https://img.shields.io/badge/license-see%20license.txt-red)](license.txt)

---

## Introduction

VShell is an open-source, **incomplete** re-implementation of the VShell C2 (Command & Control) management framework. It provides a web management panel, a multi-protocol C2 engine (HTTP/HTTPS, DNS, KCP, WebSocket/CDN), and an agent with remote terminal, screen streaming and plugin execution. The project was produced by decompiling and reimplementing the original Windows binary (`v_windows_amd64.exe`). Alignment is a work in progress: the [Reverse-Engineering Status](#reverse-engineering-status) section states exactly which modules are verified 1:1 against the binary and which are not.

---

## Features

| Module | Description |
|---|---|
| **Web panel** | Login auth, Basic Auth, JWT, dashboard, client/listener/task management, file upload/download, screen viewer |
| **C2 engine** | Multi-protocol listeners (HTTP/HTTPS, DNS, KCP, WebSocket/CDN); online monitoring, health checks, maintenance tasks |
| **Agent** | Remote terminal, screen streaming, plugin execution; VerifyKey + salt handshake |
| **Notifications** | DingTalk / WeChat Work bot alerts (optional) |
| **Persistence** | SQLite (web) + JSON (engine) dual storage |

---

## Layout

```
vshell/
├── main.go            # Entry: config, engine, db, router
├── conf/              # Config files (gitignored; contains keys)
├── c2engine/          # Engine: listeners, protocol, KCP/DNS, storage (SQL)
├── agent/             # Agent: terminal/screen/plugins; ldflags injection
├── controllers/       # Web API controllers
├── router/            # HTTP routing & middleware
├── utils/             # Config, auth, license, notifications
└── static/            # Frontend SPA (extracted from the original binary)
```

---

## Quick Start

### 1. Build

```bash
# Server (Web + C2 Engine)
go build -o vshell-server .

# Agent (standalone module)
cd agent && go build -o agent.exe .
```

### 2. Configure

Create `conf/setting.conf` (see `generateConfigContent` in `utils/config.go` for the template):

```ini
master_type=web              # web / gui / all
web_port=8082
web_ip=0.0.0.0
web_basic_auth=true          # blocks mass-asset discovery scanners
web_username=admin
web_password=<your-strong-password>   # empty → random password generated at startup
web_jwt_secret=              # empty → random secret per process
```

> **Security note**: If `setting.conf` is absent, a random admin password is generated at startup and printed to the log. **No hardcoded credentials exist in the codebase.** Always change the default configuration after deployment.

### 3. Run

```bash
./vshell-server
# Open in browser: http://<ip>:8082/login
```

### 4. Build the Agent with injected config

Agent connection settings are injected at compile time via `ldflags` (matching `ServerAddr`, `VerifyKey`, `EncryptSalt` in `agent/main.go`):

```bash
cd agent
go build -ldflags "\
  -X main.ServerAddr=REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.VerifyKey=REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.EncryptSalt=REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX" \
  -o agent.exe .
```

### 5. Create a listener

Listeners are created dynamically through the web panel API (`c2engine.NewListener(listenAddr, connectAddr, mode, verifyKey, encryptSalt, remark)`). Supported modes: `http` / `https` / `dns` / `kcp` / `websocket` (CDN).

---

## Reverse-Engineering Status

> This project reverse-engineers the original Windows binary (`v_windows_amd64.exe`, garble-obfuscated Go) **top-down**: every module is aligned 1:1 with its Ghidra decompilation, no invented implementations. Alignment is never finished, so this section states what is verified and what is not.

### Verified against the binary (1:1 aligned and test-covered)

| Module | Aligned content | Evidence |
|---|---|---|
| `c2engine/storage.go` | SQL layer (clients/listeners/hosts/tasks) field-for-field with the decompiled SQL | runtime DB schema diff |
| `c2engine/wire.go` | 24-byte typed-field frames (kind byte + flags + 3 dwords) | unit tests |
| `c2engine/channel_frame.go` | Channel/tunnel frame protocol (FUN_011b4040/011b5600/011b5b40) | 6 tests |
| `c2engine/dns.go` | DNS channel = Go std base32 (no padding); query = `[8B agent ID][message].domain` | tests |
| `c2engine/kcp.go`, `protocol.go`, `engine.go` | KCP/protocol/listener dispatch; check-in now carries the agent's arch | tests |
| `c2engine/listener.go` | Message frames opened as `<u32 LE len><[12B nonce][ct][16B GCM tag]>` | captured-frame test |
| `c2engine/stream_hub.go` | Terminal/screen relay to panel viewers (screen frames zlib-compressed) | hub + WebSocket tests |
| `controllers/*` | Login/client/listener/tunnel/file/download/screenshot/runner controllers | endpoint tests |
| `router/`, `utils/` | Routing, auth (401 on missing/invalid token), config, license, notifications | tests |
| `agent/` | Message-frame crypto, the `FUN_010952e0` opcode dispatcher, terminal/screen relay clients | 13 opcodes + crypto tests |

### Cracked artifacts

- **Message frame**: `wire = <u32 LE len><[12B nonce][ct][16B tag]>`, AES-256-GCM.
  Key is **derived per deployment**: `key = hex.EncodeToString(md5(EncryptSalt))`
  (32 ASCII chars used verbatim). Verified by opening a captured frame to
  the 9-byte plaintext (four zero bytes then `4.9.3`); the raw 16-byte digest and
  a zero-padded digest both fail the GCM tag, so the discriminator is the tag, not
  the key length.
- **GCM parameters** (nonce 12 at offset 0, no AAD, tag 16): established by
  exhaustive search over nonce size 8-20 x offset 0-4 x AAD in {none, nonce} x tag
  size 8-20 against a captured frame — exactly one configuration authenticates it.
  This is *inferred from the capture*, not read out of the binary: garble keeps no
  `crypto/aes`/`crypto/cipher` symbol names, only their error strings.
- **`FUN_010952e0` dispatcher**: command byte 8 of the 24-byte task record is the
  opcode; the switch jumps on `opcode - 1` (`DEC R9; CMP R9,0x2a; JA default;
  JMP [0x1dc31e40 + R9*8]`, verified in the disassembly at 0x1095828). The jump
  table at `0x1dc31e40` has **43 entries**, two of which (opcodes 0x05 and 0x19)
  point at the default branch, so **41 opcodes have real handlers**; the arg is a
  4-byte big-endian int (`FUN_00fc1620`). An earlier revision of this file claimed
  39 reachable opcodes with 0x04/0x08/0x18 dead — that came from reading decompiled
  *case numbers* as opcode bytes, and is wrong: `case K` is opcode K+1, and 0x04,
  0x08 and 0x18 all have handlers.
- **Obfuscated string pools**: garble's per-package pools decode as
  `plaintext = dst_blob - src_blob` (bytewise, mod 256) over a fixed length; the
  loader is `0x116d020`, the decode site `0x116d0c2`, e.g. 0x9aff bytes giving
  SQLite's pragma-name array. **Corrected:** the 67-record table at `0x1e302680`
  is NOT a command-name table and its 3-byte field is NOT an offset into a
  decoder — it is SQLite's `sqlite3Pragma` list (from the embedded
  modernc.org/sqlite), rewritten at load by `0x117b989`, containing zero
  relocations. Where the per-opcode name table lives remains unresolved; the
  pools that decode cleanly contain no VShell strings.
- **Obfuscated string chain** (`po`/`decFunc`): a permutation chain whose per-step
  operation is class-dependent; recovered byte-exactly
  (`"stageless/ebpf_%s_%s"`, `"windows_amd64.exe"`).
- **SPA wire contracts**: `/runner/runplugin` takes `pluginName`/`procArg`; screen
  `quality` is `"big"/"normal"/"small"`; screenshot returns bare base64;
  `/download/*` return raw binary bodies with `Content-Disposition`/`Content-Type`.
- **Older findings kept for reference**: server AES-128 `FUN_0053a1e0`; login
  password = `web_password` verbatim -> JWT; client struct (22 fields @ 0x1bb9580).
- **Corrected**: `0x458f00` is a garble string/field-name decryptor (rdx = 0x8e2240
  string table, inputs are JSON field names), **not** a message cipher. The earlier
  keystream/CBC-chain model and the `msgFrameKey` constant were both wrong; the
  constant was a guess that had been written into the source, and it appears nowhere
  in `v_windows_amd64.exe`.

### Not yet recovered

| Item | Status |
|---|---|
| Most of the 41 `FUN_010952e0` opcodes | Report `not implemented` — their client-state fields and result-frame encodings have no counterpart yet. Frame emitters: `FUN_0100d160`/`FUN_0100d440`/`FUN_0100d5e0` |
| Per-opcode string constants | Not in the table previously believed to hold them (that one is SQLite pragma names, and the dispatcher record comes from its binary search). The table that holds them is unlocated; ruled out so far: that table, any file-image table with relocations, and all 881 cleanly-decodable pools (`c2engine/string_decrypt.go`) |
| `FUN_0194d140` background services | Constant-based branches unaligned; `AppBackground` covers the license/`licTime` path only |
| Download payload bytes | Labeled a **known deviation**: templates are fetched through the listener at request time, config values are per-listener, and the argv key is unrecovered. Two placeholders are documented in-source (`PoArgvSeed`, argv entry key) |
| Embedded agent binaries | Not statically extractable — Go fills the per-file `{ptr, len}` records from `init` via `loaduintptr` |
| Screen quality -> parameter mapping | Unlocated; the values in `screenCaptureParams` and the zlib level are marked PLACEHOLDER in-source |
| Agent-side `runplugin` handler | Absent; `/runner/runplugin` therefore does its pre-flight checks and dispatches nothing |
| `FUN_017019c0` state-machine strings | Deeply encrypted; static solving abandoned |
| `FUN_011a02e0`/`01564720` decrypt stubs | Static solve blocked |

### Deliberate divergences from the original

- **License failure**: the original aborts the process via `FUN_005ecc00`; this
  implementation falls back to the `FUN_0194cd00` defaults. Documented in
  `controllers/engine.go` and asserted by `background_test.go`.
- **License key**: the original RSA private key is not included, so the server runs
  with inferred license values (`public`, `20990101`, 99 clients, VIP).
- **Agent generation**: payloads are built here rather than patched from embedded
  templates, because those templates could not be extracted.
## Known Limitations

> Because this is an **incomplete** reverse-engineering effort, the following may differ from the original:

- **License validation**: the original RSA private key is **not** included; without it the server runs in "observation mode" with inferred license values (`LicenseName=public, LimitClient=99, VIP=true`).
- **Frontend assets**: the SPA in `static/` was extracted from the original binary; some form defaults may differ.
- **Agent behavior**: platform-specific code (process hiding, persistence, etc.) is a minimal implementation.
- **Protocol compatibility**: interop with the official server/client is **not guaranteed**; intended for independent research only.

---

## Tech Stack

Go 1.25 · gorilla/websocket · kcp-go/v5 · modernc.org/sqlite · gorilla/sessions

---

## License

This repository does not include the original license; all rights of the original software belong to its author. **Research only — no commercial or unlawful use.**
