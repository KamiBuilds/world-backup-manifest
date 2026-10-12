# World Backup Manifest

A dependency-free Python CLI for deterministic SHA-256 inventories of **copied, offline** game-world backups. It compares relative paths, byte sizes and hashes and reports missing, modified and unexpected files. It reads backup data only; it never starts/stops a server, archives, restores or deletes a world.

The implementation passed independent security/correctness review within its documented offline-inventory scope. It is not a backup creator, atomic snapshot, manifest-authentication system or restore test.

## Requirements and platform matrix

- Python 3.9+; no pip, virtual environment, third-party packages or administrator permissions needed.
- Read and directory-search permissions for the entire offline backup and its manifest.
- Descriptor-relative filesystem operations and `O_CLOEXEC`, `O_DIRECTORY`, `O_NOFOLLOW`, `O_NONBLOCK`.
- Git for clone/update; Bash and standard POSIX utilities for the shell examples.

| Platform | Support / verification |
| --- | --- |
| Linux x86_64, Python 3.11.16 | Live-tested here: complete suite, FIFO races and documented local flows |
| Other mainstream Linux distributions / ARM64 | Designed for the same POSIX APIs; not live-tested |
| macOS / BSD | Designed for POSIX APIs where supported; not live-tested; run the suite before use |
| Native Windows | Unsupported: required safe no-follow directory operations are unavailable |
| WSL Linux | Designed to work on its Linux filesystem; not live-tested; Windows-mounted filesystems are unverified |
| Python 3.9, 3.10, 3.12+ | Intended compatibility; not live-tested in this repair |

Run the suite on any designed-but-unverified environment before relying on it. No claims are made for network filesystems, special virtual filesystems or hostile mounts.

## Installation

From a directory where you want a dedicated checkout:

```bash
git clone https://github.com/KamiBuilds/world-backup-manifest.git
cd world-backup-manifest
python3 --version
python3 world_backup_manifest.py --help
python3 -m unittest discover -s tests -v
```

There is no installation step or system configuration beyond cloning. Run the script from the checkout.

## Run the synthetic example

All files in `examples/demo-world` are visibly synthetic UTF-8 text / JSON. The `.dat` and `.mca` suffixes imitate backup filenames, **not** valid game formats. There are no proprietary binaries, real worlds or server credentials. See [examples/README.md](examples/README.md).

```bash
python3 world_backup_manifest.py verify examples/demo-world examples/demo-manifest.json
python3 world_backup_manifest.py verify examples/demo-world examples/demo-manifest.json --json
```

Human output: `OK: 3 file(s) matched`. JSON output includes `"ok": true` and `"matched": 3`.

### Create and verify without changing repository fixtures

Write manifests **outside** the world tree. Creation emits JSON to standard output only; shell redirection is responsible for writing it. Bash `noclobber` prevents overwriting an existing file:

```bash
scratch="$(mktemp -d)"
(
  set -o noclobber
  python3 world_backup_manifest.py create examples/demo-world > "$scratch/manifest.json"
)
python3 world_backup_manifest.py verify examples/demo-world "$scratch/manifest.json"
python3 world_backup_manifest.py verify examples/demo-world "$scratch/manifest.json" --json
rm -rf -- "$scratch"
```

For an actual backup, use a consistent offline copy under your own control rather than a live server directory. Keep the manifest outside that copy and retain a trusted baseline; do not regenerate it to hide drift. This utility neither creates nor validates the consistency of the original backup operation.

### Exercise drift detection safely

This modifies a temporary copy only:

```bash
scratch="$(mktemp -d)"
cp -R examples/demo-world "$scratch/world"
printf 'changed\n' >> "$scratch/world/level.dat"
python3 world_backup_manifest.py verify "$scratch/world" examples/demo-manifest.json
status=$?
rm -rf -- "$scratch"
test "$status" -eq 1
```

The verification command returns `1` and identifies `level.dat` as modified. The final `test` returns `0` when the expected drift was detected.

| Exit status | Meaning |
| --- | --- |
| `0` | Create succeeded, or verify matched all files without extras |
| `1` | Verify detected missing, modified or unexpected files |
| `2` | Input, manifest, unsupported platform or filesystem error |

`verify --json` emits JSON on success or drift; errors still go to standard error and return `2`.

## Safety and limits

- Use a stopped/offline copy or immutable filesystem snapshot. This is **not** a transactional scanner: concurrent tree changes can evade a whole-tree consistency check. SHA-256 inventories do not authenticate a manifest or prove that a world can be loaded.
- Symlinks in world or manifest paths (including parent components) are rejected, not followed. Paths containing `..` are rejected; use a direct path to the backup instead.
- Special files are rejected. Nonblocking candidate opens prevent a regular-file-to-FIFO replacement from blocking before post-open type/inode validation.
- Each world file is streamed in chunks of at most 1 MiB and reads at most its initial opened size plus one byte. Growth, truncation or observed metadata changes fail closed. World size has no fixed cap; very large files still cost proportional I/O.
- Manifest inputs must be stable regular UTF-8 files at most **16 MiB**, read with a size-derived bound. Larger inventories must be split into separately manifested backup subdirectories. JSON object keys must be unique; schema fields, relative paths, sizes and lowercase SHA-256 digests are validated strictly. Backslash filenames are rejected during creation because they cannot round-trip through this format.
- Directory traversal and inventory memory scale with tree size; extreme depth can exceed descriptor or recursion limits and fail. No wall-clock I/O timeout is promised for stalled disks, network mounts or device replacement races other than FIFOs.
- Manifests reveal filenames, sizes and hashes. Store them as sensitive backup metadata. A maliciously replaced trusted manifest can hide corruption; keep it somewhere trusted.
- Never redirect `create` output inside the world: the shell would create a self-generated file before scanning. Failed creation can leave a partial or empty redirected file; discard that failed output rather than treating it as a baseline.

## Tests and quality checks

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q world_backup_manifest.py tests
python3 world_backup_manifest.py create examples/demo-world
python3 world_backup_manifest.py verify examples/demo-world examples/demo-manifest.json
python3 world_backup_manifest.py verify examples/demo-world examples/demo-manifest.json --json
git diff --check
git diff --cached --check
```

Tests use isolated synthetic temporary fixtures, including a deterministic stat/open FIFO-swap regression with a bounded subprocess timeout. They never contact game servers or read real user worlds. There is no GitHub Actions workflow because the publication credential lacks workflow scope; these local commands are CI-ready, but no hosted-CI success is claimed.

## Update

Save local changes and retain your existing trusted manifests. Then, from the dedicated checkout:

```bash
git status --short
git pull --ff-only
python3 -m unittest discover -s tests -v
python3 world_backup_manifest.py verify examples/demo-world examples/demo-manifest.json
```

Do not automatically re-baseline a backup during update.

## Uninstall / cleanup

Nothing is installed globally. Temporary example directories are removed by their example commands. To remove Python bytecode caches only, from the checkout:

```bash
python3 -c 'import shutil; shutil.rmtree("__pycache__", ignore_errors=True); shutil.rmtree("tests/__pycache__", ignore_errors=True)'
```

To remove the tool, first preserve any local changes or manifests you placed in its dedicated clone. From the **parent** directory of that clone only:

```bash
rm -rf -- world-backup-manifest
```

This deletes the checkout, not an external backup. Do not run it on a directory containing data you need. No server uninstall or system cleanup is required.

## License

MIT — see [LICENSE](LICENSE).
