# Synthetic fixtures only

`demo-world/level.dat` and `demo-world/region/r.0.0.mca` are plain UTF-8 text with deliberately game-like filenames. They are not valid game save formats. `level.json` is synthetic JSON.

These files contain no real world data, proprietary game binaries, licensed game assets, server credentials or user information. The examples do not require or launch any game. `demo-manifest.json` is the deterministic SHA-256 inventory of these three synthetic files.

To verify from the repository root:

```bash
python3 world_backup_manifest.py verify examples/demo-world examples/demo-manifest.json
```
