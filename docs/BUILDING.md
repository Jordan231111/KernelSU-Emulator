# Build from source

Use the repository tag matching your release. Building requires Docker in addition to the installation requirements in the README.

```sh
python3 ksu.py build --output out/core
python3 ksu.py build-susfs --output out/susfs
python3 ksu.py check-bundle out/core
python3 ksu.py check-susfs-bundle out/susfs
```

Use `out/core` and `out/susfs` as the bundle paths in the installation commands. The build downloads checksum-pinned sources and produces matching modules, userspace tools and source archives.

Host checks:

```sh
python3 -m unittest discover -s tests -v
```

Runtime qualification is documented in [tests/guest/README.md](../tests/guest/README.md). Host checks and successful compilation do not establish emulator compatibility.

Generated builds and downloads live in ignored `out/` and `.work/` directories. Delete them after publishing or installing if they are no longer needed. Keep source files and the release checksums.
