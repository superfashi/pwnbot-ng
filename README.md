# pwnbot-ng

pwnbot-ng is a fast, safe and headless automatic exploit thrower for Attack/Defense Capture the Flag (CTF) competitions.

This tool is internally used by CTF team Blue Water during DEF CON CTF 2025.

This tool is expected to be used together with a configured Git repository. Please see https://github.com/superfashi/pwnbot-repo-template for example repository configuration.

> More detailed documentation coming soon&hellip;

## Dependencies
   - `libgpgme` (library and development files)
   - `crun` binary: https://github.com/containers/crun
   - `netavark` binary: https://github.com/containers/netavark

## Build

- main binary: `go build -tags exclude_graphdriver_btrfs pwnbot-ng`
- local binary: `go build -tags exclude_graphdriver_btrfs pwnbot-ng/cmd/pwnbot-local`
- git update hook: `go build pwnbot-ng/cmd/update-hook`

## License

This work is licensed under the Zero-Clause BSD license. See [LICENSE](LICENSE) for details.
