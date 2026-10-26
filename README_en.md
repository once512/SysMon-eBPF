<p align="center">
  <a href="./README_en.md">English</a>
  &middot;
  <a href="./README.md">简体中文</a>
</p>

# SecMon

Having explored various Linux system monitoring techniques, eBPF was the only approach I had yet to implement. Thus, this open-source repository was born.

Developers who share the same interest are more than welcome to join, contribute, and iterate on this project together!


The monitor now has one service entry point: `secmon` owns BPF and optional fanotify modules as objects in the same process, sharing one policy revision and control socket. The analyzer remains a separate worker with reduced privileges. See [the service guide](docs/UNIFIED_SERVICE.md) for the current structure and commands.

Scoped online file-vault sessions now reuse the existing policy and root management channel; see [vault session semantics](docs/VAULT_SESSIONS.md). This is access control, without encryption or end-user authentication.


An optional [FUSE virtual decoy view](docs/VIRTUAL_DECOYS.md) now provides up to 64 immutable synthetic files without a business-file backing store. Existing inode-based canary policies and kernel responses apply directly. This initial independent mount does not provide transparent business-directory injection, automatic provider supervision or policy rebinding after remount. Build with libfuse3 development headers, or set `SECMON_BUILD_DECOYFS=OFF` for the core service alone.

Fanotify now isolates event-file acquisition and cleanup for both static and [analysis decisions](docs/ANALYSIS_EVENT_READER.md). [Reader progress](docs/READER_HEALTH.md) is observable in status; a missing acknowledgement for two seconds reports unresponsive without automatically replacing the permission group. BPF self-protection also covers [privileged direct helpers](docs/HELPER_PROTECTION.md), while the host retains cleanup authority.
