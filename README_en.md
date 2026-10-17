<p align="center">
  <a href="./README_en.md">English</a>
  &middot;
  <a href="./README.md">简体中文</a>
</p>

# SecMon

Having explored various Linux system monitoring techniques, eBPF was the only approach I had yet to implement. Thus, this open-source repository was born.

Developers who share the same interest are more than welcome to join, contribute, and iterate on this project together!


The monitor now has one service entry point: `secmon` owns BPF and optional fanotify modules as objects in the same process, sharing one policy revision and control socket. The analyzer remains a separate worker with reduced privileges. See [the service guide](docs/UNIFIED_SERVICE.md) for the current structure and commands.
