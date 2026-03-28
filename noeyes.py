"""NoEyes entry point."""

import sys

# Version check before any other imports - gives a clear error on old Python
if sys.version_info < (3, 10):
    _v = sys.version_info
    print(f"\n  [!] Python 3.10 or newer is required.")
    print(f"      You are running Python {_v.major}.{_v.minor}.{_v.micro}")
    print(f"\n  Run python setup.py or python install/install.py to install Python 3.10+.\n")
    sys.exit(1)

import logging

from core import config as cfg_mod
from core import firewall as fw
from core.startup import run_server, run_client, run_gen_key, run_generate_access_key, run_generate_chat_key

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logging.getLogger("noeyes.server").setLevel(logging.INFO)


def main(argv=None) -> None:
    cfg = cfg_mod.load_config(argv)

    if cfg["gen_key"]:
        run_gen_key(cfg)
        return

    if cfg["generate_access_key"]:
        run_generate_access_key(cfg)
        return

    if cfg["generate_chat_key"]:
        run_generate_chat_key(cfg)
        return

    if cfg["server"]:
        fw.check_stale()
        run_server(cfg)
        return

    if cfg["connect"]:
        run_client(cfg)
        return

    cfg_mod.build_arg_parser().print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()