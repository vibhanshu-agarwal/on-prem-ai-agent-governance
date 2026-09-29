"""python -m govdisc [config.yaml]  (default: $GOVDISC_CONFIG or /etc/govdisc/config.yaml)"""
import logging
import os
import signal
import sys

from .wiring import build_runner, load_config


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GOVDISC_CONFIG", "/etc/govdisc/config.yaml")
    runner = build_runner(load_config(path))
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    runner.run_forever()


if __name__ == "__main__":
    main()
