"""Entrypoint: `python -m model_supply_chain_scanner`."""

from __future__ import annotations

from model_supply_chain_scanner import __version__
from model_supply_chain_scanner.configuration import settings


def main() -> None:
    header = f"Model Supply Chain Scanner v{__version__}"
    status = f"environment={settings.environment}, seed={settings.seed}"
    print(f"{header} - {status}")


if __name__ == "__main__":
    main()
