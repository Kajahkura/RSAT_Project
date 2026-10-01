"""Compatibility entry point for source runs and standalone builds."""

from rsat.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
