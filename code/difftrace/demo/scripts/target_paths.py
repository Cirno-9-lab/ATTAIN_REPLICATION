#!/usr/bin/env python3

import os
import pathlib


PREFERRED_DEMO_TARGET_ROOT = pathlib.Path("/data-1/xinweimao/code/difftrace/demo/target")


def demo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def default_demo_target_root() -> pathlib.Path:
    override = os.environ.get("DIFFTRACE_DEMO_TARGET_ROOT")
    if override:
        return pathlib.Path(override).expanduser().resolve()
    if PREFERRED_DEMO_TARGET_ROOT.parent.exists():
        return PREFERRED_DEMO_TARGET_ROOT
    return demo_root() / "target"
