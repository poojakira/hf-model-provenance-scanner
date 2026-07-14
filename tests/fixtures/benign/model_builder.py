"""Benign model loader for the privacy-filter fixture.

Pure, side-effect-free model construction — no shell, no network, no eval.
Used to verify the scanner does not raise false positives on clean loaders.
"""
import json
import os


def load_config(model_dir: str) -> dict:
    with open(os.path.join(model_dir, "config.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def build_model(model_dir: str = "."):
    config = load_config(model_dir)
    return {"config": config, "weights": None}
