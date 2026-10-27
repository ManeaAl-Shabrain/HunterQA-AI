"""Compatibility only: pre-HunterQA scripts may still import zeroscope.

All functionality lives in the single hunterqa package.
"""
from hunterqa import create_app
__all__ = ["create_app"]
