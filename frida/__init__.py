"""Frida — a toolsmith for the terminal.

Describe a command-line tool. Frida agrees on the shape, writes it, runs it for
real, reads what went wrong, fixes it, and leaves the finished thing on your PATH
as a command you can type.

No GUI. No browser. No window anywhere in it.
"""

from .engine import __version__          # noqa: F401

__all__ = ["__version__"]
