"""Normalize the supported node architecture for execution and environment cache keys."""
import platform


def runtime_architecture(machine=None):
    value = (platform.machine() if machine is None else machine).strip().lower()
    aliases = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}
    try:
        return aliases[value]
    except KeyError:
        raise ValueError('UNSUPPORTED_NODE_ARCHITECTURE') from None


def runtime_platform(machine=None):
    return 'linux/' + runtime_architecture(machine)
