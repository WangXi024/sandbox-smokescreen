"""Lossless opt-in command output over the fixed SDK's text-only SSE channel."""

import base64
import binascii

OUTPUT_HEADER = "X-LazyX-Command-Output"
OUTPUT_ENCODING = "base64-v1"
MAX_OUTPUT_CHUNK = 64 * 1024
MAX_ENCODED_CHUNK = 4 * ((MAX_OUTPUT_CHUNK + 2) // 3)


class WorkspaceOutputEncodingError(RuntimeError):
    def __init__(self):
        super().__init__("WORKSPACE_OUTPUT_TRANSPORT_INVALID")


async def require_output_encoding(response):
    request = response.request
    if (request.method == "POST" and request.url.path.rstrip("/").endswith("/command") and 200 <= response.status_code < 300
            and (response.status_code != 200 or request.headers.get(OUTPUT_HEADER) != OUTPUT_ENCODING
                 or response.headers.get(OUTPUT_HEADER) != OUTPUT_ENCODING)):
        # Response hooks precede SSE iteration. Never let an old server's user
        # stdout masquerade as base64, including a string that happens to decode.
        await response.aclose()
        raise WorkspaceOutputEncodingError()


def workspace_connection(connection):
    """Clone only public configuration, retaining transport ownership semantics."""
    headers = dict(connection.headers)
    headers[OUTPUT_HEADER] = OUTPUT_ENCODING
    hooks = {name: list(items) for name, items in connection.event_hooks.items()}
    hooks["response"] = [require_output_encoding, *hooks.get("response", [])]
    return connection.model_copy(update={"headers": headers, "event_hooks": hooks})


def decode_output(text):
    if not isinstance(text, str) or not text.isascii() or len(text) > MAX_ENCODED_CHUNK:
        raise WorkspaceOutputEncodingError()
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise WorkspaceOutputEncodingError() from None
    if len(data) > MAX_OUTPUT_CHUNK or base64.b64encode(data).decode("ascii") != text:
        raise WorkspaceOutputEncodingError()
    return data
