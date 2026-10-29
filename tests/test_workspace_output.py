"""Fixed SDK + synthetic HTTP streams. No real sandbox or user-code execution."""

import base64
import json
import unittest
from unittest.mock import patch

import httpx
from opensandbox.adapters.command_adapter import CommandsAdapter
from opensandbox.config import ConnectionConfig
from opensandbox.models.execd import ExecutionHandlers
from opensandbox.models.sandboxes import SandboxEndpoint
from sandbox_model.workspace_output import (MAX_OUTPUT_CHUNK, OUTPUT_ENCODING, OUTPUT_HEADER,
    WorkspaceOutputEncodingError, decode_output, require_output_encoding, workspace_connection)


class Body(httpx.AsyncByteStream):
    def __init__(self, content):
        self.content, self.read, self.closed = content, False, False

    async def __aiter__(self):
        self.read = True
        yield self.content

    async def aclose(self):
        self.closed = True


def sse(kind, **values):
    return ("data: " + json.dumps({"type": kind, "timestamp": 1, **values}) + "\n\n").encode()


class WorkspaceOutputTests(unittest.IsolatedAsyncioTestCase):
    def test_lossless_every_byte_nul_newlines_and_legitimate_replacement_character(self):
        raw = bytes(range(256)) * 256 + b"\x00\r\n" + "合法的\ufffd字符".encode()
        encoded = [base64.b64encode(raw[index:index + MAX_OUTPUT_CHUNK]).decode() for index in range(0, len(raw), MAX_OUTPUT_CHUNK)]
        self.assertEqual(b"".join(map(decode_output, encoded)), raw)
        self.assertEqual(decode_output(base64.b64encode(b"\xff\xfe").decode()), b"\xff\xfe")
        self.assertEqual(decode_output(base64.b64encode("\ufffd".encode()).decode()), "\ufffd".encode())

    def test_decoding_fails_closed_without_text_fallback_or_oversized_chunks(self):
        for text in ("not!base64", "77+9\n", "AA=", "AB==", "\ufffd", base64.b64encode(b"x" * (MAX_OUTPUT_CHUNK + 1)).decode(), None):
            with self.subTest(kind=type(text).__name__, length=len(text) if isinstance(text, str) else None):
                with self.assertRaises(WorkspaceOutputEncodingError):
                    decode_output(text)

    async def test_clone_preserves_original_configuration_and_existing_hooks(self):
        seen = []
        async def old_hook(response):
            seen.append(response.status_code)
        transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
        with patch('opensandbox.config.client_ip.apply_client_ip'):
            original = ConnectionConfig(domain="control.invalid", headers={"Original": "unchanged"},
                event_hooks={"response": [old_hook]}, transport=transport)
        clone = workspace_connection(original)
        self.assertEqual(original.headers, {"Original": "unchanged"})
        self.assertEqual(original.event_hooks, {"response": [old_hook]})
        self.assertIs(clone.transport, original.transport)
        self.assertEqual(clone.owns_transport, original.owns_transport)
        self.assertEqual(clone.headers[OUTPUT_HEADER], OUTPUT_ENCODING)
        self.assertEqual(clone.event_hooks["response"], [require_output_encoding, old_hook])

    async def test_real_sdk_sse_callbacks_receive_exact_bytes_and_error_seven_unchanged(self):
        payload = bytes(range(256)) + b"\x00\r\n" + "\ufffd".encode()
        # Deliberately split a multibyte UTF-8 sequence. Individual raw chunks
        # need not be UTF-8; validation belongs after the full bytes are collected.
        slices = [payload[:-2], payload[-2:-1], payload[-1:]]
        stderr = b"stderr\x00\xff\n"
        events = sse("init", text="trusted-command-id")
        events += b"".join(sse("stdout", text=base64.b64encode(item).decode()) for item in slices)
        events += sse("stderr", text=base64.b64encode(stderr).decode())
        events += sse("error", error={"ename": "CommandExecutionError", "evalue": "7", "traceback": []})
        def response(request):
            self.assertEqual(request.headers.get(OUTPUT_HEADER), OUTPUT_ENCODING)
            return httpx.Response(200, headers={OUTPUT_HEADER: OUTPUT_ENCODING, "Content-Type": "text/event-stream"}, content=events)
        with patch('opensandbox.config.client_ip.apply_client_ip'):
            connection = workspace_connection(ConnectionConfig(domain="control.invalid", transport=httpx.MockTransport(response)))
        adapter = CommandsAdapter(connection, SandboxEndpoint(endpoint="execd.invalid:80"))
        outputs, errors, ids = [], [], []
        async def stdout(message): outputs.append(decode_output(message.text))
        async def error(message): errors.append(decode_output(message.text))
        async def initialized(value): ids.append(value.id)
        try:
            result = await adapter.run("synthetic-command-no-process", handlers=ExecutionHandlers(
                on_stdout=stdout, on_stderr=error, on_init=initialized, skip_accumulation=True))
            self.assertEqual(b"".join(outputs), payload)
            self.assertEqual(b"".join(errors), stderr)
            self.assertEqual(ids, ["trusted-command-id"])
            self.assertEqual(result.exit_code, 7)
        finally:
            # Adapter is tested directly; its public owner Sandbox.close normally closes these clients.
            await adapter._sse_client.aclose()
            await adapter._httpx_client.aclose()

    async def test_missing_or_unknown_ack_is_rejected_before_any_stream_body(self):
        for ack in (None, "unknown-v2"):
            # This is valid base64 chosen by a hypothetical old server's user program.
            # It still must never be accepted without a trusted response acknowledgement.
            body = Body(sse("stdout", text=base64.b64encode(b"spoofed").decode()))
            def response(request):
                headers = {"Content-Type": "text/event-stream"}
                if ack is not None: headers[OUTPUT_HEADER] = ack
                return httpx.Response(200, headers=headers, stream=body)
            with patch('opensandbox.config.client_ip.apply_client_ip'):
                connection = workspace_connection(ConnectionConfig(domain="control.invalid", transport=httpx.MockTransport(response)))
            adapter = CommandsAdapter(connection, SandboxEndpoint(endpoint="execd.invalid:80"))
            seen = []
            async def stdout(message): seen.append(message.text)
            try:
                with self.assertRaises(Exception):
                    await adapter.run("synthetic-no-execution", handlers=ExecutionHandlers(on_stdout=stdout))
                self.assertFalse(body.read)
                self.assertTrue(body.closed)
                self.assertEqual(seen, [])
            finally:
                await adapter._sse_client.aclose()
                await adapter._httpx_client.aclose()

    async def test_missing_or_changed_request_marker_also_fails_closed(self):
        for marker in (None, "changed-v2"):
            headers = {OUTPUT_HEADER: marker} if marker else {}
            body = Body(b"valid-looking-legacy-base64")
            response = httpx.Response(200, request=httpx.Request("POST", "http://execd.invalid/command", headers=headers),
                                      headers={OUTPUT_HEADER: OUTPUT_ENCODING}, stream=body)
            with self.assertRaises(WorkspaceOutputEncodingError):
                await require_output_encoding(response)
            self.assertTrue(body.closed)
            self.assertFalse(body.read)

    async def test_unexpected_success_status_cannot_bypass_ack_guard(self):
        for status in (201, 204, 206):
            body = Body(b"must not be read")
            response = httpx.Response(status, request=httpx.Request("POST", "http://execd.invalid/command",
                headers={OUTPUT_HEADER: OUTPUT_ENCODING}), headers={OUTPUT_HEADER: OUTPUT_ENCODING}, stream=body)
            with self.assertRaises(WorkspaceOutputEncodingError):
                await require_output_encoding(response)
            self.assertTrue(body.closed)
            self.assertFalse(body.read)

    async def test_plain_legacy_sdk_connection_keeps_text_without_installing_raw_hook(self):
        events = sse("init", text="legacy-command") + sse("stdout", text="legacy text\r\n") + sse("execution_complete", execution_time_in_millis=1)
        def response(request):
            self.assertNotIn(OUTPUT_HEADER, request.headers)
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, content=events)
        with patch('opensandbox.config.client_ip.apply_client_ip'):
            connection = ConnectionConfig(domain="control.invalid", transport=httpx.MockTransport(response))
        self.assertNotIn(require_output_encoding, connection.event_hooks.get("response", []))
        adapter = CommandsAdapter(connection, SandboxEndpoint(endpoint="execd.invalid:80"))
        output = []
        async def stdout(message): output.append(message.text)
        try:
            result = await adapter.run("synthetic-no-process", handlers=ExecutionHandlers(on_stdout=stdout))
            self.assertEqual(output, ["legacy text\r\n"])
            self.assertEqual(result.exit_code, 0)
        finally:
            await adapter._sse_client.aclose()
            await adapter._httpx_client.aclose()

    async def test_unrelated_responses_and_legacy_connections_are_not_changed(self):
        for method, path in (("GET", "/command/id/status"), ("POST", "/code"), ("POST", "/v1/sandboxes")):
            body = Body(b"ordinary response")
            response = httpx.Response(200, request=httpx.Request(method, "http://control.invalid" + path,
                headers={OUTPUT_HEADER: OUTPUT_ENCODING}), stream=body)
            await require_output_encoding(response)
            self.assertFalse(body.closed)
            await response.aclose()
