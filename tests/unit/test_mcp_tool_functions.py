"""
Unit tests for MCP dynamic tool function generation.

Tests _build_tool_function behavior for various schema patterns,
verifying that dynamically generated functions correctly dispatch
GET/POST requests with proper parameter handling.
"""

import asyncio
import json
import inspect
import os
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def setUpModule():
    """Force strict mode off for tests that don't manage it explicitly.

    The bridge reads GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS at import (via
    bridge_mcp_ghidra.state._init_require_selectors()). If the variable happens
    to be set in the surrounding shell or CI, that import would flip
    state._require_selectors=True and leak into tests that assume the default
    off state (i.e. every test outside TestProgramRequired). Clamp the module
    state here so the suite is deterministic regardless of the environment;
    TestProgramRequired manages its own state via setUp/tearDown.
    """
    import bridge_mcp_ghidra

    bridge_mcp_ghidra.state._require_selectors = False


class TestGetToolDispatch(unittest.TestCase):
    """Test that GET tool functions dispatch correctly."""

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_with_required_param(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = '{"result": "ok"}'

        schema = {
            "properties": {"address": {"type": "string"}},
            "required": ["address"],
        }
        fn = _build_tool_function("/decompile_function", "GET", schema)
        result = fn(address="0x401000")

        mock_get.assert_called_once_with("/decompile_function", params={"address": "0x401000"})
        self.assertEqual(result, '{"result": "ok"}')

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_with_optional_param_none(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = '{"data": []}'

        schema = {
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
            },
            "required": [],
        }
        fn = _build_tool_function("/list_functions", "GET", schema)
        result = fn(offset=None, limit=None)

        # None values should be filtered out
        mock_get.assert_called_once_with("/list_functions", params=None)

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_with_no_params(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = '{"version": "4.2.0"}'

        schema = {"properties": {}, "required": []}
        fn = _build_tool_function("/get_version", "GET", schema)
        result = fn()

        mock_get.assert_called_once_with("/get_version", params=None)


class TestPostToolDispatch(unittest.TestCase):
    """Test that POST tool functions dispatch correctly."""

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_post_with_json_body(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["address", "name"],
        }
        fn = _build_tool_function("/rename_function", "POST", schema)
        result = fn(address="0x401000", name="main")

        mock_post.assert_called_once_with(
            "/rename_function", data={"address": "0x401000", "name": "main"}, query_params=None
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_post_filters_none_values(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "program": {"type": "string"},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/rename_function", "POST", schema)
        fn(address="0x401000", program=None)

        mock_post.assert_called_once_with("/rename_function", data={"address": "0x401000"}, query_params=None)

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_post_integer_params(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"data": []}'

        schema = {
            "properties": {
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
            },
            "required": ["offset", "limit"],
        }
        fn = _build_tool_function("/search", "POST", schema)
        fn(offset=0, limit=50)

        # POST sends native types, not strings
        mock_post.assert_called_once_with("/search", data={"offset": 0, "limit": 50}, query_params=None)

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_post_synthetic_dry_run_only_for_true_values(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["address", "name"],
        }
        fn = _build_tool_function("/rename_function", "POST", schema)

        fn(address="0x401000", name="main", dry_run="false")
        mock_post.assert_called_once_with(
            "/rename_function",
            data={"address": "0x401000", "name": "main"},
            query_params=None,
        )

        mock_post.reset_mock()
        fn(address="0x401000", name="main", dry_run=True)
        mock_post.assert_called_once_with(
            "/rename_function",
            data={"address": "0x401000", "name": "main"},
            query_params={"dry_run": "true"},
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_bsim_create_db_synthetic_dry_run_goes_as_query_param(self, mock_post):
        """bsim_create_db does not declare dry_run; the bridge must still send it
        so AnnotationScanner can short-circuit before createdatabase runs."""
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"status":"would_execute","dry_run":true}'
        schema = {
            "properties": {
                "db_url": {"type": "string", "source": "body"},
                "config_template": {"type": "string", "source": "body", "default": "medium_nosize"},
            },
            "required": ["db_url"],
        }
        fn = _build_tool_function("/bsim_create_db", "POST", schema)
        fn(db_url="file:/srv/ghidra/bsim/re", dry_run=True)
        mock_post.assert_called_once_with(
            "/bsim_create_db",
            data={"db_url": "file:/srv/ghidra/bsim/re"},
            query_params={"dry_run": "true"},
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_schema_declared_query_dry_run_does_not_duplicate_signature(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"dry_run": true}'

        schema = {
            "properties": {
                "program": {"type": "string", "source": "query", "default": ""},
                "dry_run": {
                    "type": "boolean",
                    "source": "query",
                    "default": "false",
                },
            },
            "required": [],
        }
        fn = _build_tool_function("/archive_ingest_program", "POST", schema)
        sig = inspect.signature(fn)

        self.assertEqual(list(sig.parameters).count("dry_run"), 1)

        fn(program="pwahelper.exe", dry_run="false")
        mock_post.assert_called_once_with(
            "/archive_ingest_program",
            data={},
            query_params={"program": "pwahelper.exe", "dry_run": "false"},
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_schema_declared_body_dry_run_uses_body_source(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"dry_run": true}'

        schema = {
            "properties": {
                "source": {"type": "string", "source": "body"},
                "target": {"type": "string", "source": "body"},
                "dry_run": {
                    "type": "boolean",
                    "source": "body",
                    "default": "false",
                },
            },
            "required": ["source", "target"],
        }
        fn = _build_tool_function("/merge_program_documentation", "POST", schema)
        sig = inspect.signature(fn)

        self.assertEqual(list(sig.parameters).count("dry_run"), 1)

        fn(source="recovered", target="original", dry_run=True)
        mock_post.assert_called_once_with(
            "/merge_program_documentation",
            data={"source": "recovered", "target": "original", "dry_run": True},
            query_params=None,
        )


class TestSchemaEdgeCases(unittest.TestCase):
    """Test edge cases in schema parsing."""

    def test_unknown_type_defaults_to_string(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"data": {"type": "unknown_type"}},
            "required": ["data"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        self.assertEqual(fn.__annotations__["data"], str)

    def test_missing_type_defaults_to_string(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"data": {}},
            "required": ["data"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        self.assertEqual(fn.__annotations__["data"], str)

    def test_missing_required_field(self):
        """Schema without 'required' field should treat all as optional."""
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"data": {"type": "string"}},
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["data"].default)

    def test_many_parameters(self):
        """Schema with many parameters should work."""
        from bridge_mcp_ghidra import _build_tool_function

        props = {f"param_{i}": {"type": "string"} for i in range(20)}
        schema = {"properties": props, "required": ["param_0"]}
        fn = _build_tool_function("/test", "POST", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 21)
        self.assertIn("dry_run", sig.parameters)


class TestToolRegistrationRoundTrip(unittest.TestCase):
    """Test full schema → registration → dispatch round trip."""

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_full_roundtrip(self, mock_get):
        from bridge_mcp_ghidra import register_tools_from_schema, mcp

        mock_get.return_value = '{"functions": []}'

        schema = [
            {
                "name": "roundtrip_test_tool",
                "description": "Test decompilation",
                "endpoint": "/roundtrip_test",
                "http_method": "GET",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address"},
                    },
                    "required": ["address"],
                },
            },
        ]
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 1)

        # The tool should be registered in the MCP server
        tools = mcp._tool_manager._tools
        self.assertIn("roundtrip_test_tool", tools)

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_registered_tool_offloads_blocking_dispatch(self, mock_get):
        from bridge_mcp_ghidra import mcp, register_tools_from_schema

        started = threading.Event()
        release = threading.Event()

        def blocking_get(endpoint, params=None):
            started.set()
            if not release.wait(1):
                raise AssertionError("blocking dispatch ran on the MCP event loop")
            return '{"ok": true}'

        mock_get.side_effect = blocking_get
        schema = [
            {
                "name": "async_dispatch_test_tool",
                "description": "Test worker offload",
                "endpoint": "/async_dispatch_test",
                "http_method": "GET",
                "input_schema": {
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                    "required": ["address"],
                },
            }
        ]

        try:
            register_tools_from_schema(schema)
            tool = mcp._tool_manager._tools["async_dispatch_test_tool"]
            self.assertTrue(tool.is_async)
            self.assertTrue(inspect.iscoroutinefunction(tool.fn))

            async def run_tool():
                task = asyncio.create_task(tool.fn(address="0x401000"))
                for _ in range(100):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(started.is_set())
                release.set()
                return await task

            self.assertEqual(asyncio.run(run_tool()), '{"ok": true}')
        finally:
            release.set()
            register_tools_from_schema([])


class TestProgramRequired(unittest.TestCase):
    """GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS: refuse calls missing a program selector."""

    def setUp(self):
        import bridge_mcp_ghidra as bridge

        self.bridge = bridge
        self._saved = bridge.state._require_selectors

    def tearDown(self):
        self.bridge.state._require_selectors = self._saved

    _OPTIONAL_PROGRAM_TOOL = {
        "properties": {
            "address": {"type": "string"},
            "program": {"type": "string", "source": "query"},
        },
        "required": ["address"],
    }

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_refuses_when_program_omitted(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        result = fn(address="0x401000")

        mock_get.assert_not_called()
        data = json.loads(result)
        self.assertIn("error", data)
        self.assertIn("program=", data["error"])
        self.assertIn("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS", data["error"])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_allows_explicit_program(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        fn(address="0x401000", program="game.exe")

        mock_get.assert_called_once_with(
            "/decompile_function",
            params={"address": "0x401000", "program": "game.exe"},
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_pass_through_when_strict_mode_disabled(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = False

        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        fn(address="0x401000")

        mock_get.assert_called_once_with("/decompile_function", params={"address": "0x401000"})

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_no_refusal_for_tools_without_program_param(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = True

        # Some tools have no program= selector at all.
        schema = {"properties": {"address": {"type": "string"}}, "required": ["address"]}
        fn = _build_tool_function("/some_tool", "GET", schema)
        fn(address="0x401000")

        mock_get.assert_called_once_with("/some_tool", params={"address": "0x401000"})

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_empty_program_counts_as_omitted(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        self.bridge.state._require_selectors = True

        # An empty string is filtered upstream of the strict check, so the
        # check should treat it as a missing program=.
        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        result = fn(address="0x401000", program="")

        mock_get.assert_not_called()
        self.assertIn("error", json.loads(result))

    # Cross-program tools (diff_functions, bulk_fuzzy_match,
    # find_similar_functions_fuzzy) take source_program/target_program or
    # program_a/program_b. These are schema-required, yet the server falls back
    # to the current program when one arrives empty (getProgramOrError), so
    # strict mode enforces them regardless of the required flag. The tests pass
    # empty strings to mirror that path: the bridge filter drops "" so the
    # selector is absent in `filtered` and the call is refused.

    _FUZZY_SCHEMA = {
        "properties": {
            "address": {"type": "string"},
            "source_program": {"type": "string", "source": "query"},
            "target_program": {"type": "string", "source": "query"},
        },
        "required": ["address", "source_program", "target_program"],
    }
    _DIFF_SCHEMA = {
        "properties": {
            "address_a": {"type": "string"},
            "address_b": {"type": "string"},
            "program_a": {"type": "string", "source": "query"},
            "program_b": {"type": "string", "source": "query"},
        },
        "required": ["address_a", "address_b", "program_a", "program_b"],
    }

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_multi_program_refuses_when_both_selectors_empty(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/bulk_fuzzy_match", "GET", self._FUZZY_SCHEMA)
        result = fn(address="0x401000", source_program="", target_program="")

        mock_get.assert_not_called()
        data = json.loads(result)
        self.assertIn("source_program=", data["error"])
        self.assertIn("target_program=", data["error"])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_multi_program_refuses_when_one_selector_empty(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/bulk_fuzzy_match", "GET", self._FUZZY_SCHEMA)
        result = fn(address="0x401000", source_program="game.exe", target_program="")

        mock_get.assert_not_called()
        data = json.loads(result)
        # Only the missing one is named.
        self.assertIn("target_program=", data["error"])
        self.assertNotIn("source_program=", data["error"])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_multi_program_allows_when_all_present(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function

        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/bulk_fuzzy_match", "GET", self._FUZZY_SCHEMA)
        fn(address="0x401000", source_program="game.exe", target_program="test.dll")

        mock_get.assert_called_once_with(
            "/bulk_fuzzy_match",
            params={
                "address": "0x401000",
                "source_program": "game.exe",
                "target_program": "test.dll",
            },
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_program_a_b_pattern_enforced(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function

        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/diff_functions", "POST", self._DIFF_SCHEMA)
        result = fn(address_a="0x401000", address_b="0x402000", program_a="", program_b="")

        mock_post.assert_not_called()
        data = json.loads(result)
        self.assertIn("program_a=", data["error"])
        self.assertIn("program_b=", data["error"])

    def test_init_value_1_enables_strict_mode(self):
        for val in ("1", " 1 "):  # only "1" (surrounding whitespace tolerated)
            self.bridge.state._require_selectors = False
            with patch.dict("os.environ", {"GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": val}):
                # assertLogs captures the enable-time INFO line (keeping it out
                # of test output) and doubles as an assertion that it fires.
                with self.assertLogs("bridge_mcp_ghidra", level="INFO"):
                    self.bridge.state._init_require_selectors()
            self.assertTrue(self.bridge.state._require_selectors, f"{val!r} should enable strict mode")

    def test_init_non_1_values_leave_strict_mode_off(self):
        # Only "1" enables; other spellings (true/yes/on) and falsy values don't.
        for val in ("true", "yes", "on", "TRUE", "0", "2", "", "anything"):
            self.bridge.state._require_selectors = True
            with patch.dict("os.environ", {"GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": val}):
                self.bridge.state._init_require_selectors()
            self.assertFalse(self.bridge.state._require_selectors, f"{val!r} should not enable strict mode")

    def test_init_unset_env_leaves_strict_mode_off(self):
        self.bridge.state._require_selectors = True
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS"}
        with patch.dict("os.environ", env, clear=True):
            self.bridge.state._init_require_selectors()
        self.assertFalse(self.bridge.state._require_selectors)

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_bsim_ingest_program_is_not_a_required_selector(self, mock_post):
        """bsim_ingest's target is `source` (a ghidraURL). Strict mode must not
        demand program= — that blocked every ingest before the Java server saw it.
        """
        from bridge_mcp_ghidra import _build_tool_function

        mock_post.return_value = '{"status":"success"}'
        self.bridge.state._require_selectors = True
        schema = {
            "properties": {
                "db_url": {"type": "string", "source": "body"},
                "source": {"type": "string", "source": "body"},
                "program": {
                    "type": "string",
                    "source": "query",
                    "default": "",
                    "selector": False,
                },
            },
            "required": ["db_url", "source"],
        }
        fn = _build_tool_function("/bsim_ingest", "POST", schema)
        result = fn(
            db_url="file:/srv/ghidra/bsim/re",
            source="ghidra://172.16.1.104/general/5n4ck3y/nullcog-v2",
        )
        mock_post.assert_called_once()
        self.assertNotIn("error", json.loads(result) if result.startswith("{") else {})

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_import_data_types_program_still_required_in_strict_mode(self, mock_post):
        """A `source` that is C text is not a program identifier; program= stays required."""
        from bridge_mcp_ghidra import _build_tool_function

        self.bridge.state._require_selectors = True
        schema = {
            "properties": {
                "source": {"type": "string", "source": "body"},
                "program": {"type": "string", "source": "query", "default": ""},
            },
            "required": ["source"],
        }
        fn = _build_tool_function("/import_data_types", "POST", schema)
        result = fn(source="struct Foo { int a; };")
        mock_post.assert_not_called()
        data = json.loads(result)
        self.assertIn("program=", data["error"])


class TestToolExceptionPayload(unittest.TestCase):
    def test_format_includes_type_message_traceback(self):
        from bridge_mcp_ghidra.server import format_tool_exception

        try:
            raise ValueError("nope")
        except ValueError as exc:
            payload = format_tool_exception(exc, "/bsim_ingest")
        self.assertEqual(payload["type"], "ValueError")
        self.assertIn("nope", payload["message"])
        self.assertIn("ValueError", payload["traceback"])
        self.assertEqual(payload["tool"], "/bsim_ingest")
        self.assertIn("ValueError: nope", payload["error"])

    @patch("bridge_mcp_ghidra.registry._dispatch_tool_call", side_effect=NameError("x"))
    def test_handler_returns_exception_payload_instead_of_raising(self, _mock_dispatch):
        from bridge_mcp_ghidra import _build_tool_function

        fn = _build_tool_function(
            "/bsim_ingest",
            "POST",
            {
                "properties": {
                    "db_url": {"type": "string"},
                    "source": {"type": "string"},
                },
                "required": ["db_url", "source"],
            },
        )
        result = json.loads(fn(db_url="file:/x", source="ghidra://h/r/p"))
        self.assertEqual(result["type"], "NameError")
        self.assertIn("x", result["message"])
        self.assertIn("traceback", result)
        self.assertIn("NameError", result["error"])


class TestSlowToolWarning(unittest.TestCase):
    """Calls that outlive the gateway budget must leave bridge-side evidence.

    Upstream MCP gateways/tunnels abandon responses around 60-100s and
    fabricate a bare -32603 with data: null; neither container logs anything
    unless the bridge notes the slow call itself. That silence is how
    bsim_ingest cost two debugging rounds.
    """

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_slow_call_logs_gateway_budget_warning(self, mock_get):
        from bridge_mcp_ghidra import mcp, register_tools_from_schema
        import bridge_mcp_ghidra.registry as registry

        mock_get.return_value = '{"ok": true}'
        schema = [
            {
                "name": "slow_warning_test_tool",
                "description": "Test slow-call warning",
                "endpoint": "/slow_warning_test",
                "http_method": "GET",
                "input_schema": {
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                    "required": ["address"],
                },
            }
        ]
        original = registry.SLOW_TOOL_WARN_SECONDS
        try:
            register_tools_from_schema(schema)
            tool = mcp._tool_manager._tools["slow_warning_test_tool"]
            registry.SLOW_TOOL_WARN_SECONDS = 0
            with self.assertLogs("bridge_mcp_ghidra", level="WARNING") as logs:
                result = asyncio.run(tool.fn(address="0x401000"))
            self.assertEqual(result, '{"ok": true}')
            joined = "\n".join(logs.output)
            self.assertIn("slow_warning_test_tool", joined)
            self.assertIn("-32603", joined)
        finally:
            registry.SLOW_TOOL_WARN_SECONDS = original
            register_tools_from_schema([])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_fast_call_does_not_warn(self, mock_get):
        from bridge_mcp_ghidra import mcp, register_tools_from_schema
        import bridge_mcp_ghidra.registry as registry

        mock_get.return_value = '{"ok": true}'
        schema = [
            {
                "name": "fast_no_warning_test_tool",
                "description": "Test fast-call silence",
                "endpoint": "/fast_no_warning_test",
                "http_method": "GET",
                "input_schema": {
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                    "required": ["address"],
                },
            }
        ]
        try:
            register_tools_from_schema(schema)
            tool = mcp._tool_manager._tools["fast_no_warning_test_tool"]
            with self.assertNoLogs("bridge_mcp_ghidra", level="WARNING"):
                result = asyncio.run(tool.fn(address="0x401000"))
            self.assertEqual(result, '{"ok": true}')
        finally:
            register_tools_from_schema([])


class TestSchemaDefaultCoercion(unittest.TestCase):
    def test_boolean_string_defaults_become_bool(self):
        from bridge_mcp_ghidra.schema import _parse_schema
        import inspect
        from bridge_mcp_ghidra import _build_tool_function

        parsed = _parse_schema(
            {
                "tools": [
                    {
                        "path": "/bsim_ingest",
                        "method": "POST",
                        "params": [
                            {"name": "db_url", "type": "string", "source": "body", "required": True},
                            {"name": "source", "type": "string", "source": "body", "required": True},
                            {
                                "name": "commit",
                                "type": "boolean",
                                "source": "body",
                                "required": False,
                                "default": "true",
                            },
                            {
                                "name": "overwrite",
                                "type": "boolean",
                                "source": "body",
                                "required": False,
                                "default": "false",
                            },
                            {
                                "name": "program",
                                "type": "string",
                                "source": "query",
                                "required": False,
                                "default": "",
                                "selector": False,
                            },
                        ],
                    }
                ]
            }
        )
        schema = parsed[0]["input_schema"]
        self.assertIs(schema["properties"]["commit"]["default"], True)
        self.assertIs(schema["properties"]["overwrite"]["default"], False)
        self.assertIs(schema["properties"]["program"]["selector"], False)
        fn = _build_tool_function("/bsim_ingest", "POST", schema)
        sig = inspect.signature(fn)
        self.assertIs(sig.parameters["commit"].default, True)
        self.assertIs(sig.parameters["overwrite"].default, False)


if __name__ == "__main__":
    unittest.main()
