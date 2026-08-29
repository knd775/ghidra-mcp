"""The FastMCP server singleton and its initialization-options patch."""

import json
import traceback

from mcp.server.fastmcp import FastMCP, Context  # noqa: F401  (Context re-exported)
from mcp.server.fastmcp.tools.tool_manager import ToolManager
from mcp.server.lowlevel.server import NotificationOptions
from mcp.types import TextContent

# `state` imports only from `config`, so this cannot cycle back through here.
from . import state as _state
from .config import logger

# The MCP server singleton. All static and dynamically registered tools attach
# to this object.
mcp = FastMCP("ghidra-mcp")

# Enable tools/list_changed notifications so clients re-fetch tools after
# dynamic registration.
_orig_init_options = mcp._mcp_server.create_initialization_options


def _patched_init_options(**kwargs):
    return _orig_init_options(
        notification_options=NotificationOptions(tools_changed=True), **kwargs
    )


mcp._mcp_server.create_initialization_options = _patched_init_options


# Capture the client's session the first time it lists tools.
#
# Enabling the tools_changed capability above is only half of it: something has
# to hold a reference to the session so a background thread can actually send
# the notification. That reference used to be captured only inside
# connect_instance/load_tool_group/unload_tool_group/import_file, i.e. only
# after the client called one of those tools -- which it never does when the
# tools it wants are the ones still missing. tools/list is the one request
# every MCP client issues right after initialize, so capturing here guarantees
# a target exists before the auto-connect retry thread can succeed.
_orig_list_tools = mcp.list_tools


async def _list_tools_capturing_session():
    try:
        # Set by the low-level server for every request, including this one.
        _state.remember_tools_changed_session(mcp._mcp_server.request_context.session)
    except (LookupError, AttributeError):
        # No active request context (direct call, e.g. from a test) -- nothing
        # to capture, and listing tools must not fail because of it.
        pass
    return await _orig_list_tools()


mcp.list_tools = _list_tools_capturing_session
mcp._mcp_server.list_tools()(_list_tools_capturing_session)


def format_tool_exception(exc: BaseException, tool: str) -> dict:
    """Structured error payload for a failed tool call.

    FastMCP/MCP convert uncaught exceptions into JSON-RPC ``-32603 Internal
    Error`` with ``data: null``. Putting type, message, and traceback here
    (and returning them as tool content) is what makes a bridge-side failure
    diagnosable — BSim ingest's first-use crash was otherwise a blank 32603.
    """
    cause = exc.__cause__
    payload: dict = {
        "error": f"{type(exc).__name__}: {exc}",
        "type": type(exc).__name__,
        "message": str(exc),
        "tool": tool,
        "traceback": traceback.format_exc(),
    }
    if cause is not None:
        payload["cause_type"] = type(cause).__name__
        payload["cause"] = str(cause)
    return payload


def format_tool_exception_json(exc: BaseException, tool: str) -> str:
    return json.dumps(format_tool_exception(exc, tool))


_orig_tool_manager_call = ToolManager.call_tool


async def _call_tool_never_raises(self, name, arguments, context=None, convert_result=False):
    """Catch FastMCP/Pydantic failures that happen before the tool body runs."""
    try:
        return await _orig_tool_manager_call(
            self, name, arguments, context=context, convert_result=convert_result
        )
    except Exception as e:
        logger.exception("Tool %s failed", name)
        text = format_tool_exception_json(e, name)
        return [TextContent(type="text", text=text)]


ToolManager.call_tool = _call_tool_never_raises
