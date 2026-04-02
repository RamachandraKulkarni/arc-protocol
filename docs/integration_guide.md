# Integration Guide

ARC supports three integration patterns. Choose the one that matches your deployment.

## Pattern 1: SDK Decorator (@signed_tool)

The @signed_tool decorator wraps any Python function. Five lines of setup.

**Setup:**

```python
from arc import ARCContext, ARCKeyPair, ARCLogClient, SnapshotStore

ctx = ARCContext(
    agent_id="my-agent",
    model_version="my-model-v1",
    session_id="session-001",
    provider_keypair=ARCKeyPair.generate(),
    provider_name="my-tools-v1",
    log=ARCLogClient(base_url="http://localhost:8080"),
    snapshot_store=SnapshotStore(),
    on_behalf_of="user:alice@example.com",
)
```

**Wrap any function:**

```python
from arc import signed_tool

@signed_tool(resource="filesystem", resource_uri_from_args="path")
def delete_file(path: str, ctx: ARCContext) -> dict:
    import os
    os.remove(path)
    return {"deleted": path}

receipt = delete_file("/tmp/data.txt", ctx=ctx)
```

**Async functions:**

```python
@signed_tool(resource="api", resource_uri_from_args="url")
async def fetch_data(url: str, ctx: ARCContext) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        return resp.json()

receipt = await fetch_data("https://api.example.com/data", ctx=ctx)
```

**Supported resource types:**

| Value | Before-state captured | is_reversible |
|-------|-----------------------|---------------|
| filesystem | File or directory contents, recursively | True |
| dict | Deep copy of the in-memory dict | True |
| api | API response body (read before write) | False |
| custom | Caller provides snapshot manually | Caller-defined |

**Decorator parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| resource | string | required | One of: filesystem, dict, api, custom |
| resource_uri_from_args | string | None | Name of the function argument that contains the resource URI or path |
| rollback_valid_minutes | integer | 60 | How long the inverse operation remains valid |
| capture_args | list of strings | None | Additional argument names to include in snapshot context |

### LangChain Integration

Wrap any LangChain tool with @signed_tool:

```python
from langchain.tools import tool
from arc import signed_tool, ARCContext

@tool
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def read_file_tool(path: str, ctx: ARCContext) -> str:
    with open(path) as f:
        return f.read()
```

Wrap an existing BaseTool subclass:

```python
from langchain.tools import BaseTool
from arc import signed_tool, ARCContext

class SignedReadFileTool(BaseTool):
    name = "read_file"
    description = "Read a file and return its contents"

    def _run(self, path: str) -> str:
        return self._arc_wrapped_run(path)

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def _arc_wrapped_run(self, path: str, ctx: ARCContext) -> str:
        with open(path) as f:
            return f.read()
```

Pass the ARCContext via the tool's metadata or through your agent executor's shared context object.

### OpenAI Agents SDK Integration

```python
from openai import OpenAI
from agents import function_tool
from arc import signed_tool, ARCContext, ARCKeyPair, ARCInMemoryLog, SnapshotStore

ctx = ARCContext(
    agent_id="openai-agent",
    model_version="gpt-4o",
    session_id="session-001",
    provider_keypair=ARCKeyPair.generate(),
    provider_name="my-tools-v1",
    log=ARCInMemoryLog(),
    snapshot_store=SnapshotStore(),
)

@function_tool
@signed_tool(resource="dict", resource_uri_from_args="key")
def update_state(key: str, value: str, ctx: ARCContext) -> dict:
    # tool logic here
    return {"key": key, "value": value}
```

The @signed_tool decorator wraps the function before @function_tool sees it. The ctx argument is consumed by the decorator and not passed to the OpenAI SDK.

### CrewAI Integration

```python
from crewai.tools import BaseTool
from arc import signed_tool, ARCContext

class SignedFileTool(BaseTool):
    name: str = "write_file"
    description: str = "Write content to a file"
    arc_ctx: ARCContext

    def _run(self, path: str, content: str) -> str:
        receipt = self._arc_write(path, content, ctx=self.arc_ctx)
        return f"Written. Receipt: {receipt['receipt_id']}"

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def _arc_write(self, path: str, content: str, ctx: ARCContext) -> dict:
        with open(path, "w") as f:
            f.write(content)
        return {"path": path, "bytes": len(content)}
```

---

## Pattern 2: HTTP Proxy (Zero-Code)

Replace your tool endpoint URL with the ARC proxy URL. The proxy intercepts all tool calls, wraps them with ARC receipts, and forwards to the original endpoint. The agent does not need to know ARC exists.

**Start the proxy:**

```bash
python -m arc.proxy \
    --target http://tool-provider.internal:9000 \
    --port 7999 \
    --log-url http://localhost:8080 \
    --provider-key-file /etc/arc/provider.key
```

**Configure the agent:** Change only the tool endpoint URL.

```python
# Before:
client.tools.endpoint = "http://tool-provider.internal:9000"

# After:
client.tools.endpoint = "http://localhost:7999"
```

All tool calls through the proxy will have receipts committed to the log automatically.

**Provider key file format:**

```
# /etc/arc/provider.key
# One line: 64 hex characters (Ed25519 private key)
a1b2c3d4e5f6...64hexchars
```

**When to use this pattern:**
- You cannot modify the agent code.
- You are using a third-party tool provider and want ARC receipts without changes to the provider.
- You want ARC receipts for all tool calls without modifying individual functions.

---

## Pattern 3: Kubernetes Sidecar

Deploy the ARC proxy as a sidecar container in the same pod as the agent. The sidecar intercepts all traffic from the agent pod to tool services.

**Kubernetes pod spec:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-agent
spec:
  containers:
    - name: agent
      image: my-agent:latest
      env:
        - name: TOOLS_URL
          value: http://localhost:7999  # sidecar proxy
    - name: arc-proxy
      image: arc-protocol/proxy:1.0.0
      env:
        - name: ARC_TARGET_URL
          value: http://tool-provider.internal:9000
        - name: ARC_LOG_URL
          value: http://arc-log-server:8080
        - name: ARC_PROVIDER_KEY_FILE
          value: /etc/arc/provider.key
      volumeMounts:
        - name: provider-key
          mountPath: /etc/arc
          readOnly: true
  volumes:
    - name: provider-key
      secret:
        secretName: arc-provider-key
```

**Create the provider key secret:**

```bash
# Generate a keypair
python -c "from arc import ARCKeyPair; kp = ARCKeyPair.generate(); print(kp.private_key_hex)" > provider.key

# Store in Kubernetes
kubectl create secret generic arc-provider-key \
    --from-file=provider.key=./provider.key
```

**When to use this pattern:**
- You are running agents in Kubernetes and want ARC receipts without application-level changes.
- You want to enforce ARC receipts at the infrastructure layer as an organizational policy.
- You have multiple agent services and want consistent receipt coverage across all of them.

---

## MCP (Model Context Protocol) Integration

ARC wraps MCP tool calls by intercepting at the JSON-RPC layer.

```python
from arc import signed_tool, ARCContext
from mcp import ClientSession

class ARCMCPWrapper:
    def __init__(self, session: ClientSession, ctx: ARCContext):
        self.session = session
        self.ctx = ctx

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        @signed_tool(resource="custom")
        async def _wrapped(tool_name: str, arguments: dict, ctx: ARCContext) -> dict:
            result = await self.session.call_tool(tool_name, arguments)
            return {"content": result.content, "isError": result.isError}

        return await _wrapped(tool_name, arguments, ctx=self.ctx)
```

Usage:

```python
from mcp import ClientSession, StdioServerParameters

async def main():
    server_params = StdioServerParameters(command="python", args=["-m", "my_mcp_server"])
    async with ClientSession(server_params) as session:
        arc_wrapper = ARCMCPWrapper(session, ctx)
        result = await arc_wrapper.call_tool("read_file", {"path": "/tmp/data.txt"})
        # result contains the full ActionReceipt
```

This produces a receipt for every MCP tool call. The before-state is captured from the arguments because the MCP protocol does not expose resource state before execution.

---

## Multi-Agent Delegation

When one agent spawns another agent and the child agent takes an action, link the receipts using parent_receipt_id and delegation_chain.

```python
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def child_action(path: str, ctx: ARCContext) -> dict:
    import shutil
    shutil.rmtree(path)
    return {"deleted": path}

# Set up child context with parent receipt reference
child_ctx = ARCContext(
    agent_id="child-agent",
    model_version="my-model-v1",
    session_id="child-session-001",
    provider_keypair=provider_kp,
    provider_name="my-tools-v1",
    log=log,
    snapshot_store=store,
)

# Pass parent receipt ID so the child receipt chains back to the parent
receipt = child_action(
    path="/tmp/data",
    ctx=child_ctx,
    parent_receipt_id="arc_01JTXM9KP3F...",      # ID of parent agent's receipt
    authorization_scope=["files:delete"],
    delegation_chain=["parent-agent", "child-agent"],
)
```

The resulting receipt includes phase_1.intent.authorization.parent_receipt_id and phase_1.intent.authorization.delegation_chain. Auditors can reconstruct the full delegation graph by following parent_receipt_id chains.

---

## Choosing Between Patterns

| Pattern | Code Changes Required | ARC Receipt Coverage | Best For |
|---------|----------------------|---------------------|----------|
| @signed_tool decorator | Wrap each function | Per-function | New tools, existing Python functions |
| HTTP proxy | Change endpoint URL only | All calls through proxy | Existing agents, third-party tools |
| Kubernetes sidecar | None | All pod traffic | Kubernetes deployments, multi-agent organizations |
| MCP wrapper | Wrap MCP session | All MCP tool calls | Claude-based agents using MCP |

---

## Rollback After Integration

For any pattern, rollback uses the snapshot stored at Phase 1:

```python
from arc import rollback_filesystem

# Retrieve the snapshot reference from the receipt
snapshot_ref = receipt["phase_1"]["before_state"]["snapshot_ref"]

# Retrieve the snapshot from the store
snap = ctx.snapshot_store.retrieve(snapshot_ref)

# Check rollback is still valid
from datetime import datetime, timezone
valid_until = receipt["phase_2"]["inverse"]["valid_until"]
if datetime.now(timezone.utc).isoformat() < valid_until:
    success = rollback_filesystem(snap)
    print(f"Rollback succeeded: {success}")
else:
    print("Rollback window has expired")
```

For dict resources, use rollback_dict:

```python
from arc import rollback_dict

snap = ctx.snapshot_store.retrieve(snapshot_ref)
success = rollback_dict(snap, target_dict)
```

Rollback is only available for resource types where is_reversible=True. API calls (resource="api") are not reversible by default because ARC cannot undo side effects on external systems.
