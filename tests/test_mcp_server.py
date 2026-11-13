"""Unit tests for the Model Context Protocol (MCP) Server."""
import json
from secskill.mcp_server import SecSkillMCPServer

def test_mcp_initialize():
    server = SecSkillMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    resp = server.handle_request(req)
    assert resp["id"] == 1
    assert "result" in resp
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "secskill"

def test_mcp_tools_list():
    server = SecSkillMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    resp = server.handle_request(req)
    assert resp["id"] == 2
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "secskill_scan" in tool_names
    assert "secskill_scan_url" in tool_names
    assert "secskill_verify_patch" in tool_names
    assert "secskill_audit_agent" in tool_names
    assert "secskill_explain" in tool_names
    assert "secskill_attack_map" in tool_names

def test_mcp_tools_call_attack_map(tmp_path):
    server = SecSkillMCPServer()
    out_html = tmp_path / "test_attack_map.html"
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "secskill_attack_map",
            "arguments": {
                "path": str(tmp_path),
                "output": str(out_html)
            }
        }
    }
    resp = server.handle_request(req)
    assert resp["id"] == 5
    content = resp["result"]["content"][0]["text"]
    data = json.loads(content)
    assert data["status"] == "success"
    assert "file_uri" in data
    assert out_html.is_file()
    html_text = out_html.read_text(encoding="utf-8")
    assert "Interactive Attack Map" in html_text or "SecSkill Attack Path Visualizer" in html_text

def test_mcp_tools_call_explain():
    server = SecSkillMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "secskill_explain",
            "arguments": {"query": "CWE-89"}
        }
    }
    resp = server.handle_request(req)
    assert resp["id"] == 3
    content = resp["result"]["content"][0]["text"]
    data = json.loads(content)
    assert "SQL Injection" in data["cwe"]
    assert data["severity"] == "CRITICAL"

def test_mcp_ping():
    server = SecSkillMCPServer()
    req = {"jsonrpc": "2.0", "id": 4, "method": "ping"}
    resp = server.handle_request(req)
    assert resp["id"] == 4
    assert resp["result"] == {}

