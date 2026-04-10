/**
 * Forge MCP Server
 * Model Context Protocol endpoint for Claude Cowork and Claude Code.
 * Exposes forge_verify as an MCP tool that Claude can call before executing actions.
 *
 * Protocol: JSON-RPC 2.0 over HTTP
 * Auth: API key in request headers (X-Forge-Key)
 */

import { Router, Request, Response } from "express";
import { authenticateApiKey } from "./apiDb";
import { evaluateConstraints } from "./policyEngine";
import { compileFromYaml } from "./policyCompiler";
import { getPolicyByName } from "./apiDb";
import crypto from "crypto";

export const mcpRouter = Router();

// ─── MCP Tool Definitions ───

const FORGE_TOOLS = [
  {
    name: "forge_verify",
    description: "Verify an AI agent action against Forge policies before execution. Returns ALLOW or DENY with the reason.",
    inputSchema: {
      type: "object" as const,
      properties: {
        action: {
          type: "string",
          description: "The action being attempted (e.g., 'send_email', 'payment.create', 'file.delete')",
        },
        params: {
          type: "object",
          description: "Parameters of the action (e.g., { recipient: 'user@example.com', amount: 100 })",
        },
        policy: {
          type: "string",
          description: "Name of the policy to evaluate against. If omitted, uses the default policy.",
        },
        agent_id: {
          type: "string",
          description: "Identifier for the agent making the request.",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "forge_list_policies",
    description: "List all active policies for this API key.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
];

// ─── MCP Protocol Handler ───
// Supports both /mcp (key in headers) and /mcp/:apiKey (key in URL path for Claude Cowork connectors)

async function handleMcpRequest(req: Request, res: Response, urlApiKey?: string) {
  const body = req.body;

  // Validate JSON-RPC structure
  if (!body || body.jsonrpc !== "2.0" || !body.method) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Invalid JSON-RPC request" },
      id: body?.id ?? null,
    });
    return;
  }

  const { method, params, id } = body;

  // ─── Authentication ───
  // Check URL path key first, then headers
  const apiKeyRaw = urlApiKey || req.headers["x-forge-key"] as string || req.headers["authorization"]?.replace("Bearer ", "");
  let apiKey: any = null;

  if (apiKeyRaw) {
    const authResult = await authenticateApiKey(apiKeyRaw);
    if (authResult && !authResult.suspended && !authResult.revoked) {
      apiKey = authResult.key;
    }
  }

  // ─── Handle MCP Methods ───

  switch (method) {
    // Initialize handshake
    case "initialize": {
      res.json({
        jsonrpc: "2.0",
        result: {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: {},
          },
          serverInfo: {
            name: "forge-verification",
            version: "1.0.0",
          },
        },
        id,
      });
      return;
    }

    // List available tools
    case "tools/list": {
      res.json({
        jsonrpc: "2.0",
        result: {
          tools: FORGE_TOOLS,
        },
        id,
      });
      return;
    }

    // Execute a tool
    case "tools/call": {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};

      if (toolName === "forge_verify") {
        // Require authentication for verification
        if (!apiKey) {
          res.json({
            jsonrpc: "2.0",
            result: {
              content: [{
                type: "text",
                text: JSON.stringify({
                  verified: false,
                  error: "authentication_required",
                  message: "Valid Forge API key required. Get one at veritera.ai/register",
                }),
              }],
              isError: true,
            },
            id,
          });
          return;
        }

        const { action, params: actionParams, policy, agent_id } = toolArgs;

        if (agent_id && /[<>"'&]/.test(String(agent_id))) {
          res.json({
            jsonrpc: "2.0",
            result: {
              content: [{ type: "text", text: JSON.stringify({ error: "agent_id contains invalid characters" }) }],
              isError: true,
            },
            id,
          });
          return;
        }

        if (!action) {
          res.json({
            jsonrpc: "2.0",
            result: {
              content: [{ type: "text", text: JSON.stringify({ error: "action is required" }) }],
              isError: true,
            },
            id,
          });
          return;
        }

        // Evaluate against policy — entire block is fail-closed
        let verified = false;
        let reason: string | null = null;
        let evaluatedConstraints: any[] = [];
        const start = Date.now();

        try {
          if (policy) {
            // Load named policy
            const policyObj = await getPolicyByName(apiKey.id, policy);
            if (policyObj) {
              const constraints = Array.isArray(policyObj.rules) ? policyObj.rules : [];
              const evalResult = evaluateConstraints(action, actionParams || null, constraints as any);
              verified = evalResult.verdict === "approved";
              reason = evalResult.reason;
              evaluatedConstraints = evalResult.evaluated_constraints || [];
            } else {
              // Fail-closed: policy not found
              verified = false;
              reason = `Policy '${policy}' not found — verification denied (fail-closed)`;
            }
          } else {
            // No policy specified — fail-closed
            verified = false;
            reason = "No policy specified — verification denied. Create a policy at veritera.ai/dashboard";
          }
        } catch (err) {
          // Fail-closed: any error during policy load or evaluation → deny
          console.error("[MCP] Policy evaluation error (fail-closed):", err instanceof Error ? err.message : err);
          verified = false;
          reason = "Verification engine error — action denied (fail-closed)";
        }

        const latency = Date.now() - start;
        const proofId = `mcp_${crypto.randomBytes(8).toString("hex")}`;

        res.json({
          jsonrpc: "2.0",
          result: {
            content: [{
              type: "text",
              text: JSON.stringify({
                verified,
                decision: verified ? "ALLOW" : "DENY",
                proof_id: proofId,
                latency_ms: latency,
                reason,
                action,
                agent_id: agent_id || "mcp-agent",
                evaluated_constraints: evaluatedConstraints,
              }),
            }],
          },
          id,
        });
        return;
      }

      if (toolName === "forge_list_policies") {
        if (!apiKey) {
          res.json({
            jsonrpc: "2.0",
            result: {
              content: [{ type: "text", text: JSON.stringify({ error: "authentication_required" }) }],
              isError: true,
            },
            id,
          });
          return;
        }

        const { getPoliciesByApiKey } = await import("./apiDb");
        const policies = await getPoliciesByApiKey(apiKey.id);
        res.json({
          jsonrpc: "2.0",
          result: {
            content: [{
              type: "text",
              text: JSON.stringify({
                policies: policies.map(p => ({
                  name: p.name,
                  description: p.description,
                  version: p.version,
                  active: p.isActive,
                })),
              }),
            }],
          },
          id,
        });
        return;
      }

      // Unknown tool
      res.json({
        jsonrpc: "2.0",
        error: { code: -32601, message: `Unknown tool: ${toolName}` },
        id,
      });
      return;
    }

    // Notifications (no response needed)
    case "notifications/initialized": {
      res.json({ jsonrpc: "2.0", result: {}, id });
      return;
    }

    // Unknown method
    default: {
      res.json({
        jsonrpc: "2.0",
        error: { code: -32601, message: `Method not found: ${method}` },
        id,
      });
    }
  }
}

// Route: POST /mcp (key in headers)
mcpRouter.post("/mcp", (req, res) => handleMcpRequest(req, res));

// Route: POST /mcp/:apiKey (key in URL — for Claude Cowork custom connectors)
mcpRouter.post("/mcp/:apiKey", (req, res) => handleMcpRequest(req, res, req.params.apiKey));

// Route: GET /mcp/:apiKey (some MCP clients do a GET handshake first)
mcpRouter.get("/mcp/:apiKey", (req, res) => {
  res.json({
    jsonrpc: "2.0",
    result: {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "forge-verification", version: "1.0.0" },
    },
    id: null,
  });
});

// Health check for MCP endpoint
mcpRouter.get("/mcp/health", (_req: Request, res: Response) => {
  res.json({
    status: "operational",
    protocol: "mcp",
    version: "1.0.0",
    transport: "streamable-http",
    tools: FORGE_TOOLS.map(t => t.name),
  });
});
