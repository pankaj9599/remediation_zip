

// --------------------------------------------------
// Start server
// ------------------------------

import express from "express";
import axios from "axios";
//change 
import { createJiraTicket } from "./jira.js";
//change

const app = express();
app.use(express.json());

// ------------------------------------------------------------------
//  In-Memory Temp Block Store (per-IP timers)
// ------------------------------------------------------------------

/*
Structure:
tempBlocks = {
  "203.0.113.42": {
     rule_id: "...",
     timeout: TimeoutObject
  }
}
*/

const tempBlocks = {};  // Do NOT replace with a Set/Array. We store timeout references here.

// ------------------------------------------------------------------
// Configuration
// ------------------------------------------------------------------

const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CF_ZONE = process.env.CLOUDFLARE_ZONE_ID;

if (!CF_TOKEN || !CF_ZONE) {
  console.error("❌ Missing required Cloudflare env vars (CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)");
}

// Cloudflare API client
const CF = axios.create({
  baseURL: `https://api.cloudflare.com/client/v4/zones/${CF_ZONE}`,
  headers: {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${CF_TOKEN}`
  }
});

// ------------------------------------------------------------------
// Severity → Temporary duration (in minutes, for testing)
// low = 1 min, medium = 2 min
// high/critical = permanent
// ------------------------------------------------------------------

function getTempBanMinutes(severity) {
  if (severity === "low") return 1;      // 1 minute (for testing)
  if (severity === "medium") return 2;   // 2 minutes (for testing)
  return 0; // high / critical → permanent
}

// ------------------------------------------------------------------
// Health check
// ------------------------------------------------------------------

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "Remediation API",
    timestamp: new Date().toISOString()
  });
});

// ------------------------------------------------------------------
// MAIN REMEDIATION ENDPOINT
// ------------------------------------------------------------------

app.post("/", async (req, res) => {
  const { action, severity, target = {}, issue, description, block } = req.body;

  const ip = target.ip;
  const service = target.service;
  const replicas = target.replicas;

  if (!action) {
    return res.status(400).json({ error: "Missing 'action' field" });
  }

  try {
    // ----------------------------------------------------------
    // 1) BLOCK IP (Temporary or Permanent)
    // ----------------------------------------------------------

    if (action === "block_ip") {
      if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

      const tempMinutes = getTempBanMinutes(severity);
      console.log(`⏳ Temp ban minutes for ${ip}: ${tempMinutes}`);

      // NEW CONDITION: Check if block is explicitly set to true OR if severity is low/medium
      if (block === true || tempMinutes > 0) {
        // Create Cloudflare block rule
        const resp = await CF.post("/firewall/access_rules/rules", {
          mode: "block",
          configuration: { target: "ip", value: ip },
          notes: `ThreatPilot block (${severity})`
        });

        const ruleId = resp.data.result.id;

        // TEMPORARY block
        if (tempMinutes > 0) {
          // Clear previous timer if exists
          if (tempBlocks[ip]?.timeout) clearTimeout(tempBlocks[ip].timeout);

          const timeout = setTimeout(async () => {
            console.log(`⏱ Unblocking ${ip} (timer expired)`);

            try {
              await CF.delete(`/firewall/access_rules/rules/${ruleId}`);
            } catch (e) {
              console.error("Cloudflare delete error:", e.response?.data || e.message);
            }

            delete tempBlocks[ip];
          }, tempMinutes * 60 * 1000);

          tempBlocks[ip] = { rule_id: ruleId, timeout };

          return res.json({
            status: "success",
            action: "temp_block_ip",
            ip,
            severity,
            duration_minutes: tempMinutes,
            unblock_at: new Date(Date.now() + tempMinutes * 60000).toISOString()
          });
        }

        // PERMANENT block
        return res.json({
          status: "success",
          action: "block_ip",
          ip,
          severity,
          permanent: true
        });
      } else {
        // Block condition not met - skip blocking
        return res.json({
          status: "skipped",
          action: "block_ip",
          ip,
          severity,
          message: "Block condition not met (block flag not set and severity is high/critical)"
        });
      }
    }

    // ----------------------------------------------------------
    // 2) UNBLOCK IP (manual)
    // ----------------------------------------------------------

    if (action === "unblock_ip") {
      if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

      const list = await CF.get("/firewall/access_rules/rules");
      const rule = list.data.result.find(r => r.configuration.value === ip);

      if (!rule) {
        return res.json({
          status: "not_found",
          message: "IP was not blocked"
        });
      }

      await CF.delete(`/firewall/access_rules/rules/${rule.id}`);

      if (tempBlocks[ip]) {
        clearTimeout(tempBlocks[ip].timeout);
        delete tempBlocks[ip];
      }

      return res.json({
        status: "success",
        action: "unblock_ip",
        ip
      });
    }

    // ----------------------------------------------------------
    // 3) LIST ALL BLOCKED IPs
    // ----------------------------------------------------------

    if (action === "list_blocked") {
      const cfRules = await CF.get("/firewall/access_rules/rules");

      const ips = cfRules.data.result
        .filter(r => r.mode === "block")
        .map(r => r.configuration.value);

      return res.json({
        status: "success",
        action: "list_blocked",
        ips
      });
    }

    // ----------------------------------------------------------
    // 4) MOCK SERVICE ACTIONS
    // ----------------------------------------------------------

    if (action === "restart") {
      return res.json({ status: "success", action: "restart", service });
    }

    if (action === "scale") {
      return res.json({
        status: "success",
        action: "scale",
        service,
        replicas
      });
    }

    if (action === "rollback") {
      return res.json({
        status: "success",
        action: "rollback",
        service
      });
    }
    //ritesh

    // if (action === "drain") {
    //   return res.json({
    //     status: "success",
    //     action: "drain",
    //     service
    //   });
    // }

    //ritesh

    if (action === "drain") {
  if (!service) {
    return res.status(400).json({ error: "Missing target.service" });
  }

  const jiraKey = await createJiraTicket({
    summary: `[ThreatPilot] Drain Service ${service}`,
    description:{
    type: "doc",
    version: 1,
    content: [
      {
        type: "paragraph",
        content: [
          {
            type: "text",
            text: `ACTION: DRAIN SERVICE\n\nService: ${service}\nSeverity: ${severity}\nIssue: ${issue || "unknown"}\n\n${description || ""}`
          }
        ]
      }
    ]
  },
    priority: severity === "critical" ? "Highest" : "High",
    issueType: "Task",
    labels: ["threatpilot", "drain", "manual-approval"]
  });

  return res.json({
    status: "pending_approval",
    action: "drain",
    service,
    jira_ticket: jiraKey,
    message: "Drain action requires human approval via Jira"
  });
}


    if (action === "notify") {
      return res.json({
        status: "success",
        action: "notify",
        message: "SRE notified"
      });
    }

    return res.status(400).json({ error: `Unknown action: ${action}` });

  } catch (err) {
    console.error("ERROR:", err.response?.data || err.message);

    return res.status(500).json({
      status: "error",
      action,
      details: err.response?.data || err.message
    });
  }
});

// ------------------------------------------------------------------
// Start API
// ------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Remediation API running on port ${PORT}`)
);


