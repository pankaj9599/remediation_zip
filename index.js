// --------------------------------------------------
// ThreatPilot – Unified Remediation API
// --------------------------------------------------

import express from "express";
import axios from "axios";
import fetch from "node-fetch";
import { createJiraTicket, toADF } from "./jira.js";

const app = express();
app.use(express.json());

// --------------------------------------------------
// Action Normalization (CRITICAL FIX)
// --------------------------------------------------
function normalizeAction(action) {
  const map = {
    block: "block",
    block_ip: "block",
    unblock_ip: "unblock",

    restart_service: "restart",
    scale_service: "scale",
    rollback_service: "rollback",
    drain_service: "drain",

    trigger_alert: "notify",
    notify_team: "notify"
  };

  return map[action] || action;
}

// --------------------------------------------------
// Severity → Jira Priority
// --------------------------------------------------
function priorityFromSeverity(severity) {
  if (severity === "critical") return "Highest";
  if (severity === "high") return "High";
  if (severity === "medium") return "Medium";
  return "Low";
}

// --------------------------------------------------
// Slack Alert
// --------------------------------------------------
async function alertSRESlack(payload) {
  const webhook = process.env.SLACK_WEBHOOK_URL;
  if (!webhook) throw new Error("Slack webhook not configured");

  await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: `🚨 *ThreatPilot Alert*
Action: ${payload.action}
Severity: ${payload.severity}
Issue: ${payload.issue || "unknown"}
Target: ${JSON.stringify(payload.target)}`
    })
  });
}

// --------------------------------------------------
// Cloudflare
// --------------------------------------------------
const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CF_ZONE = process.env.CLOUDFLARE_ZONE_ID;

const CF = axios.create({
  baseURL: `https://api.cloudflare.com/client/v4/zones/${CF_ZONE}`,
  headers: {
    Authorization: `Bearer ${CF_TOKEN}`,
    "Content-Type": "application/json"
  }
});

// --------------------------------------------------
// Health
// --------------------------------------------------
app.get("/", (_, res) => res.send("ThreatPilot Remediation API up"));
app.get("/health", (_, res) => res.json({ status: "ok" }));

// --------------------------------------------------
// MAIN REMEDIATION ENDPOINT
// --------------------------------------------------
app.post("/", async (req, res) => {
  try {
    const {
      action: rawAction,
      severity,
      issue,
      description,
      target = {}
    } = req.body;

    if (!rawAction || !severity || !issue || !description) {
      return res.status(400).json({
        error: "Missing required fields: action, severity, issue, description"
      });
    }

    const action = normalizeAction(rawAction);
    const { ip, service, replicas } = target;

    // --------------------------------------------------
    // BLOCK IP
    // --------------------------------------------------
    if (action === "block") {
      if (!ip) return res.status(400).json({ error: "Missing target.ip" });

      const resp = await CF.post("/firewall/access_rules/rules", {
        mode: "block",
        configuration: { target: "ip", value: ip },
        notes: `ThreatPilot block (${severity})`
      });

      return res.json({
        status: "success",
        action: "block",
        ip,
        cloudflare_rule_id: resp.data.result.id
      });
    }

    // --------------------------------------------------
    // RESTART
    // --------------------------------------------------
    if (action === "restart") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jira = await createJiraTicket({
        summary: `[ThreatPilot] Restart Service ${service}`,
        description: toADF(description),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "restart"]
      });

      return res.json({
        status: "pending_approval",
        action: "restart",
        service,
        jira_ticket: jira
      });
    }

    // --------------------------------------------------
    // SCALE
    // --------------------------------------------------
    if (action === "scale") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jira = await createJiraTicket({
        summary: `[ThreatPilot] Scale Service ${service}`,
        description: toADF(description),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "scale"]
      });

      return res.json({
        status: "pending_approval",
        action: "scale",
        service,
        replicas,
        jira_ticket: jira
      });
    }

    // --------------------------------------------------
    // ROLLBACK
    // --------------------------------------------------
    if (action === "rollback") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jira = await createJiraTicket({
        summary: `[ThreatPilot] Rollback Service ${service}`,
        description: toADF(description),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "rollback"]
      });

      return res.json({
        status: "pending_approval",
        action: "rollback",
        service,
        jira_ticket: jira
      });
    }

    // --------------------------------------------------
    // DRAIN
    // --------------------------------------------------
    if (action === "drain") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jira = await createJiraTicket({
        summary: `[ThreatPilot] Drain Service ${service}`,
        description: toADF(description),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "drain"]
      });

      return res.json({
        status: "pending_approval",
        action: "drain",
        service,
        jira_ticket: jira
      });
    }

    // --------------------------------------------------
    // NOTIFY
    // --------------------------------------------------
    if (action === "notify") {
      await alertSRESlack({ action, severity, issue, target });
      return res.json({
        status: "success",
        action: "notify",
        message: "SRE notified via Slack"
      });
    }

    return res.status(400).json({ error: `Unsupported action: ${rawAction}` });

  } catch (err) {
    console.error("❌ Remediation error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
// Start Server
// --------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 ThreatPilot Remediation API running on port ${PORT}`)
);




// // --------------------------------------------------
// // Start server
// // ------------------------------

// import express from "express";
// import axios from "axios";
// //change 
// import { createJiraTicket, toADF } from "./jira.js";
// //change

// const app = express();
// app.use(express.json());

// function priorityFromSeverity(severity) {
//   if (severity === "critical") return "Highest";
//   if (severity === "high") return "High";
//   if (severity === "medium") return "Medium";
//   return "Low";
// }


// // ------------------------------------------------------------------
// //  In-Memory Temp Block Store (per-IP timers)
// // ------------------------------------------------------------------

// /*
// Structure:
// tempBlocks = {
//   "203.0.113.42": {
//      rule_id: "...",
//      timeout: TimeoutObject
//   }
// }
// */

// const tempBlocks = {};  // Do NOT replace with a Set/Array. We store timeout references here.

// // ------------------------------------------------------------------
// // Configuration
// // ------------------------------------------------------------------

// const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
// const CF_ZONE = process.env.CLOUDFLARE_ZONE_ID;

// if (!CF_TOKEN || !CF_ZONE) {
//   console.error("❌ Missing required Cloudflare env vars (CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)");
// }

// // Cloudflare API client
// const CF = axios.create({
//   baseURL: `https://api.cloudflare.com/client/v4/zones/${CF_ZONE}`,
//   headers: {
//     "Content-Type": "application/json",
//     "Authorization": `Bearer ${CF_TOKEN}`
//   }
// });

// // ------------------------------------------------------------------
// // Severity → Temporary duration (in minutes, for testing)
// // low = 1 min, medium = 2 min
// // high/critical = permanent
// // ------------------------------------------------------------------

// function getTempBanMinutes(severity) {
//   if (severity === "low") return 1;      // 1 minute (for testing)
//   if (severity === "medium") return 2;   // 2 minutes (for testing)
//   return 0; // high / critical → permanent
// }

// // ------------------------------------------------------------------
// // Health check
// // ------------------------------------------------------------------

// app.get("/health", (req, res) => {
//   res.json({
//     status: "ok",
//     service: "Remediation API",
//     timestamp: new Date().toISOString()
//   });
// });

// // ------------------------------------------------------------------
// // MAIN REMEDIATION ENDPOINT
// // ------------------------------------------------------------------

// app.post("/", async (req, res) => {

  
//   // const { action, severity, target = {}, issue, description, block } = req.body;
//   const {
//   action,
//   severity,
//   target = {},
//   issue,
//   description: userDescription,
//   block
// } = req.body;
// //change

//   const ip = target.ip;
//   const service = target.service;
//   const replicas = target.replicas;

//   if (!action) {
//     return res.status(400).json({ error: "Missing 'action' field" });
//   }

//   try {
//     // ----------------------------------------------------------
//     // 1) BLOCK IP (Temporary or Permanent)
//     // ----------------------------------------------------------

//     if (action === "block") {
//       if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

//       const tempMinutes = getTempBanMinutes(severity);
//       console.log(`⏳ Temp ban minutes for ${ip}: ${tempMinutes}`);

//       // NEW CONDITION: Check if block is explicitly set to true OR if severity is low/medium
//       if (block === true || tempMinutes > 0) {
//         // Create Cloudflare block rule
//         const resp = await CF.post("/firewall/access_rules/rules", {
//           mode: "block",
//           configuration: { target: "ip", value: ip },
//           notes: `ThreatPilot block (${severity})`
//         });

//         const ruleId = resp.data.result.id;

//         // TEMPORARY block
//         if (tempMinutes > 0) {
//           // Clear previous timer if exists
//           if (tempBlocks[ip]?.timeout) clearTimeout(tempBlocks[ip].timeout);

//           const timeout = setTimeout(async () => {
//             console.log(`⏱ Unblocking ${ip} (timer expired)`);

//             try {
//               await CF.delete(`/firewall/access_rules/rules/${ruleId}`);
//             } catch (e) {
//               console.error("Cloudflare delete error:", e.response?.data || e.message);
//             }

//             delete tempBlocks[ip];
//           }, tempMinutes * 60 * 1000);

//           tempBlocks[ip] = { rule_id: ruleId, timeout };

//           return res.json({
//             status: "success",
//             action: "temp_block",
//             ip,
//             severity,
//             duration_minutes: tempMinutes,
//             unblock_at: new Date(Date.now() + tempMinutes * 60000).toISOString()
//           });
//         }

//         // PERMANENT block
//         return res.json({
//           status: "success",
//           action: "block",
//           ip,
//           severity,
//           permanent: true
//         });
//       } else {
//         // Block condition not met - skip blocking
//         return res.json({
//           status: "skipped",
//           action: "block",
//           ip,
//           severity,
//           message: "Block condition not met (block flag not set and severity is high/critical)"
//         });
//       }
//     }

//     // ----------------------------------------------------------
//     // 2) UNBLOCK IP (manual)
//     // ----------------------------------------------------------

//     if (action === "unblock") {
//       if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

//       const list = await CF.get("/firewall/access_rules/rules");
//       const rule = list.data.result.find(r => r.configuration.value === ip);

//       if (!rule) {
//         return res.json({
//           status: "not_found",
//           message: "IP was not blocked"
//         });
//       }

//       await CF.delete(`/firewall/access_rules/rules/${rule.id}`);

//       if (tempBlocks[ip]) {
//         clearTimeout(tempBlocks[ip].timeout);
//         delete tempBlocks[ip];
//       }

//       return res.json({
//         status: "success",
//         action: "unblock",
//         ip
//       });
//     }

//     // ----------------------------------------------------------
//     // 3) LIST ALL BLOCKED IPs
//     // ----------------------------------------------------------

//     if (action === "list_blocked") {
//       const cfRules = await CF.get("/firewall/access_rules/rules");

//       const ips = cfRules.data.result
//         .filter(r => r.mode === "block")
//         .map(r => r.configuration.value);

//       return res.json({
//         status: "success",
//         action: "list_blocked",
//         ips
//       });
//     }

//     // ----------------------------------------------------------
//     // 4) MOCK SERVICE ACTIONS
//     // ----------------------------------------------------------

//     // if (action === "restart") {
//     //   return res.json({ status: "success", action: "restart", service });
//     // }

//     if (action === "restart") {
//   if (!service) {
//     return res.status(400).json({ error: "Missing target.service" });
//   }

//   const jiraKey = await createJiraTicket({
//     summary: `[ThreatPilot] Restart Service ${service}`,
//     description: toADF(
//       `ACTION: RESTART SERVICE

// Service: ${service}
// Severity: ${severity}
// Issue: ${issue || "unknown"}

// ${userDescription || ""}`
//     ),
//     priority: priorityFromSeverity(severity),
//     issueType: "Task",
//     labels: ["threatpilot", "restart", "manual-approval"]
//   });

//   return res.json({
//     status: "pending_approval",
//     action: "restart",
//     service,
//     jira_ticket: jiraKey
//   });
// }


//     // if (action === "scale") {
//     //   return res.json({
//     //     status: "success",
//     //     action: "scale",
//     //     service,
//     //     replicas
//     //   });
//     // }

//     if (action === "scale") {
//   if (!service) {
//     return res.status(400).json({ error: "Missing target.service" });
//   }

//   const jiraKey = await createJiraTicket({
//     summary: `[ThreatPilot] Scale Service ${service}`,
//     description: toADF(
//       `ACTION: SCALE SERVICE

// Service: ${service}
// Target replicas: ${replicas ?? "not specified"}
// Severity: ${severity}
// Issue: ${issue || "unknown"}

// ${userDescription || ""}`
//     ),
//     priority: priorityFromSeverity(severity),
//     issueType: "Task",
//     labels: ["threatpilot", "scale", "manual-approval"]
//   });

//   return res.json({
//     status: "pending_approval",
//     action: "scale",
//     service,
//     replicas,
//     jira_ticket: jiraKey
//   });
// }

//     // if (action === "rollback") {
//     //   return res.json({
//     //     status: "success",
//     //     action: "rollback",
//     //     service
//     //   });
//     // }

//     if (action === "rollback") {
//   if (!service) {
//     return res.status(400).json({ error: "Missing target.service" });
//   }

//   const jiraKey = await createJiraTicket({
//     summary: `[ThreatPilot] Rollback Required for ${service}`,
//     description: toADF(
//       `ACTION: ROLLBACK SERVICE

// Service: ${service}
// Severity: ${severity}
// Issue: ${issue || "unknown"}

// ${userDescription || ""}`
//     ),
//     priority: priorityFromSeverity(severity),
//     issueType: "Task",
//     labels: ["threatpilot", "rollback", "manual-approval"]
//   });

//   return res.json({
//     status: "pending_approval",
//     action: "rollback",
//     service,
//     jira_ticket: jiraKey
//   });
// }

    
//     //ritesh

//     // if (action === "drain") {
//     //   return res.json({
//     //     status: "success",
//     //     action: "drain",
//     //     service
//     //   });
//     // }

//     //ritesh

// //     if (action === "drain") {
// //   if (!service) {
// //     return res.status(400).json({ error: "Missing target.service" });
// //   }

// //   const jiraKey = await createJiraTicket({
// //     summary: `[ThreatPilot] Drain Service ${service}`,
// //     description:{
// //     type: "doc",
// //     version: 1,
// //     content: [
// //       {
// //         type: "paragraph",
// //         content: [
// //           {
// //             type: "text",
// //             text: `ACTION: DRAIN SERVICE\n\nService: ${service}\nSeverity: ${severity}\nIssue: ${issue || "unknown"}\n\n${description || ""}`
// //           }
// //         ]
// //       }
// //     ]
// //   },
// //     priority: severity === "critical" ? "Highest" : "High",
// //     issueType: "Task",
// //     labels: ["threatpilot", "drain", "manual-approval"]
// //   });

// //   return res.json({
// //     status: "pending_approval",
// //     action: "drain",
// //     service,
// //     jira_ticket: jiraKey,
// //     message: "Drain action requires human approval via Jira"
// //   });
// // }
//     if (action === "drain") {
//   if (!service) {
//     return res.status(400).json({ error: "Missing target.service" });
//   }

//   const jiraKey = await createJiraTicket({
//     summary: `[ThreatPilot] Drain Service ${service}`,
//     description: toADF(
//       `ACTION: DRAIN SERVICE

// Service: ${service}
// Severity: ${severity}
// Issue: ${issue || "unknown"}

// ${userDescription || ""}`
//     ),
//     priority: severity === "critical" ? "Highest" : "High",
//     issueType: "Task",
//     labels: ["threatpilot", "drain", "manual-approval"]
//   });

//   return res.json({
//     status: "pending_approval",
//     action: "drain",
//     service,
//     jira_ticket: jiraKey
//   });
// }


//     if (action === "notify") {
//       return res.json({
//         status: "success",
//         action: "notify",
//         message: "SRE notified"
//       });
//     }

//     return res.status(400).json({ error: `Unknown action: ${action}` });

//   } catch (err) {
//     console.error("ERROR:", err.response?.data || err.message);

//     return res.status(500).json({
//       status: "error",
//       action,
//       details: err.response?.data || err.message
//     });
//   }
// });

// // ------------------------------------------------------------------
// // Start API
// // ------------------------------------------------------------------

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () =>
//   console.log(`🚀 Remediation API running on port ${PORT}`)
// );


