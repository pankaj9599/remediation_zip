// --------------------------------------------------
// Start server
// --------------------------------------------------

import express from "express";
import axios from "axios";
import fetch from "node-fetch";
import { createJiraTicket, toADF } from "./jira.js";

const app = express();
app.use(express.json());

// --------------------------------------------------
// Slack
// --------------------------------------------------

async function alertSRESlack(payload) {
  const webhook = process.env.SLACK_WEBHOOK_URL;
  if (!webhook) throw new Error("Slack webhook not configured");

  await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: `🚨 ThreatPilot Alert
Action: ${payload.action}
Severity: ${payload.severity}
Target: ${JSON.stringify(payload.target)}
Issue: ${payload.issue || "unknown"}`
    })
  });
}

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function priorityFromSeverity(severity) {
  if (severity === "critical") return "Highest";
  if (severity === "high") return "High";
  if (severity === "medium") return "Medium";
  return "Low";
}

/**
 * ACCEPT BOTH commander + legacy action names
 */
function normalizeAction(action) {
  const map = {
    restart_service: "restart",
    scale_service: "scale",
    rollback_service: "rollback",
    drain_service: "drain",
    notify_team: "notify",
    trigger_alert: "notify",
    block: "block_ip"
  };

  return map[action] || action;
}

// --------------------------------------------------
// Cloudflare
// --------------------------------------------------

const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CF_ZONE = process.env.CLOUDFLARE_ZONE_ID;

const CF = axios.create({
  baseURL: `https://api.cloudflare.com/client/v4/zones/${CF_ZONE}`,
  headers: {
    "Authorization": `Bearer ${CF_TOKEN}`,
    "Content-Type": "application/json"
  }
});

// --------------------------------------------------
// Health
// --------------------------------------------------

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "Remediation API" });
});

// --------------------------------------------------
// MAIN ENDPOINT
// --------------------------------------------------

app.post("/", async (req, res) => {
  const {
    action: rawAction,
    severity,
    target = {},
    issue,
    description,
    block
  } = req.body;

  if (!rawAction) {
    return res.status(400).json({ error: "Missing action" });
  }

  const action = normalizeAction(rawAction);
  const ip = target.ip;
  const service = target.service;
  const replicas = target.replicas;

  try {
    // --------------------------------------------------
    // BLOCK IP (block OR block_ip)
    // --------------------------------------------------
    if (action === "block_ip") {
      if (!ip) return res.status(400).json({ error: "Missing target.ip" });

      const resp = await CF.post("/firewall/access_rules/rules", {
        mode: "block",
        configuration: { target: "ip", value: ip },
        notes: "ThreatPilot automated block"
      });

      return res.json({
        status: "success",
        action: "block_ip",
        ip,
        cloudflare_rule_id: resp.data.result.id
      });
    }

    // --------------------------------------------------
    // RESTART / RESTART_SERVICE
    // --------------------------------------------------
    if (action === "restart") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jiraKey = await createJiraTicket({
        summary: `[ThreatPilot] Restart Service ${service}`,
        description: toADF(
          `ACTION: RESTART SERVICE
Service: ${service}
Severity: ${severity}
Issue: ${issue || "unknown"}

${description || ""}`
        ),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "restart"]
      });

      return res.json({
        status: "pending_approval",
        action: "restart",
        service,
        jira_ticket: jiraKey
      });
    }

    // --------------------------------------------------
    // SCALE / SCALE_SERVICE
    // --------------------------------------------------
    if (action === "scale") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jiraKey = await createJiraTicket({
        summary: `[ThreatPilot] Scale Service ${service}`,
        description: toADF(
          `ACTION: SCALE SERVICE
Service: ${service}
Target replicas: ${replicas || "N/A"}
Severity: ${severity}`
        ),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "scale"]
      });

      return res.json({
        status: "pending_approval",
        action: "scale",
        service,
        replicas,
        jira_ticket: jiraKey
      });
    }

    // --------------------------------------------------
    // ROLLBACK / ROLLBACK_SERVICE
    // --------------------------------------------------
    if (action === "rollback") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jiraKey = await createJiraTicket({
        summary: `[ThreatPilot] Rollback Service ${service}`,
        description: toADF(
          `ACTION: ROLLBACK SERVICE
Service: ${service}
Severity: ${severity}`
        ),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "rollback"]
      });

      return res.json({
        status: "pending_approval",
        action: "rollback",
        service,
        jira_ticket: jiraKey
      });
    }

    // --------------------------------------------------
    // DRAIN / DRAIN_SERVICE
    // --------------------------------------------------
    if (action === "drain") {
      if (!service) return res.status(400).json({ error: "Missing target.service" });

      const jiraKey = await createJiraTicket({
        summary: `[ThreatPilot] Drain Service ${service}`,
        description: toADF(
          `ACTION: DRAIN SERVICE
Service: ${service}
Severity: ${severity}`
        ),
        priority: priorityFromSeverity(severity),
        issueType: "Task",
        labels: ["threatpilot", "drain"]
      });

      return res.json({
        status: "pending_approval",
        action: "drain",
        service,
        jira_ticket: jiraKey
      });
    }

    // --------------------------------------------------
    // NOTIFY / NOTIFY_TEAM / TRIGGER_ALERT
    // --------------------------------------------------
    if (action === "notify") {
      await alertSRESlack({ action, severity, target, issue });
      return res.json({
        status: "success",
        action: "notify",
        message: "SRE notified via Slack"
      });
    }

    return res.status(400).json({
      error: `Unsupported action: ${rawAction}`
    });

  } catch (err) {
    console.error("❌ Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
// Start API
// --------------------------------------------------

const PORT = process.env.PORT || 8080;
app.listen(PORT, () =>
  console.log(`🚀 Remediation API running on port ${PORT}`)
);


// import axios from "axios";

// const JIRA_BASE = process.env.JIRA_BASE_URL;
// const JIRA_EMAIL = process.env.JIRA_EMAIL;
// const JIRA_TOKEN = process.env.JIRA_API_TOKEN;

// const jira = axios.create({
//   baseURL: `${JIRA_BASE}/rest/api/3`,
//   headers: {
//     "Authorization":
//       "Basic " +
//       Buffer.from(`${JIRA_EMAIL}:${JIRA_TOKEN}`).toString("base64"),
//     "Content-Type": "application/json"
//   }
// });

// export function toADF(text) {
//   return {
//     type: "doc",
//     version: 1,
//     content: [
//       {
//         type: "paragraph",
//         content: [
//           {
//             type: "text",
//             text: String(text)
//           }
//         ]
//       }
//     ]
//   };
// }


// export async function createJiraTicket({
//   summary,
//   description,
//   priority = "High",
//   issueType = "Task",
//   labels = []
// }) {
//   const res = await jira.post("/issue", {
//     fields: {
//       project: { key: process.env.JIRA_PROJECT_KEY },
//       summary,
//       description,
//       issuetype: { name: issueType },
//       priority: { name: priority },
//       labels
//     }
//   });

//   return res.data.key;
// }
