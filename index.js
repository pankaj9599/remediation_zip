import express from "express";
import axios from "axios";

// --------------------------------------------------
// App setup
// --------------------------------------------------
const app = express();
app.use(express.json());

// --------------------------------------------------
// In-memory temp block store (IP → timer)
// --------------------------------------------------
const tempBlocks = {}; 
// {
//   "1.2.3.4": { rule_id, timeout }
// }

// --------------------------------------------------
// ENV VARIABLES
// --------------------------------------------------
const {
  PORT = 3000,

  // Cloudflare
  CLOUDFLARE_API_TOKEN,
  CLOUDFLARE_ZONE_ID,

  // Jira
  JIRA_BASE_URL,
  JIRA_EMAIL,
  JIRA_API_TOKEN,
  JIRA_PROJECT_KEY
} = process.env;

// --------------------------------------------------
// Cloudflare client
// --------------------------------------------------
const CF = axios.create({
  baseURL: `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}`,
  headers: {
    "Authorization": `Bearer ${CLOUDFLARE_API_TOKEN}`,
    "Content-Type": "application/json"
  }
});

// --------------------------------------------------
// Jira client
// --------------------------------------------------
const jira = axios.create({
  baseURL: `${JIRA_BASE_URL}/rest/api/3`,
  headers: {
    "Authorization":
      "Basic " +
      Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString("base64"),
    "Content-Type": "application/json"
  }
});

// --------------------------------------------------
// Helpers
// --------------------------------------------------
function getTempBanMinutes(severity) {
  if (severity === "low") return 1;      // testing
  if (severity === "medium") return 2;   // testing
  return 0; // high / critical → permanent
}

async function createJiraTicket({
  summary,
  description,
  priority = "High",
  issueType = "Task",
  labels = []
}) {
  const res = await jira.post("/issue", {
    fields: {
      project: { key: JIRA_PROJECT_KEY },
      summary,
      description,
      issuetype: { name: issueType },
      priority: { name: priority },
      labels
    }
  });

  return res.data.key;
}

// --------------------------------------------------
// Health check
// --------------------------------------------------
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ThreatPilot Remediation API",
    timestamp: new Date().toISOString()
  });
});

// --------------------------------------------------
// MAIN REMEDIATION ENDPOINT
// --------------------------------------------------
app.post("/", async (req, res) => {
  const {
    action,
    severity = "medium",
    target = {},
    issue,
    description,
    block
  } = req.body;

  const ip = target.ip;
  const service = target.service;
  const replicas = target.replicas;

  if (!action) {
    return res.status(400).json({ error: "Missing action" });
  }

  try {
    // --------------------------------------------------
    // 1️⃣ BLOCK IP (temp / permanent)
    // --------------------------------------------------
    if (action === "block_ip") {
      if (!ip) return res.status(400).json({ error: "Missing target.ip" });

      const tempMinutes = getTempBanMinutes(severity);

      const resp = await CF.post("/firewall/access_rules/rules", {
        mode: "block",
        configuration: { target: "ip", value: ip },
        notes: `ThreatPilot block (${severity})`
      });

      const ruleId = resp.data.result.id;

      // TEMP BLOCK
      if (tempMinutes > 0) {
        if (tempBlocks[ip]?.timeout) {
          clearTimeout(tempBlocks[ip].timeout);
        }

        const timeout = setTimeout(async () => {
          try {
            await CF.delete(`/firewall/access_rules/rules/${ruleId}`);
          } catch (e) {
            console.error("Unblock failed:", e.message);
          }
          delete tempBlocks[ip];
        }, tempMinutes * 60 * 1000);

        tempBlocks[ip] = { rule_id: ruleId, timeout };

        return res.json({
          status: "success",
          action: "temp_block_ip",
          ip,
          duration_minutes: tempMinutes
        });
      }

      // PERMANENT
      return res.json({
        status: "success",
        action: "block_ip",
        ip,
        permanent: true
      });
    }

    // --------------------------------------------------
    // 2️⃣ UNBLOCK IP
    // --------------------------------------------------
    if (action === "unblock_ip") {
      if (!ip) return res.status(400).json({ error: "Missing target.ip" });

      const rules = await CF.get("/firewall/access_rules/rules");
      const rule = rules.data.result.find(
        r => r.configuration.value === ip
      );

      if (!rule) {
        return res.json({ status: "not_found", ip });
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

    // --------------------------------------------------
    // 3️⃣ LIST BLOCKED IPs
    // --------------------------------------------------
    if (action === "list_blocked") {
      const rules = await CF.get("/firewall/access_rules/rules");

      const ips = rules.data.result
        .filter(r => r.mode === "block")
        .map(r => r.configuration.value);

      return res.json({
        status: "success",
        ips
      });
    }

    // --------------------------------------------------
    // 4️⃣ SERVICE ACTIONS (REAL + JIRA)
    // --------------------------------------------------
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
      const key = await createJiraTicket({
        summary: `[ThreatPilot] Rollback required for ${service}`,
        description: description || "Rollback requested",
        priority: "Highest",
        labels: ["threatpilot", "rollback"]
      });

      return res.json({
        status: "pending_approval",
        action: "rollback",
        jira_ticket: key
      });
    }

    // --------------------------------------------------
    // 5️⃣ DRAIN → JIRA ONLY (NO AUTO)
    // --------------------------------------------------
    if (action === "drain") {
      if (!service) {
        return res.status(400).json({ error: "Missing target.service" });
      }

      const key = await createJiraTicket({
        summary: `[ThreatPilot] Drain service ${service}`,
        description: `
ACTION: DRAIN SERVICE

Service: ${service}
Severity: ${severity}
Issue: ${issue || "unknown"}

${description || ""}
`,
        priority: severity === "critical" ? "Highest" : "High",
        labels: ["threatpilot", "drain", "manual-approval"]
      });

      return res.json({
        status: "pending_approval",
        action: "drain",
        service,
        jira_ticket: key
      });
    }

    // --------------------------------------------------
    // 6️⃣ NOTIFY
    // --------------------------------------------------
    if (action === "notify") {
      const key = await createJiraTicket({
        summary: `[ThreatPilot] Notification required`,
        description: description || "Manual attention required",
        priority: "Medium",
        labels: ["threatpilot", "notify"]
      });

      return res.json({
        status: "notified",
        jira_ticket: key
      });
    }

    return res.status(400).json({ error: `Unknown action: ${action}` });

  } catch (err) {
    console.error("ERROR:", err.response?.data || err.message);
    return res.status(500).json({
      status: "error",
      details: err.response?.data || err.message
    });
  }
});

// --------------------------------------------------
// Start server
// ------------------------------




// import express from "express";
// import axios from "axios";

// const app = express();
// app.use(express.json());

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
//   const { action, severity, target = {}, issue, description, block } = req.body;

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

//     if (action === "block_ip") {
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
//             action: "temp_block_ip",
//             ip,
//             severity,
//             duration_minutes: tempMinutes,
//             unblock_at: new Date(Date.now() + tempMinutes * 60000).toISOString()
//           });
//         }

//         // PERMANENT block
//         return res.json({
//           status: "success",
//           action: "block_ip",
//           ip,
//           severity,
//           permanent: true
//         });
//       } else {
//         // Block condition not met - skip blocking
//         return res.json({
//           status: "skipped",
//           action: "block_ip",
//           ip,
//           severity,
//           message: "Block condition not met (block flag not set and severity is high/critical)"
//         });
//       }
//     }

//     // ----------------------------------------------------------
//     // 2) UNBLOCK IP (manual)
//     // ----------------------------------------------------------

//     if (action === "unblock_ip") {
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
//         action: "unblock_ip",
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

//     if (action === "restart") {
//       return res.json({ status: "success", action: "restart", service });
//     }

//     if (action === "scale") {
//       return res.json({
//         status: "success",
//         action: "scale",
//         service,
//         replicas
//       });
//     }

//     if (action === "rollback") {
//       return res.json({
//         status: "success",
//         action: "rollback",
//         service
//       });
//     }

//     if (action === "drain") {
//       return res.json({
//         status: "success",
//         action: "drain",
//         service
//       });
//     }

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


