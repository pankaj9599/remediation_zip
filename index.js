import express from "express";
import axios from "axios";

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
  const { action, severity, target = {}, issue, description } = req.body;

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

    if (action === "drain") {
      return res.json({
        status: "success",
        action: "drain",
        service
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



// import express from "express";
// import axios from "axios";

// const app = express();
// app.use(express.json());



// let durationHours = 0;
// if (severity === "low") durationHours = 24;
// if (severity === "medium") durationHours = 48;


// // Logging middleware
// app.use((req, res, next) => {
//   console.log(`[LOG] ${new Date().toISOString()} - ${req.method} ${req.url}`);
//   next();
// });

// // Validate env variables
// const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
// const CLOUDFLARE_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID;

// if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ZONE_ID || !CLOUDFLARE_EMAIL) {
//   console.error("❌ Missing Cloudflare ENV variables");
// }

// // Cloudflare API instance
// const CF = axios.create({
//   baseURL: `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}`,
//   headers: {
//     "Content-Type": "application/json",
//     "Authorization": `Bearer ${CLOUDFLARE_API_TOKEN}`
//   }
// });


// // Health Check
// app.get("/health", (req, res) => {
//   res.json({
//     status: "ok",
//     timestamp: new Date().toISOString(),
//     service: "Remediation API"
//   });
// });

// // -------------------------------
// // REAL REMEDIATION ENDPOINT
// // -------------------------------
// app.post("/", async (req, res) => {
//   const { action, service, replicas, message, ip } = req.body;

//   if (!action) {
//     return res.status(400).json({
//       error: "Missing 'action' field. Provide: block_ip, unblock_ip, list_blocked, restart, scale, rollback, drain, notify"
//     });
//   }

//   try {
//     let result;

//     switch (action) {

//       // --------------------------
//       // REAL CLOUDFLARE ACTIONS
//       // --------------------------

//       case "block_ip":
//         if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

//         result = await CF.post("/firewall/access_rules/rules", {
//           mode: "block",
//           configuration: {
//             target: "ip",
//             value: ip
//           },
//           notes: "Blocked by ThreatPilot AI Remediator"
//         });

//         return res.json({
//           status: "success",
//           action: "block_ip",
//           ip,
//           cloudflare_result: result.data
//         });

//       case "unblock_ip":
//         if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

//         // list rules
//         const rules = await CF.get("/firewall/access_rules/rules");
//         const rule = rules.data.result.find(r => r.configuration.value === ip);

//         if (!rule) return res.json({ status: "not_found", message: "IP was not blocked" });

//         await CF.delete(`/firewall/access_rules/rules/${rule.id}`);

//         return res.json({
//           status: "success",
//           action: "unblock_ip",
//           ip
//         });

//       case "list_blocked":
//         const blockedList = await CF.get("/firewall/access_rules/rules");
        
//         return res.json({
//           status: "success",
//           action: "list_blocked",
//           blocked_ips: blockedList.data.result
//             .filter(r => r.mode === "block")
//             .map(r => r.configuration.value)
//         });

//       // --------------------------
//       // SIMULATED / MOCK ACTIONS
//       // --------------------------

//       case "restart":
//         return res.json({
//           status: "success",
//           action: "restart",
//           service,
//           message: `Restarted ${service} (mock)`
//         });

//       case "scale":
//         return res.json({
//           status: "success",
//           action: "scale",
//           service,
//           replicas,
//           message: `Scaled ${service} to ${replicas} replicas (mock)`
//         });

//       case "rollback":
//         return res.json({
//           status: "success",
//           action: "rollback",
//           service,
//           message: `Rolled back config for ${service} (mock)`
//         });

//       case "drain":
//         return res.json({
//           status: "success",
//           action: "drain",
//           service,
//           message: `Traffic drained for ${service} (mock)`
//         });

//       case "notify":
//         return res.json({
//           status: "success",
//           action: "notify",
//           message
//         });

//       default:
//         return res.status(400).json({ error: `Unknown action: ${action}` });
//     }
//   }

//   catch (err) {
//     console.error("Cloudflare API Error:", err.response?.data || err.message);
//     return res.status(500).json({
//       status: "error",
//       action,
//       details: err.response?.data || err.message
//     });
//   }
// });


// // START SERVER
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//   console.log("🔥 Unified Remediation API running on port", PORT);
// });


