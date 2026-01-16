import express from "express";
import axios from "axios";

// ----------------------------
// Load OnDemand KV Storage
// ----------------------------
let storage = null;

try {
  const mod = await import("ondemand:storage");  // ⚠️ Correct virtual module
  storage = mod.storage;
  console.log("✅ OnDemand Storage loaded");
} catch (err) {
  console.log("⚠️ Storage not available (local mode)");
}

const app = express();
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

// ENV VARS
const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CF_ZONE = process.env.CLOUDFLARE_ZONE_ID;

if (!CF_TOKEN || !CF_ZONE) {
  console.error("❌ Missing Cloudflare env vars");
}

// Cloudflare API client
const CF = axios.create({
  baseURL: `https://api.cloudflare.com/client/v4/zones/${CF_ZONE}`,
  headers: {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${CF_TOKEN}`
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "Remediation API",
    timestamp: new Date().toISOString()
  });
});

/*
======================================================
 TEMPORARY BLOCK DURATIONS (TESTING)
======================================================
 low     → 1 minute  
 medium  → 2 minutes  
 high    → permanent  
======================================================
*/

function getTempBanMinutes(severity) {
  if (severity === "low") return 1;
  if (severity === "medium") return 2;
  return 0; // Permanent
}

/*
======================================================
 MAIN REMEDIATION ENDPOINT
======================================================
*/

app.post("/", async (req, res) => {
  const { action, severity, target = {} } = req.body;

  const ip = target.ip;
  const service = target.service;
  const replicas = target.replicas;

  if (!action) {
    return res.status(400).json({ error: "Missing 'action'" });
  }

  try {
    switch (action) {

      /*
      ======================================================
        1. BLOCK IP (TEMPORARY OR PERMANENT)
      ======================================================
      */
      case "block_ip":
        if (!ip) return res.status(400).json({ error: "Missing IP" });

        const tempMinutes = getTempBanMinutes(severity);

        // Create block
        const resp = await CF.post("/firewall/access_rules/rules", {
          mode: "block",
          configuration: { target: "ip", value: ip },
          notes: `ThreatPilot (${severity})`
        });

        const ruleId = resp.data.result.id;

        // Temporary block
        if (tempMinutes > 0 && storage) {
          const expiresAt = Date.now() + tempMinutes * 60 * 1000;

          await storage.put(
            `blocked:${ip}`,
            JSON.stringify({
              ip,
              rule_id: ruleId,
              severity,
              expires_at: expiresAt
            })
          );

          return res.json({
            status: "success",
            action: "temp_block_ip",
            ip,
            severity,
            duration_minutes: tempMinutes,
            unblock_at: new Date(expiresAt).toISOString()
          });
        }

        // Permanent block
        return res.json({
          status: "success",
          action: "block_ip",
          ip,
          severity,
          permanent: true
        });


      /*
      ======================================================
        2. UNBLOCK IP
      ======================================================
      */
      case "unblock_ip": {
        if (!ip) return res.status(400).json({ error: "Missing IP" });

        const list = await CF.get("/firewall/access_rules/rules");
        const rule = list.data.result.find(r => r.configuration.value === ip);

        if (!rule) return res.json({ status: "not_found" });

        await CF.delete(`/firewall/access_rules/rules/${rule.id}`);

        if (storage) await storage.delete(`blocked:${ip}`);

        return res.json({ status: "success", action: "unblock_ip", ip });
      }

      /*
      ======================================================
        3. LIST BLOCKED IPS
      ======================================================
      */
      case "list_blocked": {
        const cfRules = await CF.get("/firewall/access_rules/rules");
        const blockedIps = cfRules.data.result
          .filter(r => r.mode === "block")
          .map(r => r.configuration.value);

        return res.json({
          status: "success",
          ips: blockedIps
        });
      }

      /*
      ======================================================
        4. MOCK SERVICE ACTIONS
      ======================================================
      */
      case "restart":
        return res.json({ status: "success", action: "restart", service });

      case "scale":
        return res.json({ status: "success", action: "scale", service, replicas });

      case "rollback":
        return res.json({ status: "success", action: "rollback", service });

      case "drain":
        return res.json({ status: "success", action: "drain", service });

      case "notify":
        return res.json({ status: "success", action: "notify" });

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  }

  catch (err) {
    console.error("ERROR:", err.response?.data || err.message);
    return res.status(500).json({
      status: "error",
      error: err.response?.data || err.message
    });
  }
});

/*
======================================================
 CLEANUP: REMOVE EXPIRED TEMP BLOCKS
======================================================
*/

app.post("/cleanup", async (req, res) => {
  if (!storage) {
    return res.json({ status: "disabled" });
  }

  const expired = [];

  for await (const key of storage.list("blocked:")) {
    const data = JSON.parse(await storage.get(key));

    if (Date.now() > data.expires_at) {
      await CF.delete(`/firewall/access_rules/rules/${data.rule_id}`);
      await storage.delete(key);
      expired.push(data.ip);
    }
  }

  return res.json({
    status: "success",
    cleaned_ips: expired
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🔥 Remediation API running on port", PORT);
});


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


