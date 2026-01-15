import express from "express";
import axios from "axios";

const app = express();
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`[LOG] ${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Validate env variables
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CLOUDFLARE_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID;

if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ZONE_ID ) {
  console.error("❌ Missing Cloudflare ENV variables");
}

// Cloudflare API instance
const CF = axios.create({
  baseURL: `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}`,
  headers: {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${CLOUDFLARE_API_TOKEN}`
  }
});
// Health Check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    service: "Remediation API"
  });
});

// -------------------------------
// REAL REMEDIATION ENDPOINT
// -------------------------------
app.post("/", async (req, res) => {
  const { action, service, replicas, message, ip } = req.body;

  if (!action) {
    return res.status(400).json({
      error: "Missing 'action' field. Provide: block_ip, unblock_ip, list_blocked, restart, scale, rollback, drain, notify"
    });
  }

  try {
    let result;

    switch (action) {

      // --------------------------
      // REAL CLOUDFLARE ACTIONS
      // --------------------------

      case "block_ip":
        if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

        result = await CF.post("/firewall/access_rules/rules", {
          mode: "block",
          configuration: {
            target: "ip",
            value: ip
          },
          notes: "Blocked by ThreatPilot AI Remediator"
        });

        return res.json({
          status: "success",
          action: "block_ip",
          ip,
          cloudflare_result: result.data
        });

      case "unblock_ip":
        if (!ip) return res.status(400).json({ error: "Missing 'ip' field" });

        // list rules
        const rules = await CF.get("/firewall/access_rules/rules");
        const rule = rules.data.result.find(r => r.configuration.value === ip);

        if (!rule) return res.json({ status: "not_found", message: "IP was not blocked" });

        await CF.delete(`/firewall/access_rules/rules/${rule.id}`);

        return res.json({
          status: "success",
          action: "unblock_ip",
          ip
        });

      case "list_blocked":
        const blockedList = await CF.get("/firewall/access_rules/rules");
        
        return res.json({
          status: "success",
          action: "list_blocked",
          blocked_ips: blockedList.data.result
            .filter(r => r.mode === "block")
            .map(r => r.configuration.value)
        });

      // --------------------------
      // SIMULATED / MOCK ACTIONS
      // --------------------------

      case "restart":
        return res.json({
          status: "success",
          action: "restart",
          service,
          message: `Restarted ${service} (mock)`
        });

      case "scale":
        return res.json({
          status: "success",
          action: "scale",
          service,
          replicas,
          message: `Scaled ${service} to ${replicas} replicas (mock)`
        });

      case "rollback":
        return res.json({
          status: "success",
          action: "rollback",
          service,
          message: `Rolled back config for ${service} (mock)`
        });

      case "drain":
        return res.json({
          status: "success",
          action: "drain",
          service,
          message: `Traffic drained for ${service} (mock)`
        });

      case "notify":
        return res.json({
          status: "success",
          action: "notify",
          message
        });

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  }

  catch (err) {
    console.error("Cloudflare API Error:", err.response?.data || err.message);
    return res.status(500).json({
      status: "error",
      action,
      details: err.response?.data || err.message
    });
  }
});


// START SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🔥 Unified Remediation API running on port", PORT);
});
