import express from "express";

const app = express();
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`[LOG] ${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Health Check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    service: "Remediation API"
  });
});

// ALL-IN-ONE REMEDIATION ENDPOINT
app.post("/remediate", (req, res) => {
  const { action, service, replicas, message } = req.body;

  if (!action) {
    return res.status(400).json({
      error: "Missing 'action' field. Provide: restart, scale, rollback, drain, notify"
    });
  }

  let response;

  switch (action) {
    case "restart":
      response = {
        status: "success",
        action: "restart",
        service,
        message: `Restarted ${service} (mock)`
      };
      break;

    case "scale":
      response = {
        status: "success",
        action: "scale",
        service,
        replicas,
        message: `Scaled ${service} to ${replicas} replicas (mock)`
      };
      break;

    case "rollback":
      response = {
        status: "success",
        action: "rollback",
        service,
        message: `Rolled back config for ${service} (mock)`
      };
      break;

    case "drain":
      response = {
        status: "success",
        action: "drain",
        service,
        message: `Traffic drained for ${service} (mock)`
      };
      break;

    case "notify":
      response = {
        status: "success",
        action: "notify",
        message
      };
      break;

    default:
      response = { error: `Unknown action: ${action}` };
  }

  return res.json(response);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Unified Remediation API running on port", PORT);
});
