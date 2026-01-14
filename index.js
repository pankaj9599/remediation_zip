
import express from "express";

const app = express();
app.use(express.json());

// Simple Logger
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

// 1. Restart Service
app.post("/restart", (req, res) => {
  const { service } = req.body;
  res.json({
    status: "success",
    action: "restart",
    service,
    message: `Restarted ${service} (mock)`
  });
});

// 2. Scale Service
app.post("/scale", (req, res) => {
  const { service, replicas } = req.body;
  res.json({
    status: "success",
    action: "scale",
    service,
    replicas,
    message: `Scaled ${service} to ${replicas} replicas (mock)`
  });
});

// 3. Rollback Config
app.post("/rollback", (req, res) => {
  const { service } = req.body;
  res.json({
    status: "success",
    action: "rollback",
    service,
    message: `Rolled back config for ${service} (mock)`
  });
});

// 4. Drain Traffic
app.post("/drain", (req, res) => {
  const { service } = req.body;
  res.json({
    status: "success",
    action: "drain",
    service,
    message: `Traffic drained for ${service} (mock)`
  });
});

// 5. Notify On-Call
app.post("/notify", (req, res) => {
  const { message } = req.body;
  res.json({
    status: "success",
    action: "notify",
    message
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Remediation API running on port", PORT);
});
