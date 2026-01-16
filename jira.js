import axios from "axios";

const JIRA_BASE = process.env.JIRA_BASE_URL;
const JIRA_EMAIL = process.env.JIRA_EMAIL;
const JIRA_TOKEN = process.env.JIRA_API_TOKEN;

const jira = axios.create({
  baseURL: `${JIRA_BASE}/rest/api/3`,
  headers: {
    "Authorization":
      "Basic " +
      Buffer.from(`${JIRA_EMAIL}:${JIRA_TOKEN}`).toString("base64"),
    "Content-Type": "application/json"
  }
});

export async function createJiraTicket({
  summary,
  description,
  priority = "High",
  issueType = "Task",
  labels = []
}) {
  const res = await jira.post("/issue", {
    fields: {
      project: { key: process.env.JIRA_PROJECT_KEY },
      summary,
      description,
      issuetype: { name: issueType },
      priority: { name: priority },
      labels
    }
  });

  return res.data.key;
}
