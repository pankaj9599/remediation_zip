import axios from "axios";

/* =========================
   ENV
========================= */

const JIRA_BASE_URL = process.env.JIRA_BASE;
const JIRA_EMAIL = process.env.JIRA_MAIL;
const JIRA_API_TOKEN = process.env.JIRA_API;
const JIRA_PROJECT_KEY = process.env.JIRA_PROJECT;

/* =========================
   JIRA CLIENT
========================= */

const jira = axios.create({
  baseURL: `${JIRA_BASE_URL}/rest/api/3`,
  headers: {
    "Authorization":
      "Basic " +
      Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString("base64"),
    "Content-Type": "application/json"
  }
});

/* =========================
   ADF HELPER
========================= */

export function toADF(text) {
  return {
    type: "doc",
    version: 1,
    content: [
      {
        type: "paragraph",
        content: [
          {
            type: "text",
            text: String(text)
          }
        ]
      }
    ]
  };
}

/* =========================
   GENERIC JIRA TICKET
========================= */

export async function createJiraTicket({
  summary,
  description,
  priority = "Medium",
  issueType = "Task",
  labels = []
}) {
  if (!JIRA_PROJECT_KEY) {
    throw new Error("JIRA_PROJECT env var missing");
  }

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
