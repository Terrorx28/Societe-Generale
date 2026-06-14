import React, { useState, useRef, useEffect } from 'react';
import type { DerivedData, EventRow, Profile, UserRisk } from '../App';
import { scoreColor } from '../App';

// ── Colors ─────────────────────────────────────────────────────────────
const C = {
  bg: '#0a0c10', bg2: '#111318', bg3: '#181b22', bg4: '#1e2130',
  border: 'rgba(255,255,255,0.07)', border2: 'rgba(255,255,255,0.12)',
  text: '#e8eaf0', text2: '#8b9099', text3: '#555b66',
  red: '#ff4757', redDim: 'rgba(255,71,87,0.15)', redBorder: 'rgba(255,71,87,0.3)',
  orange: '#ff8c00', orangeDim: 'rgba(255,140,0,0.12)',
  yellow: '#ffd700', yellowDim: 'rgba(255,215,0,0.1)',
  green: '#00e676', greenDim: 'rgba(0,230,118,0.1)',
  blue: '#4dabf7', blueDim: 'rgba(77,171,247,0.1)',
  purple: '#c678dd', cyan: '#56d3f5',
};

// ── Types ──────────────────────────────────────────────────────────────
interface ChatMessage {
  id: string; role: 'user' | 'assistant'; text: string; ts: Date;
  mode?: string; confidenceLevel?: 'high' | 'medium' | 'low';
}

interface QuickPrompt { label: string; icon: string; q: string; }
interface PromptCategory { id: string; label: string; prompts: QuickPrompt[]; }

// ── LLM Provider Presets ───────────────────────────────────────────────
interface ProviderPreset {
  id: string; label: string; endpoint: string; model: string;
  keyPlaceholder: string; keyHint: string; modelHint: string;
  requiresKey?: boolean;
}
const PROVIDERS: ProviderPreset[] = [
  {
    id: 'server', label: 'Server-side key (recommended)',
    endpoint: '/api/llm/chat',
    model: 'meta-llama/Llama-3.1-8B-Instruct',
    keyPlaceholder: 'managed on server — no key needed',
    keyHint: 'The API key is read from the HUGGINGFACE_ACCESS_TOKEN environment variable on the server. It is never stored in or sent from your browser.',
    modelHint: 'Any chat model your server token can access, e.g. meta-llama/Llama-3.1-8B-Instruct, Qwen/Qwen2.5-7B-Instruct.',
    requiresKey: false,
  },
  {
    id: 'huggingface', label: 'Hugging Face',
    endpoint: 'https://router.huggingface.co/v1/chat/completions',
    model: 'meta-llama/Llama-3.1-8B-Instruct',
    keyPlaceholder: 'hf_...',
    keyHint: 'Create a token at huggingface.co/settings/tokens (role: "Read" or "Inference"). Starts with hf_.',
    modelHint: 'Any chat model on HF Inference Providers, e.g. meta-llama/Llama-3.1-8B-Instruct, Qwen/Qwen2.5-7B-Instruct, mistralai/Mistral-7B-Instruct-v0.3',
  },
  {
    id: 'openai', label: 'OpenAI',
    endpoint: 'https://api.openai.com/v1/chat/completions',
    model: 'gpt-4o-mini',
    keyPlaceholder: 'sk-...',
    keyHint: 'API key from platform.openai.com/api-keys.',
    modelHint: 'e.g. gpt-4o, gpt-4o-mini, gpt-4.1-mini',
  },
  {
    id: 'groq', label: 'Groq (fast & free)',
    endpoint: 'https://api.groq.com/openai/v1/chat/completions',
    model: 'llama-3.3-70b-versatile',
    keyPlaceholder: 'gsk_...',
    keyHint: 'Free API key from console.groq.com/keys.',
    modelHint: 'e.g. llama-3.3-70b-versatile, llama-3.1-8b-instant',
  },
  {
    id: 'custom', label: 'Custom (OpenAI-compatible)',
    endpoint: '',
    model: '',
    keyPlaceholder: 'your API key',
    keyHint: 'Any endpoint that implements the OpenAI /chat/completions schema.',
    modelHint: 'The model identifier expected by your endpoint.',
  },
];

// ── DLP (Data Loss Prevention) ─────────────────────────────────────────
// Scans outbound text for sensitive data and redacts it BEFORE anything is
// sent to a third-party LLM, preventing accidental data exfiltration.
interface DlpRule { type: string; label: string; re: RegExp; }
const DLP_RULES: DlpRule[] = [
  { type: 'email', label: 'Email address', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: 'ssn', label: 'SSN', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'credit_card', label: 'Credit card', re: /\b(?:\d[ -]*?){13,16}\b/g },
  { type: 'phone', label: 'Phone number', re: /\b(?:\+?\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b/g },
  { type: 'aws_key', label: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'api_key', label: 'API key / token', re: /\b(?:sk|hf|gsk|ghp|xoxb|pk)[-_][A-Za-z0-9]{16,}\b/g },
  { type: 'jwt', label: 'JWT', re: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
  { type: 'private_ip', label: 'Private IP', re: /\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b/g },
];

interface DlpResult { text: string; hits: Record<string, number>; total: number; }
function applyDlp(input: string): DlpResult {
  let text = input;
  const hits: Record<string, number> = {};
  let total = 0;
  for (const rule of DLP_RULES) {
    text = text.replace(rule.re, (match) => {
      // Skip very short credit-card/phone false positives (need enough digits).
      if ((rule.type === 'credit_card' || rule.type === 'phone') && (match.replace(/\D/g, '').length < 10)) {
        return match;
      }
      hits[rule.type] = (hits[rule.type] || 0) + 1;
      total++;
      return `[REDACTED:${rule.type.toUpperCase()}]`;
    });
  }
  return { text, hits, total };
}

// ── Quick Prompts ──────────────────────────────────────────────────────
const PROMPT_CATEGORIES: PromptCategory[] = [
  {
    id: 'critical', label: '🔴 Critical', prompts: [
      { icon: '🚨', label: 'Top 5 critical threats', q: 'Give me a comprehensive summary of the top 5 most critical insider threats. For each: what happened, when, who, why it is dangerous, and immediate action required.' },
      { icon: '🔥', label: 'Most dangerous user', q: 'Who is the single most dangerous user in this dataset? Provide a full threat profile: their behavior patterns, what specific actions are suspicious, what resources they touched, and what should be done right now.' },
      { icon: '💣', label: 'Active exfiltration risk', q: 'Is there evidence of active data exfiltration or data staging? Identify users who exported large amounts of sensitive data, especially from Customer_Vault, PROD_DB, GL_System, or HRIS. Rank by exfiltration risk.' },
      { icon: '🎯', label: 'Worst single incident', q: 'What is the single highest-risk individual incident in this entire dataset? Explain it in full detail — who, what, when, where, why suspicious, and what the blast radius could be if it is malicious.' },
    ]
  },
  {
    id: 'users', label: '👤 Users', prompts: [
      { icon: '📊', label: 'Risk-rank all users', q: 'Rank all users by insider threat risk. Group into tiers: CRITICAL (immediate action), HIGH (investigate this week), MEDIUM (monitor closely), and LOW (normal). Give specific reasons for top users in each tier.' },
      { icon: '🧟', label: 'Stale account abuse', q: 'Identify all stale or long-inactive accounts that still show recent access events. Which accounts are most dangerous? Who owns them? Are they service accounts or personal accounts? What should happen to each?' },
      { icon: '🔑', label: 'Privilege abuse analysis', q: 'Analyze privilege abuse patterns. Which admin or power-user accounts are using their elevated access in suspicious ways? Are there any normal users accessing resources that seem above their privilege level?' },
      { icon: '👥', label: 'Peer outliers', q: 'Compare users within the same department to identify outliers. Who behaves very differently from their department peers in terms of resource access, timing, or action types? These behavioral outliers are high-priority suspects.' },
    ]
  },
  {
    id: 'behavior', label: '🌙 Behavior', prompts: [
      { icon: '🌙', label: 'Night access deep dive', q: 'Deep dive on all night-time and off-hours access events. Separate legitimate patterns (shift workers, global teams) from suspicious anomalies. Which night-time events are most alarming and why?' },
      { icon: '📤', label: 'Export pattern analysis', q: 'Analyze all data export events in detail. Who is exporting what, when, and from which systems? Identify suspicious export chains (multiple exports from different systems by the same user). Rank export risk.' },
      { icon: '🔒', label: 'Failed auth investigation', q: 'Investigate all failed authentication events. Could any of them be credential stuffing, brute force, or reconnaissance activity? Which users had repeated failures and did they eventually succeed?' },
      { icon: '🗂️', label: 'Sensitive resource access', q: 'Map all access events to our most sensitive resources: Customer_Vault, PROD_DB, GL_System, HRIS, Admin_Console, SIEM. Who has touched these? Any unauthorized or suspicious access patterns?' },
    ]
  },
  {
    id: 'departments', label: '🏢 Departments', prompts: [
      { icon: '📋', label: 'Dept risk ranking', q: 'Rank all departments by insider threat risk level. For each department: number of alerts, critical/high events, most suspicious user, biggest risk factors, and recommended department-level actions.' },
      { icon: '💼', label: 'Finance dept analysis', q: 'Analyze the Finance department specifically. They access GL_System and financial records. Are there any Finance employees showing suspicious patterns? What compliance risk does Finance behavior create?' },
      { icon: '🔐', label: 'Security & IT analysis', q: 'Security and IT teams have privileged access to SIEM, Admin_Console, and critical infrastructure. Analyze their behavior — are any security/IT staff showing insider threat patterns themselves? This is the highest-risk scenario.' },
      { icon: '⚖️', label: 'Legal & Compliance', q: 'Analyze Legal and Compliance department users. They often access sensitive records. Are any compliance officers accessing data outside their mandate? Any conflicts of interest visible in the access logs?' },
    ]
  },
  {
    id: 'compliance', label: '⚖️ Compliance', prompts: [
      { icon: '📜', label: 'CISO executive brief', q: 'Write a concise executive brief for the CISO. Include: threat summary, top 3 incidents needing immediate action, compliance exposure (GDPR/SOX), department breakdown, and a 5-point remediation plan with priority order.' },
      { icon: '🇪🇺', label: 'GDPR exposure', q: 'Assess GDPR Article 32 compliance risk. Which events involve personal data in HRIS or Customer_Vault? Do we have evidence of adequate access controls? What specific events create reportable data breach risk?' },
      { icon: '📈', label: 'SOX controls check', q: 'Assess SOX 302 compliance for financial systems. Who accessed GL_System? Were there admin operations or exports from financial systems? Is there segregation of duties? Flag any control failures.' },
      { icon: '🛡️', label: 'Remediation roadmap', q: 'Create a prioritized remediation roadmap. What security controls should be implemented first? Which account should be disabled first? What monitoring rules should be added? Give a 30/60/90 day action plan.' },
    ]
  },
];

// ── Analysis Engine ────────────────────────────────────────────────────
function fmtTs(ts: string) {
  const d = new Date(ts.replace(' ', 'T'));
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' +
    d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
}

function summarizeEvent(e: EventRow): string {
  const ruleDetails = e.rules_triggered && e.rules_triggered.length
    ? ` | Rules: ${e.rules_triggered.join(', ')}`
    : '';
  return `[${e.sev}/${e.score}] ${e.user} (${e.dept}/${e.priv}): ${e.action.replace(/_/g,' ')} on ${e.resource} at ${fmtTs(e.ts)} [${e.tc.replace(/_/g,' ')}]` +
    ` → ${e.dest.replace(/_/g,' ')} (dest +${e.destScore})` +
    `${e.firstTime ? ` [FIRST-TIME resource access +${e.firstTimeScore}]` : ''}` +
    ` [ML ${Math.round(e.ml_anomaly_score)}/Rule ${Math.round(e.rule_score)}]${ruleDetails}${e.reasons.length ? ' — ' + e.reasons.join('; ') : ''}`;
}

function getTopRiskUsers(data: DerivedData, limit = 12) {
  return Object.entries(data.userRisk)
    .sort((a, b) => b[1].maxScore - a[1].maxScore)
    .slice(0, limit)
    .map(([uid, risk]) => ({ uid, profile: data.profileMap[uid] || {} as Profile, risk, topEvent: [...risk.events].sort((a, b) => b.score - a.score)[0] }));
}

function getDeptRisks(data: DerivedData) {
  const d: Record<string, { dept: string; alerts: number; critical: number; high: number; max: number; stale: number; users: number; exports: number }> = {};
  data.profiles.forEach(p => {
    if (!d[p.dept]) d[p.dept] = { dept: p.dept, alerts: 0, critical: 0, high: 0, max: 0, stale: 0, users: 0, exports: 0 };
    d[p.dept].users++;
    if (p.inactive > 30) d[p.dept].stale++;
  });
  data.anomalous.forEach(e => {
    if (!d[e.dept]) d[e.dept] = { dept: e.dept, alerts: 0, critical: 0, high: 0, max: 0, stale: 0, users: 0, exports: 0 };
    d[e.dept].alerts++;
    if (e.sev === 'CRITICAL') d[e.dept].critical++;
    if (e.sev === 'HIGH') d[e.dept].high++;
    if (e.action === 'export_data') d[e.dept].exports++;
    d[e.dept].max = Math.max(d[e.dept].max, e.score);
  });
  return Object.values(d).sort((a, b) => b.critical * 4 + b.high * 2 + b.max / 10 - (a.critical * 4 + a.high * 2 + a.max / 10));
}

function analyzeQuery(query: string, data: DerivedData, context: ChatMessage[]): string {
  const q = query.toLowerCase();
  const { events, profiles, anomalous, critical, high, medium, userRisk, profileMap } = data;
  const topUsers = getTopRiskUsers(data, 10);
  const depts = getDeptRisks(data);
  const stale = profiles.filter(p => p.inactive > 30).length;
  const nightEvents = anomalous.filter(e => e.tc === 'night' || e.tc === 'unusual_hours').sort((a, b) => b.score - a.score);
  const exports = anomalous.filter(e => e.action === 'export_data').sort((a, b) => b.score - a.score);
  const highExports = events.filter(e => e.action === 'export_data' && (e.sev === 'CRITICAL' || e.sev === 'HIGH'));
  const failed = events.filter(e => e.status === 'failure');
  const topAlerts = [...anomalous].sort((a, b) => b.score - a.score);

  // Check for user mention
  const namedUser = profiles.find(p =>
    q.includes(p.user.toLowerCase()) || q.includes(p.uid.toLowerCase())
  );

  // Check for dept mention
  const namedDept = [...new Set(profiles.map(p => p.dept))].find(dept => q.includes(dept.toLowerCase()));

  // Check for resource mention
  const RESOURCES = ['Customer_Vault', 'PROD_DB', 'GL_System', 'HRIS', 'Admin_Console', 'SIEM', 'Data_Lake', 'BI_Tool', 'Email_Archive', 'File_Share'];
  const namedResource = RESOURCES.find(r => q.includes(r.toLowerCase()) || q.includes(r.replace('_', ' ').toLowerCase()));

  // ── Named user analysis ──────────────────────────────────────────────
  if (namedUser) {
    const risk = userRisk[namedUser.uid] || { maxScore: 0, alertCount: 0, events: [] };
    const userAlerts = [...risk.events].filter(e => e.sev !== 'LOW').sort((a, b) => b.score - a.score);
    const totalEvts = risk.events.length;
    const nightCount = risk.events.filter(e => e.tc === 'night' || e.tc === 'unusual_hours').length;
    const exportCount = risk.events.filter(e => e.action === 'export_data').length;
    const failCount = risk.events.filter(e => e.status === 'failure').length;
    const resources = [...new Set(risk.events.map(e => e.resource))];
    const peerEvents = anomalous.filter(e => e.dept === namedUser.dept && e.uid !== namedUser.uid);
    const peerAvgScore = peerEvents.length > 0
      ? Math.round(peerEvents.reduce((s, e) => s + e.score, 0) / peerEvents.length) : 0;

    const threatLevel = risk.maxScore >= 70 ? '🔴 CRITICAL — Immediate Investigation Required'
      : risk.maxScore >= 50 ? '🟠 HIGH — Investigate This Week'
      : risk.maxScore >= 28 ? '🟡 MEDIUM — Monitor Closely' : '🟢 LOW — Normal Behavior';

    const classification = risk.maxScore >= 70
      ? (exportCount > 2 ? 'Possible Data Exfiltration / Malicious Insider' : nightCount > 3 ? 'Possible Credential Compromise or Malicious Insider' : 'High-Risk Insider Threat')
      : risk.maxScore >= 50 ? 'Negligent User or Policy Violation' : 'Low-Risk — Monitor for Escalation';

    return `## User Investigation: ${namedUser.user}

**Threat Level:** ${threatLevel}
**Classification:** ${classification}

### Profile Summary
| Field | Value |
|-------|-------|
| Department | ${namedUser.dept} |
| Job Title | ${namedUser.job} |
| Privilege | ${namedUser.priv} |
| Days Inactive | ${namedUser.inactive} days |
| Account Status | ${namedUser.active === 'true' ? '✅ Active' : '⛔ Inactive'} |
| Systems Access | ${namedUser.systems || 'N/A'} |

### Risk Metrics
- **Max Risk Score:** ${risk.maxScore}/100 (peer average in ${namedUser.dept}: ${peerAvgScore})
- **Total Alert Events:** ${risk.alertCount} / ${totalEvts} total events
- **Night/Unusual Hour Activity:** ${nightCount} events
- **Data Exports:** ${exportCount} export events
- **Failed Access Attempts:** ${failCount} failures
- **Unique Resources Accessed:** ${resources.length} (${resources.slice(0,5).join(', ')}${resources.length > 5 ? ` +${resources.length-5} more` : ''})

### Top Suspicious Events
${userAlerts.slice(0, 7).map((e, i) => `${i+1}. **[${e.sev} ${e.score}]** ${e.action.replace(/_/g,' ')} on **${e.resource}** at ${fmtTs(e.ts)} (${e.tc.replace(/_/g,' ')})${e.reasons.length ? '\n   Risk factors: ' + e.reasons.join('; ') : ''}`).join('\n\n') || '   No anomalous events found for this user.'}

### Behavioral Analysis
${risk.maxScore >= 70 ? `This user's behavior pattern is **highly concerning**. The combination of ${exportCount > 0 ? `${exportCount} export event(s)` : 'elevated access'}${nightCount > 0 ? `, ${nightCount} off-hours events` : ''}${namedUser.inactive > 20 ? ', and long account inactivity' : ''} suggests this may be a ${exportCount > 2 ? '**data exfiltration scenario**' : '**compromised account or malicious insider**'}.`
  : risk.maxScore >= 50 ? `This user shows **elevated risk indicators** that warrant investigation. Their access patterns deviate from department norms, particularly around ${nightCount > 2 ? 'off-hours access' : 'high-sensitivity resource access'}.`
  : `This user's behavior is **within acceptable parameters** for their role, though the flagged events should be verified with their manager.`}

### Recommended Actions
${risk.maxScore >= 70 ? `1. **IMMEDIATE:** Review and consider temporary account suspension pending investigation
2. **URGENT:** Pull complete 30-day access log and compare with approved business activities
3. **URGENT:** Interview user's manager to validate flagged access events
4. **PRESERVE:** Capture forensic evidence from flagged sessions before any account action
5. **ESCALATE:** Report to CISO if no valid business justification exists`
  : risk.maxScore >= 50 ? `1. **This week:** Request manager validation of flagged access events
2. **Review:** Audit current privilege level against job requirements — consider downgrade if over-privileged
3. **Monitor:** Set enhanced logging on this account for 30 days
4. **Verify:** Confirm business justification for any export events`
  : `1. **Monitor:** Continue standard monitoring — no immediate action required
2. **Log:** Document this review in the user's security record
3. **Reassess:** Re-evaluate in 30 days or if new high-risk events appear`}`;
  }

  // ── Named department ─────────────────────────────────────────────────
  if (namedDept) {
    const deptData = depts.find(d => d.dept === namedDept);
    const deptProfiles = profiles.filter(p => p.dept === namedDept);
    const deptEvents = anomalous.filter(e => e.dept === namedDept).sort((a, b) => b.score - a.score);
    const deptUsers = getTopRiskUsers(data).filter(u => u.profile.dept === namedDept);
    const deptStale = deptProfiles.filter(p => p.inactive > 30).length;

    return `## Department Analysis: ${namedDept}

### Risk Overview
- **Total Staff:** ${deptProfiles.length} users
- **Critical Events:** ${deptData?.critical || 0}
- **High Events:** ${deptData?.high || 0}
- **Total Anomalous Events:** ${deptData?.alerts || 0}
- **Max Risk Score (in dept):** ${deptData?.max || 0}
- **Stale Accounts:** ${deptStale}
- **Export Events:** ${deptData?.exports || 0}

### Top At-Risk Users in ${namedDept}
${deptUsers.slice(0, 5).map((u, i) => `${i+1}. **${u.profile.user || u.uid}** — Score ${u.risk.maxScore}/100, ${u.risk.alertCount} alerts, privilege: ${u.profile.priv}`).join('\n') || '   No high-risk users found in this department.'}

### Top Events
${deptEvents.slice(0, 6).map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n') || '   No anomalous events in this department.'}

### Department Risk Assessment
${(deptData?.critical || 0) >= 3 ? `⚠️ **HIGH DEPARTMENT RISK**: ${namedDept} has ${deptData?.critical} critical events — this department requires priority investigation.`
  : (deptData?.alerts || 0) > 10 ? `🟡 **ELEVATED RISK**: ${namedDept} shows a pattern of repeated anomalous behavior that suggests systemic access control issues.`
  : `🟢 **MODERATE RISK**: ${namedDept} is within acceptable thresholds, though the flagged events should be reviewed.`}

### Recommended Actions
1. Schedule access review with ${namedDept} department head for all flagged users
2. Validate business justification for ${deptData?.exports || 0} export events
3. ${deptStale > 0 ? `Immediately revalidate or disable ${deptStale} stale accounts` : 'No stale account issues'}
4. Implement department-level DLP rules for sensitive resource access`;
  }

  // ── Named resource ───────────────────────────────────────────────────
  if (namedResource) {
    const resEvents = anomalous.filter(e => e.resource === namedResource).sort((a, b) => b.score - a.score);
    const resUsers = [...new Set(resEvents.map(e => e.uid))].map(uid => ({
      uid, profile: profileMap[uid] || {} as Profile,
      count: resEvents.filter(e => e.uid === uid).length,
      maxScore: Math.max(...resEvents.filter(e => e.uid === uid).map(e => e.score))
    })).sort((a, b) => b.maxScore - a.maxScore);

    return `## Resource Analysis: ${namedResource}

### Access Summary
- **Total Anomalous Events:** ${resEvents.length}
- **Critical Events:** ${resEvents.filter(e => e.sev === 'CRITICAL').length}
- **High Events:** ${resEvents.filter(e => e.sev === 'HIGH').length}
- **Unique Users:** ${resUsers.length}
- **Export Events:** ${resEvents.filter(e => e.action === 'export_data').length}
- **Off-Hours Access:** ${resEvents.filter(e => e.tc !== 'business_hours').length}

### Top Users Accessing ${namedResource}
${resUsers.slice(0, 8).map((u, i) => `${i+1}. **${u.profile.user || u.uid}** (${u.profile.dept}, ${u.profile.priv}): ${u.count} events, max score ${u.maxScore}`).join('\n')}

### Top Suspicious Events on ${namedResource}
${resEvents.slice(0, 6).map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n')}

### Risk Assessment
This resource has ${resEvents.filter(e => e.sev === 'CRITICAL' || e.sev === 'HIGH').length} critical/high events suggesting ${resEvents.filter(e => e.action === 'export_data').length > 3 ? 'active exfiltration risk from repeated exports' : 'unauthorized or suspicious access patterns'}. ${resUsers.some(u => u.profile.priv === 'service-account') ? 'Service accounts are accessing this resource — verify they still need access.' : ''}

### Recommended Controls
1. Audit all ${resUsers.length} users who accessed ${namedResource} — validate business need
2. ${resEvents.filter(e => e.action === 'export_data').length > 0 ? `Review ${resEvents.filter(e => e.action === 'export_data').length} export events from this resource — require approval workflow` : 'No exports detected — continue monitoring'}
3. Implement just-in-time access controls for ${namedResource} access
4. Add real-time alerting for any export or admin_operation on this resource`;
  }

  // ── CISO / executive summary ─────────────────────────────────────────
  if (q.includes('ciso') || q.includes('executive') || q.includes('brief') || q.includes('board')) {
    return `## CISO Executive Brief

### Situation Summary
SentinelIQ analyzed **${events.length.toLocaleString()} access events** from ${profiles.length} users. The overall threat posture is **${critical.length >= 10 ? 'HIGH' : critical.length >= 5 ? 'ELEVATED' : 'MODERATE'}**.

### Key Metrics
| Metric | Count |
|--------|-------|
| Critical Events | ${critical.length} |
| High Events | ${high.length} |
| Medium Events | ${medium.length} |
| High-Risk Exports | ${highExports.length} |
| Stale Active Accounts | ${stale} |
| Off-Hours Anomalies | ${nightEvents.length} |

### Top 3 Incidents Requiring Immediate Action
${topAlerts.slice(0,3).map((e,i) => `**${i+1}. ${e.user}** (${e.dept}, ${e.priv})\n   ${e.action.replace(/_/g,' ')} on ${e.resource} — Score ${e.score}/100\n   Risk factors: ${e.reasons.slice(0,2).join('; ')}\n   **Action: ${e.sev === 'CRITICAL' ? 'Investigate immediately, consider suspension' : 'Review with manager this week'}**`).join('\n\n')}

### Department Risk Ranking
${depts.slice(0,5).map((d,i) => `${i+1}. **${d.dept}**: ${d.critical} critical, ${d.high} high, max score ${d.max}`).join('\n')}

### Compliance Exposure
- **GDPR Art.32**: ${events.filter(e=>['HRIS','Customer_Vault'].includes(e.resource)&&e.sev!=='LOW').length} anomalous accesses to personal data systems
- **SOX 302**: ${events.filter(e=>e.resource==='GL_System').length} total GL_System accesses including ${events.filter(e=>e.resource==='GL_System'&&e.action==='export_data').length} exports
- **NIST IR-4**: Detection active; response workflows need formalization

### 30-Day Action Plan
1. **Week 1**: Investigate all ${critical.length} critical events, suspend/validate top 5 risk users
2. **Week 2**: Disable or reauthorize ${stale} stale accounts
3. **Week 3**: Implement export approval workflow for HRIS, PROD_DB, Customer_Vault, GL_System
4. **Week 4**: Deploy real-time alerting for night-time admin operations
5. **Ongoing**: Monthly access certification for all admin and power-user accounts`;
  }

  // ── Stale accounts ───────────────────────────────────────────────────
  if (q.includes('stale') || q.includes('inactive') || q.includes('dormant')) {
    const staleRisk = getTopRiskUsers(data, 20).filter(u => (u.profile.inactive || 0) > 30);
    const staleProfiles = profiles.filter(p => p.inactive > 30);
    const serviceAcctStale = staleProfiles.filter(p => p.priv === 'service-account');

    return `## Stale Account Threat Analysis

### Overview
**${stale} accounts** are inactive for more than 30 days but remain in active access logs. This is a significant security risk as dormant accounts may represent forgotten credentials, compromised accounts, or service accounts with accumulated permissions.

### Breakdown
- **Accounts inactive 30-60 days:** ${profiles.filter(p => p.inactive > 30 && p.inactive <= 60).length}
- **Accounts inactive 60-90 days:** ${profiles.filter(p => p.inactive > 60 && p.inactive <= 90).length}
- **Accounts inactive 90+ days:** ${profiles.filter(p => p.inactive > 90).length}
- **Stale service accounts:** ${serviceAcctStale.length} (highest risk — may have automated access)

### Highest-Risk Stale Accounts
${staleRisk.slice(0,8).map((u,i) => `${i+1}. **${u.profile.user || u.uid}** — Inactive ${u.profile.inactive} days, privilege: ${u.profile.priv}, score ${u.risk.maxScore}/100, ${u.risk.alertCount} alerts\n   Most recent: ${u.topEvent ? `${u.topEvent.action.replace(/_/g,' ')} on ${u.topEvent.resource} (${fmtTs(u.topEvent.ts)})` : 'No events'}`).join('\n\n')}

### Why This Is Dangerous
1. **Credential reuse**: Long-inactive accounts may have weak/reused passwords not updated recently
2. **Forgotten access**: Users who left a team/company may still have access via stale accounts
3. **Service account drift**: Service accounts accumulate permissions over time and are rarely reviewed
4. **No owner accountability**: Dormant accounts often have unclear ownership

### Immediate Remediation Steps
1. **Day 1-3**: Disable all accounts inactive >90 days (${profiles.filter(p => p.inactive > 90).length} accounts)
2. **Day 3-7**: Contact owners of accounts inactive 60-90 days for business justification
3. **Week 2**: Require manager sign-off to reactivate any 30-60 day inactive accounts
4. **Ongoing**: Implement automated 45-day account review policy
5. **Priority**: Start with ${serviceAcctStale.length > 0 ? `${serviceAcctStale.length} stale service accounts` : 'highest-risk users shown above'}`;
  }

  // ── Night/off-hours analysis ─────────────────────────────────────────
  if (q.includes('night') || q.includes('off-hour') || q.includes('unusual hour') || q.includes('midnight') || q.includes('weekend')) {
    const byUser: Record<string, number> = {};
    nightEvents.forEach(e => { byUser[e.user] = (byUser[e.user] || 0) + 1; });
    const topNightUsers = Object.entries(byUser).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const nightExports = nightEvents.filter(e => e.action === 'export_data');
    const nightAdmins = nightEvents.filter(e => e.action === 'admin_operation');

    return `## Off-Hours Access Analysis

### Summary
**${nightEvents.length} high-signal anomalies** occurred during night or unusual hours. Off-hours access to sensitive systems is a key insider threat indicator, especially when combined with export or admin operations.

### Breakdown by Time Classification
- **Night (22:00-06:00):** ${anomalous.filter(e=>e.tc==='night').length} events
- **Unusual Hours:** ${anomalous.filter(e=>e.tc==='unusual_hours').length} events
- **Weekend:** ${anomalous.filter(e=>e.tc==='weekend').length} events
- **Off-hours exports:** ${nightExports.length} — HIGH RISK
- **Off-hours admin operations:** ${nightAdmins.length} — HIGH RISK

### Top Repeat Off-Hours Users
${topNightUsers.map(([user, count], i) => {
  const p = profiles.find(pr => pr.user === user);
  return `${i+1}. **${user}** (${p?.dept || 'Unknown'}, ${p?.priv || 'unknown'}): ${count} off-hours events`;
}).join('\n')}

### Highest-Risk Off-Hours Events
${nightEvents.slice(0, 8).map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n')}

### Interpretation
${nightExports.length > 5 ? `🚨 **CRITICAL**: ${nightExports.length} off-hours exports suggest active data staging or exfiltration. Immediate investigation required.`
  : nightAdmins.length > 3 ? `⚠️ **HIGH RISK**: ${nightAdmins.length} off-hours admin operations suggest unauthorized system changes or reconnaissance.`
  : `⚠️ **ELEVATED**: Off-hours activity is above baseline. Validate business justification for all night/weekend events listed above.`}

Off-hours exports and admin operations are the most concerning combination — they can indicate an insider trying to avoid detection by acting when monitoring is reduced.

### Recommended Actions
1. **Immediate**: Verify business justification for all ${nightExports.length} off-hours exports
2. **Policy**: Implement real-time SIEM alerts for any export_data during night/weekend hours
3. **Review**: Check if any of the repeat users have legitimate business reasons (shift work, international teams)
4. **Block**: Consider requiring MFA re-authentication for admin operations outside business hours`;
  }

  // ── Export / exfiltration ────────────────────────────────────────────
  if (q.includes('export') || q.includes('exfiltrat') || q.includes('data leak')) {
    const exportsByUser: Record<string, EventRow[]> = {};
    exports.forEach(e => { if (!exportsByUser[e.user]) exportsByUser[e.user] = []; exportsByUser[e.user].push(e); });
    const topExporters = Object.entries(exportsByUser).sort((a, b) => b[1].length - a[1].length).slice(0, 8);
    const critExports = exports.filter(e => e.sev === 'CRITICAL');

    return `## Data Export & Exfiltration Risk Analysis

### Overview
**${exports.length} anomalous export events** detected, including **${critExports.length} critical** and **${highExports.length} high-risk** exports. Data exfiltration typically follows a pattern: reconnaissance → access sensitive data → export → exfiltrate.

### Export Volume by Sensitivity
- **High-sensitivity exports:** ${exports.filter(e=>e.sens==='high').length} (Customer_Vault, PROD_DB, HRIS, GL_System)
- **Medium-sensitivity exports:** ${exports.filter(e=>e.sens==='medium').length}
- **Off-hours exports:** ${exports.filter(e=>e.tc!=='business_hours').length} — elevated risk
- **Failed export attempts:** ${events.filter(e=>e.action==='export_data'&&e.status==='failure').length} — reconnaissance indicator

### Top Data Exporters (Suspicious)
${topExporters.map(([user, evs], i) => {
  const p = profiles.find(pr => pr.user === user);
  const maxScore = Math.max(...evs.map(e => e.score));
  const resources = [...new Set(evs.map(e => e.resource))];
  return `${i+1}. **${user}** (${p?.dept || 'Unknown'}, ${p?.priv || 'unknown'}): ${evs.length} exports from ${resources.join(', ')} — max score ${maxScore}`;
}).join('\n')}

### Highest-Risk Export Events
${exports.slice(0, 6).map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n')}

### Exfiltration Risk Assessment
${critExports.length >= 3 ? `🚨 **CRITICAL EXFILTRATION RISK**: ${critExports.length} critical exports detected. Multiple high-sensitivity systems involved. This pattern is consistent with deliberate data exfiltration.`
  : exports.length >= 10 ? `⚠️ **HIGH RISK**: ${exports.length} anomalous exports is above baseline. The pattern of accessing multiple sensitive systems (${[...new Set(exports.map(e=>e.resource))].slice(0,4).join(', ')}) is concerning.`
  : `🟡 **MODERATE RISK**: Export activity is elevated but not yet at critical levels. Validate business justification for the listed events.`}

### Containment Recommendations
1. **Immediate**: Temporarily disable export capability for users with CRITICAL export scores
2. **Investigate**: Pull file/size metadata for exports if available — large exports are more serious
3. **DLP**: Implement Data Loss Prevention rules for HRIS, Customer_Vault, and GL_System exports
4. **Approval workflow**: Require manager + security approval for any high-sensitivity data export
5. **Audit**: Verify destination of all exports — internal vs external, cloud storage, USB, etc.`;
  }

  // ── Failed auth ──────────────────────────────────────────────────────
  if (q.includes('fail') || q.includes('brute') || q.includes('credential') || q.includes('authentication')) {
    const failsByUser: Record<string, number> = {};
    failed.forEach(e => { failsByUser[e.user] = (failsByUser[e.user] || 0) + 1; });
    const laterSuccess = failed.filter(e => {
      const userEvts = events.filter(ev => ev.uid === e.uid && ev.status === 'success' && ev.resource === e.resource);
      return userEvts.some(ev => new Date(ev.ts) > new Date(e.ts));
    });

    return `## Failed Authentication Analysis

### Summary
**${failed.length} failed access attempts** detected. ${laterSuccess.length > 0 ? `**${laterSuccess.length} failures were followed by a successful access to the same resource** — potential credential success after brute-force or credential stuffing.` : ''}

### Failed Attempts by User
${Object.entries(failsByUser).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([user, count], i) => {
  const p = profiles.find(pr => pr.user === user);
  return `${i+1}. **${user}** (${p?.dept || 'Unknown'}): ${count} failures`;
}).join('\n')}

### Failure-then-Success Patterns (Most Dangerous)
${laterSuccess.slice(0, 5).map((e, i) => `${i+1}. **${e.user}** — failed ${e.action.replace(/_/g,' ')} on ${e.resource} at ${fmtTs(e.ts)}, then succeeded later. This could indicate credential stuffing.`).join('\n') || 'No clear failure-then-success patterns detected.'}

### Top Failed Events
${failed.sort((a, b) => b.score - a.score).slice(0, 6).map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n')}

### Recommended Actions
1. **Immediate**: Investigate the ${laterSuccess.length} failure-then-success sequences — these are highest priority
2. **Policy**: Implement account lockout after 3 consecutive failures
3. **MFA**: Enforce MFA for all admin_operation and export_data actions
4. **Monitor**: Set enhanced alerting for ${Object.entries(failsByUser).filter(([,v])=>v>=2).length} users with 2+ failures`;
  }

  // ── Privilege analysis ───────────────────────────────────────────────
  if (q.includes('privilege') || q.includes('admin') || q.includes('power-user') || q.includes('access control')) {
    const admins = profiles.filter(p => p.priv === 'admin');
    const powerUsers = profiles.filter(p => p.priv === 'power-user');
    const svcAccts = profiles.filter(p => p.priv === 'service-account');
    const adminEvents = anomalous.filter(e => e.priv === 'admin');
    const overPrivileged = getTopRiskUsers(data).filter(u => (u.profile.priv === 'admin' || u.profile.priv === 'power-user') && u.risk.maxScore >= 50);

    return `## Privilege & Access Control Analysis

### Privilege Distribution
| Level | Count | Anomalous Events |
|-------|-------|-----------------|
| Admin | ${admins.length} | ${adminEvents.length} |
| Power-User | ${powerUsers.length} | ${anomalous.filter(e=>e.priv==='power-user').length} |
| Service Account | ${svcAccts.length} | ${anomalous.filter(e=>e.priv==='service-account').length} |
| User | ${profiles.filter(p=>p.priv==='user').length} | ${anomalous.filter(e=>e.priv==='user').length} |

### Over-Privileged High-Risk Users
Users with elevated privileges AND high risk scores:
${overPrivileged.slice(0,6).map((u,i) => `${i+1}. **${u.profile.user || u.uid}** (${u.profile.dept}) — ${u.profile.priv} privilege, score ${u.risk.maxScore}/100, ${u.risk.alertCount} alerts`).join('\n') || 'No over-privileged high-risk users found.'}

### Suspicious Admin Activity
${adminEvents.slice(0,6).map((e,i) => `${i+1}. ${summarizeEvent(e)}`).join('\n') || 'No critical/high admin events found.'}

### Service Account Risk
${svcAccts.length > 0 ? `${svcAccts.length} service accounts exist. Service accounts are high-risk because they:\n- Often have elevated permissions\n- Are rarely reviewed or rotated\n- May be used by multiple people\n- Lack individual accountability\n\nService accounts with anomalous events: ${[...new Set(anomalous.filter(e=>e.priv==='service-account').map(e=>e.user))].slice(0,5).join(', ')}` : 'No service accounts with anomalous events.'}

### Privilege Reduction Recommendations
1. Review admin access for all ${admins.length} admin accounts — apply least-privilege
2. Convert service accounts to modern identity solutions with short-lived tokens
3. Implement just-in-time (JIT) privilege for admin_operation actions
4. Quarterly privilege attestation for all power-user and admin accounts`;
  }

  // ── Department ranking ───────────────────────────────────────────────
  if (q.includes('department') || q.includes('dept') || q.includes('team') || q.includes('group')) {
    return `## Department Risk Ranking

${depts.slice(0, 10).map((d, i) => {
  const emoji = d.critical >= 3 ? '🔴' : d.high >= 5 ? '🟠' : d.alerts >= 10 ? '🟡' : '🟢';
  return `### ${i+1}. ${emoji} ${d.dept}
- **Users:** ${d.users} | **Critical Events:** ${d.critical} | **High Events:** ${d.high} | **Total Anomalies:** ${d.alerts}
- **Max Risk Score:** ${d.max} | **Stale Accounts:** ${d.stale} | **Export Events:** ${d.exports}
- **Risk Verdict:** ${d.critical >= 3 ? 'Priority investigation required' : d.high >= 3 ? 'Schedule review this week' : d.alerts >= 5 ? 'Monitor closely' : 'Acceptable risk level'}`;
}).join('\n\n')}

### Key Findings
- **Highest risk department:** ${depts[0]?.dept} with ${depts[0]?.critical} critical events
- **Most export activity:** ${depts.sort((a,b)=>b.exports-a.exports)[0]?.dept} department
- **Most stale accounts:** ${depts.sort((a,b)=>b.stale-a.stale)[0]?.dept} department
- **Departments requiring immediate review:** ${depts.filter(d=>d.critical>=2).map(d=>d.dept).join(', ') || 'None'}`;
  }

  // ── Remediation roadmap ──────────────────────────────────────────────
  if (q.includes('remediat') || q.includes('roadmap') || q.includes('action plan') || q.includes('fix') || q.includes('recommendation')) {
    return `## Prioritized Remediation Roadmap

### Week 1 — Stop the Bleeding (Critical Actions)
1. **Suspend or restrict** the top 3 highest-risk users (scores ${topAlerts.slice(0,3).map(e=>e.score).join(', ')}) pending investigation
2. **Investigate** all ${critical.length} CRITICAL events — assign a security analyst to each
3. **Preserve evidence** — capture session logs, file access records before any account changes
4. **Notify CISO** — current threat level warrants executive awareness

### Week 2 — Account Hygiene
5. **Disable** all accounts inactive >90 days (${profiles.filter(p=>p.inactive>90).length} accounts)
6. **Revalidate** accounts inactive 30-90 days with manager confirmation
7. **Service account audit** — review all ${profiles.filter(p=>p.priv==='service-account').length} service accounts
8. **Revoke excess privileges** — downgrade over-privileged accounts for non-admin roles

### Week 3 — Process Controls
9. **Export approval workflow** — require manager + security sign-off for sensitive data exports
10. **MFA enforcement** — mandatory for all admin_operation and export_data actions
11. **Account lockout policy** — 3 failed logins = temporary lockout with alert
12. **Night-time alerting** — real-time SIEM rule for off-hours admin/export activity

### Month 2 — Systematic Improvements
13. **Quarterly access certification** — all admin/power-user accounts reviewed by managers
14. **Just-in-time access** — implement JIT for admin operations on PROD_DB, Customer_Vault, GL_System
15. **DLP deployment** — Data Loss Prevention for outbound transfers from sensitive systems
16. **Security awareness training** — targeted for departments with highest alert rates

### Month 3 — Measurement & Validation
17. **Rerun risk assessment** — verify reduction in critical/high events
18. **Penetration test** — validate that new controls are effective
19. **Compliance audit** — GDPR/SOX documentation ready for review
20. **Baseline establishment** — use this period as baseline for future anomaly detection`;
  }

  // ── Top risks / general summary ──────────────────────────────────────
  if (q.includes('top') || q.includes('critical') || q.includes('worst') || q.includes('summary') || q.includes('overview')) {
    return `## Threat Intelligence Summary

### Current Threat Posture: ${critical.length >= 10 ? '🔴 CRITICAL' : critical.length >= 5 ? '🟠 HIGH' : '🟡 ELEVATED'}

**${events.length.toLocaleString()} total events** · **${profiles.length} users tracked** · **${critical.length} critical** · **${high.length} high** · **${medium.length} medium**

### Top 5 Most Critical Threats
${topAlerts.slice(0, 5).map((e, i) => `${i+1}. **[${e.sev} ${e.score}] ${e.user}** (${e.dept}, ${e.priv})\n   ${e.action.replace(/_/g,' ')} on **${e.resource}** at ${fmtTs(e.ts)} (${e.tc.replace(/_/g,' ')})\n   Evidence: ${e.reasons.join('; ')}`).join('\n\n')}

### Top 5 Highest-Risk Users
${topUsers.slice(0, 5).map((u, i) => `${i+1}. **${u.profile.user || u.uid}** (${u.profile.dept}, ${u.profile.priv}) — Score ${u.risk.maxScore}/100, ${u.risk.alertCount} alerts`).join('\n')}

### Key Patterns Detected
- **${nightEvents.length}** off-hours access anomalies — ${nightEvents.length > 20 ? 'ALARMING' : 'elevated'}
- **${exports.length}** suspicious export events — ${exports.length > 15 ? 'EXFILTRATION RISK' : 'review required'}
- **${stale}** stale accounts still active — account hygiene issue
- **${failed.length}** failed access attempts — ${failed.length > 20 ? 'possible credential attacks' : 'within normal range'}

### Immediate Priority Actions
1. Investigate the top 3 critical events listed above
2. Review ${stale} stale accounts — disable those without active business need
3. Validate ${highExports.length} high-risk export events with data owners
4. Set real-time alerts for night-time admin operations

*Ask me about a specific user, department, resource, or threat pattern for a deeper analysis.*`;
  }

  // ── Peer comparison / outliers ───────────────────────────────────────
  if (q.includes('peer') || q.includes('outlier') || q.includes('baseline') || q.includes('compar')) {
    const deptOutliers = depts.slice(0, 3).map(dept => {
      const deptUsers = getTopRiskUsers(data).filter(u => u.profile.dept === dept.dept);
      const avg = deptUsers.length ? Math.round(deptUsers.reduce((s,u)=>s+u.risk.maxScore,0)/deptUsers.length) : 0;
      const outliers = deptUsers.filter(u => u.risk.maxScore > avg + 20).slice(0, 3);
      return { dept: dept.dept, avg, outliers };
    });

    return `## Peer Comparison & Behavioral Outlier Analysis

### How This Works
We compare each user's behavior against their departmental peers. Users who deviate significantly from their team baseline are flagged as outliers — these are high-priority investigation targets because their behavior cannot be explained by normal team patterns.

### Department Outliers (Users deviating from team baseline)
${deptOutliers.map(d => `**${d.dept}** (team avg risk score: ${d.avg})\n${d.outliers.length > 0 ? d.outliers.map(u => `  - **${u.profile.user}**: score ${u.risk.maxScore} (+${u.risk.maxScore - d.avg} above average) — ${u.risk.alertCount} alerts`).join('\n') : '  - No significant outliers detected'}`).join('\n\n')}

### Top Behavioral Deviations
${topUsers.slice(0, 5).map((u, i) => {
  const deptAvg = anomalous.filter(e => e.dept === u.profile.dept).length / (profiles.filter(p => p.dept === u.profile.dept).length || 1);
  return `${i+1}. **${u.profile.user || u.uid}** — ${u.risk.alertCount} alerts vs dept avg of ${Math.round(deptAvg)}, score ${u.risk.maxScore}/100`;
}).join('\n')}

### What Outlier Status Means
- **Score 20+ above team average**: Warrants investigation — behavior cannot be explained by normal team patterns
- **Multiple resource types**: Access to resources peers don't use is a red flag
- **Time pattern deviation**: Accessing systems at hours when no peers do suggests either a unique legitimate need or concealment

### Recommended Follow-Up
For each outlier: conduct a structured interview with their manager, review their access requests from the past 90 days, and determine if their job role actually requires the observed level of system access.`;
  }

  // ── Fallback — keyword-based matching ───────────────────────────────
  const terms = q.split(/[^a-z0-9_]+/).filter(t => t.length > 2 &&
    !['the','and','for','with','all','who','what','why','how','give','show','tell','about','risk','user','data','access','event','this'].includes(t));

  const matched = anomalous
    .filter(e => terms.some(t =>
      `${e.user} ${e.uid} ${e.dept} ${e.action} ${e.resource} ${e.sens} ${e.status} ${e.ip} ${e.tc} ${e.sev} ${e.reasons.join(' ')}`.toLowerCase().includes(t)))
    .sort((a, b) => b.score - a.score).slice(0, 8);

  const contextHint = context.length > 0
    ? `\n\n*Note: This is a follow-up to your previous question. For more context, I can analyze specific users, departments, resources, or threat patterns.*`
    : '';

  return `## Analysis: ${query.slice(0, 60)}${query.length > 60 ? '…' : ''}

${matched.length > 0
  ? `### Relevant Evidence (${matched.length} matching events)\n${matched.map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n')}`
  : `### Most Significant Events (no exact keyword match)\n${topAlerts.slice(0, 5).map((e, i) => `${i+1}. ${summarizeEvent(e)}`).join('\n')}`}

### Context
- Dataset: ${events.length.toLocaleString()} events, ${profiles.length} users
- Risk distribution: ${critical.length} critical, ${high.length} high, ${medium.length} medium
- Top resources at risk: ${[...new Set(topAlerts.slice(0,10).map(e=>e.resource))].slice(0,4).join(', ')}

### Suggested Follow-Up Questions
- Ask about a specific user: *"Investigate jacob.patel"*
- Department analysis: *"Analyze Finance department"*
- Resource focus: *"Who accessed Customer_Vault?"*
- Pattern analysis: *"Show me all night access events"*
- Compliance: *"CISO executive brief"*${contextHint}`;
}

// ── Markdown to JSX ────────────────────────────────────────────────────
function RenderMarkdown({ text }: { text: string }) {
  const lines = text.split('\n');
  return (
    <div style={{ fontSize: 13, lineHeight: 1.75, color: C.text2 }}>
      {lines.map((line, i) => {
        if (line.startsWith('## ')) {
          return <div key={i} style={{ fontSize: 15, fontWeight: 700, color: C.text, margin: '0 0 10px', paddingBottom: 6, borderBottom: `1px solid ${C.border2}` }}>{line.slice(3)}</div>;
        }
        if (line.startsWith('### ')) {
          return <div key={i} style={{ fontSize: 13, fontWeight: 700, color: C.blue, margin: '14px 0 6px', textTransform: 'uppercase', letterSpacing: 0.6 }}>{line.slice(4)}</div>;
        }
        if (line === '---' || line === '─'.repeat(line.length)) {
          return <hr key={i} style={{ border: 'none', borderTop: `1px solid ${C.border}`, margin: '12px 0' }} />;
        }
        if (line.startsWith('| ')) {
          const cells = line.split('|').filter(c => c.trim());
          const isHeader = lines[i + 1]?.match(/^\|[-|: ]+\|/);
          const isSep = line.match(/^\|[-|: ]+\|/);
          if (isSep) return null;
          return (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: `repeat(${cells.length}, 1fr)`, gap: 0, borderTop: `1px solid ${C.border}` }}>
              {cells.map((c, j) => (
                <div key={j} style={{ padding: '6px 10px', fontSize: 12, borderRight: j < cells.length - 1 ? `1px solid ${C.border}` : 'none',
                  fontWeight: isHeader ? 700 : 400, color: isHeader ? C.text : C.text2, background: isHeader ? C.bg3 : 'transparent' }}>
                  {renderInline(c.trim())}
                </div>
              ))}
            </div>
          );
        }
        if (line.match(/^\d+\.\s/)) {
          const content = line.replace(/^\d+\.\s/, '');
          const num = line.match(/^(\d+)/)?.[1];
          return (
            <div key={i} style={{ display: 'flex', gap: 10, padding: '3px 0', paddingLeft: 4 }}>
              <div style={{ color: C.blue, fontWeight: 700, fontSize: 12, minWidth: 18, fontFamily: 'monospace' }}>{num}.</div>
              <div style={{ flex: 1, fontSize: 13, color: C.text2 }}>{renderInline(content)}</div>
            </div>
          );
        }
        if (line.startsWith('- ')) {
          return (
            <div key={i} style={{ display: 'flex', gap: 8, padding: '3px 0', paddingLeft: 4, borderLeft: `2px solid ${C.border2}` }}>
              <div style={{ color: C.text3, paddingLeft: 6 }}>•</div>
              <div style={{ flex: 1, fontSize: 13, color: C.text2 }}>{renderInline(line.slice(2))}</div>
            </div>
          );
        }
        if (line.trim() === '') return <div key={i} style={{ height: 8 }} />;
        if (line.startsWith('*Note:')) {
          return <div key={i} style={{ fontSize: 11, color: C.text3, fontStyle: 'italic', marginTop: 10, padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: 6 }}>{line.slice(1, -1)}</div>;
        }
        return <div key={i} style={{ padding: '2px 0', color: C.text2 }}>{renderInline(line)}</div>;
      })}
    </div>
  );
}

function renderInline(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      const inner = part.slice(2, -2);
      const color = inner.includes('CRITICAL') ? C.red : inner.includes('HIGH') ? C.orange : inner.includes('MEDIUM') ? C.yellow : C.text;
      return <strong key={i} style={{ color, fontWeight: 700 }}>{inner}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} style={{ fontFamily: 'monospace', fontSize: 11, background: C.bg3, padding: '1px 5px', borderRadius: 3, color: C.cyan }}>{part.slice(1, -1)}</code>;
    }
    return <span key={i}>{part}</span>;
  });
}

// ── AI Analyst Page ────────────────────────────────────────────────────
export function AIAnalystPage({ data, initQuery, onInitQueryConsumed }: {
  data: DerivedData; initQuery: string | null; onInitQueryConsumed: () => void;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeCat, setActiveCat] = useState('critical');
  const [savedConfig, setSavedConfig] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sentineliq_ai_settings') || '{}'); } catch { return {}; }
  });
  const initialProvider = PROVIDERS.find(p => p.id === savedConfig.provider) || PROVIDERS[0];
  const [provider, setProvider] = useState(initialProvider.id);
  const [aiConfig, setAiConfig] = useState({
    endpoint: savedConfig.endpoint || initialProvider.endpoint,
    model: savedConfig.model || initialProvider.model,
    key: savedConfig.key || '',
  });
  const [dlpEnabled, setDlpEnabled] = useState(savedConfig.dlpEnabled !== false);
  const [configOpen, setConfigOpen] = useState(false);
  const chatRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const savedPreset = PROVIDERS.find(p => p.id === savedConfig.provider) || PROVIDERS[0];
  const savedNeedsKey = savedPreset.requiresKey !== false;
  const liveReady = !!(savedConfig.endpoint && savedConfig.model && (!savedNeedsKey || savedConfig.key));

  useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  useEffect(() => {
    if (initQuery) {
      setInput(initQuery);
      onInitQueryConsumed();
      setTimeout(() => sendMessage(initQuery), 100);
    }
  }, [initQuery]);

  async function sendMessage(overrideText?: string) {
    const text = (overrideText || input).trim();
    if (!text || isLoading) return;

    const userMsg: ChatMessage = { id: Date.now().toString(), role: 'user', text, ts: new Date() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    if (textareaRef.current) {
      textareaRef.current.style.height = '44px';
    }

    try {
      if (liveReady) {
        const preset = PROVIDERS.find(p => p.id === (savedConfig.provider || PROVIDERS[0].id)) || PROVIDERS[0];
        const needsKey = preset.requiresKey !== false;

        const topUsers = Object.entries(data.userRisk).sort((a, b) => b[1].maxScore - a[1].maxScore).slice(0, 30).map(([uid, r]) => ({
          uid, user: data.profileMap[uid]?.user, dept: data.profileMap[uid]?.dept,
          priv: data.profileMap[uid]?.priv, inactive: data.profileMap[uid]?.inactive,
          maxScore: r.maxScore, alerts: r.alertCount
        }));
        const topEvents = [...data.anomalous].sort((a, b) => b.score - a.score).slice(0, 50).map(e => ({
          user: e.user, dept: e.dept, action: e.action, resource: e.resource,
          score: e.score, sev: e.sev, tc: e.tc, ts: e.ts, reasons: e.reasons,
          ml_anomaly_score: e.ml_anomaly_score, rule_score: e.rule_score, explanation: e.explanation
        }));

        const sysPrompt = `You are SentinelIQ's senior cybersecurity AI analyst. You have access to a complete insider threat dataset.

Dataset summary:
- Total events: ${data.events.length}
- Critical events: ${data.critical.length}
- High events: ${data.high.length}
- Total users: ${data.profiles.length}
- Model precision: ${Math.round(data.metrics.precision * 100)}%
- Model recall: ${Math.round(data.metrics.recall * 100)}%
- Model F1: ${Math.round(data.metrics.f1_score * 100)}%
- High-risk exports: ${data.events.filter(e=>e.action==='export_data'&&(e.sev==='CRITICAL'||e.sev==='HIGH')).length}
- Stale accounts: ${data.profiles.filter(p=>p.inactive>30).length}

Event records include ml_anomaly_score, rule_score, rules_triggered, and analyst explanations. Use these values to distinguish pure statistical anomalies from rule-based hits.

Top risk users: ${JSON.stringify(topUsers.slice(0,15))}
Top anomalous events: ${JSON.stringify(topEvents.slice(0,30))}

Conversation history: ${messages.slice(-4).map(m => `${m.role}: ${m.text.slice(0,200)}`).join('\n')}

Be specific. Cite names, scores, rules, and evidence. Use markdown formatting with ## headers, **bold**, and numbered lists.`;

        // ── DLP: redact sensitive data BEFORE it leaves the browser ──
        let outSys = sysPrompt, outUser = text, dlpNote = '';
        if (dlpEnabled) {
          const sysScan = applyDlp(sysPrompt);
          const userScan = applyDlp(text);
          outSys = sysScan.text;
          outUser = userScan.text;
          const total = sysScan.total + userScan.total;
          if (total > 0) {
            const types = Array.from(new Set([...Object.keys(sysScan.hits), ...Object.keys(userScan.hits)]));
            dlpNote = `DLP redacted ${total} sensitive item(s) before sending to the model: ${types.join(', ')}.`;
          }
        }

        // Create a placeholder assistant message and stream tokens into it.
        const msgId = (Date.now() + 1).toString();
        setMessages(prev => [...prev, {
          id: msgId, role: 'assistant', text: '', ts: new Date(),
          mode: needsKey ? 'live AI…' : 'live AI (server-side key)…', confidenceLevel: 'high'
        }]);

        try {
          const ctrl = new AbortController();
          const timer = setTimeout(() => ctrl.abort(), 60000);
          const headers: Record<string, string> = { 'Content-Type': 'application/json' };
          if (needsKey) headers['Authorization'] = `Bearer ${savedConfig.key}`;

          const res = await fetch(savedConfig.endpoint, {
            method: 'POST', signal: ctrl.signal, headers,
            body: JSON.stringify({
              model: savedConfig.model, temperature: 0.2, max_tokens: 1200, stream: true,
              messages: [{ role: 'system', content: outSys }, { role: 'user', content: outUser }]
            })
          });

          if (!res.ok || !res.body) {
            const errBody = await res.text().catch(() => '');
            let detail: any = errBody;
            try { detail = JSON.parse(errBody)?.error?.message || JSON.parse(errBody)?.error || errBody; } catch { /* keep raw */ }
            throw new Error(`HTTP ${res.status} — ${typeof detail === 'string' ? detail.slice(0, 300) : JSON.stringify(detail).slice(0, 300)}`);
          }

          let acc = '';
          const contentType = res.headers.get('content-type') || '';

          if (!contentType.includes('event-stream')) {
            // Non-streaming endpoint: parse the full JSON response.
            const d = await res.json();
            acc = d.choices?.[0]?.message?.content || d.output_text || d.content?.[0]?.text || '';
            setMessages(prev => prev.map(m => m.id === msgId ? { ...m, text: acc } : m));
          } else {
            // Streaming SSE: append delta tokens as they arrive.
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              const lines = buffer.split('\n');
              buffer = lines.pop() || '';
              for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed.startsWith('data:')) continue;
                const payload = trimmed.slice(5).trim();
                if (!payload || payload === '[DONE]') continue;
                try {
                  const json = JSON.parse(payload);
                  const delta = json.choices?.[0]?.delta?.content || '';
                  if (delta) {
                    acc += delta;
                    setMessages(prev => prev.map(m => m.id === msgId ? { ...m, text: acc } : m));
                  }
                } catch { /* ignore keep-alive / partial chunks */ }
              }
            }
          }

          clearTimeout(timer);
          if (!acc.trim()) throw new Error('Empty response from model. Check that the model ID is correct and supports chat completions.');

          const finalText = dlpNote ? `${acc}\n\n---\n*${dlpNote}*` : acc;
          const finalMode = `live AI: ${savedConfig.model}${dlpNote ? ' · DLP active' : ''}`;
          setMessages(prev => prev.map(m => m.id === msgId ? { ...m, text: finalText, mode: finalMode } : m));
        } catch (err) {
          const fallback = `**Live AI unavailable:** ${(err as Error).message}\n\n` + analyzeQuery(text, data, messages);
          setMessages(prev => prev.map(m => m.id === msgId ? { ...m, text: fallback, mode: 'local fallback', confidenceLevel: 'medium' } : m));
        }
      } else {
        await new Promise(r => setTimeout(r, 300 + Math.random() * 400));
        const response = analyzeQuery(text, data, messages);
        setMessages(prev => [...prev, {
          id: (Date.now() + 1).toString(), role: 'assistant', text: response, ts: new Date(),
          mode: 'local analyst', confidenceLevel: 'medium'
        }]);
      }
    } finally {
      setIsLoading(false);
    }
  }

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  }

  function handleTextareaChange(e: React.ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value);
    e.target.style.height = '44px';
    e.target.style.height = Math.min(e.target.scrollHeight, 160) + 'px';
  }

  function copyMessage(text: string) {
    navigator.clipboard.writeText(text);
  }

  function exportConversation() {
    const md = messages.map(m => `**${m.role === 'user' ? 'You' : 'SentinelIQ AI'}** (${m.ts.toLocaleTimeString()})\n\n${m.text}`).join('\n\n---\n\n');
    const blob = new Blob([md], { type: 'text/markdown' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'sentineliq-analysis.md'; document.body.appendChild(a); a.click(); a.remove();
  }

  function clearConversation() { setMessages([]); }

  function runQuickPrompt(q: string) {
    setInput(q);
    setTimeout(() => sendMessage(q), 50);
  }

  function selectProvider(id: string) {
    setProvider(id);
    const preset = PROVIDERS.find(p => p.id === id);
    if (preset && id !== 'custom') {
      setAiConfig(prev => ({ ...prev, endpoint: preset.endpoint, model: preset.model }));
    }
  }

  function saveConfig() {
    const cfg = {
      provider,
      endpoint: aiConfig.endpoint.trim(),
      model: aiConfig.model.trim(),
      key: aiConfig.key.trim(),
      dlpEnabled,
    };
    localStorage.setItem('sentineliq_ai_settings', JSON.stringify(cfg));
    setSavedConfig(cfg);
    setConfigOpen(false);
  }

  const activeCatData = PROMPT_CATEGORIES.find(c => c.id === activeCat) || PROMPT_CATEGORIES[0];

  const statsData = [
    { n: data.events.length.toLocaleString(), l: 'Events', c: C.blue },
    { n: data.profiles.length, l: 'Users', c: C.text2 },
    { n: data.critical.length, l: 'Critical', c: C.red },
    { n: data.high.length, l: 'High', c: C.orange },
    { n: `${Math.round(data.metrics.f1_score * 100)}%`, l: 'Model F1', c: C.green },
    { n: `${Math.round(data.metrics.precision * 100)}%`, l: 'Precision', c: C.green },
    { n: `${Math.round(data.metrics.recall * 100)}%`, l: 'Recall', c: C.green },
    { n: data.profiles.filter(p=>p.inactive>30).length, l: 'Stale Accts', c: C.yellow },
  ];

  return (
    <div style={{ padding: 24, display: 'flex', gap: 16, height: 'calc(100vh - 57px)', overflow: 'hidden' }}>
      {/* Main chat area */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 0 }}>
        {/* Dataset stat bar */}
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', background: 'rgba(77,171,247,0.06)',
          border: `1px solid rgba(77,171,247,0.15)`, borderRadius: 8, padding: '10px 16px', marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.blue, textTransform: 'uppercase', letterSpacing: 0.8 }}>Context Loaded</div>
          <div style={{ width: 1, height: 16, background: C.border2 }} />
          {statsData.map(s => (
            <div key={s.l} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ fontWeight: 700, color: s.c, fontSize: 13 }}>{s.n}</span>
              <span style={{ fontSize: 11, color: C.text3 }}>{s.l}</span>
            </div>
          ))}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            {messages.length > 0 && (
              <>
                <button onClick={exportConversation}
                  style={{ padding: '4px 10px', borderRadius: 5, fontSize: 11, background: C.bg3,
                    border: `1px solid ${C.border}`, color: C.text2, cursor: 'pointer' }}>
                  ⬇ Export
                </button>
                <button onClick={clearConversation}
                  style={{ padding: '4px 10px', borderRadius: 5, fontSize: 11, background: C.bg3,
                    border: `1px solid ${C.border}`, color: C.text2, cursor: 'pointer' }}>
                  ✕ Clear
                </button>
              </>
            )}
            <button onClick={() => setConfigOpen(!configOpen)}
              style={{ padding: '4px 10px', borderRadius: 5, fontSize: 11,
                background: liveReady ? 'rgba(0,230,118,0.1)' : C.bg3,
                border: `1px solid ${liveReady ? 'rgba(0,230,118,0.3)' : C.border}`,
                color: liveReady ? C.green : C.text2, cursor: 'pointer' }}>
              {liveReady ? '● Live AI' : '⚙ Configure AI'}
            </button>
          </div>
        </div>

        {/* Live AI config panel */}
        {configOpen && (
          <div style={{ background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 10, padding: 16, marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Live AI Configuration</div>
              <button onClick={() => setConfigOpen(false)} style={{ background: 'none', border: 'none', color: C.text3, cursor: 'pointer', fontSize: 16 }}>✕</button>
            </div>
            {/* Provider selector */}
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 10, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>Provider</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {PROVIDERS.map(p => (
                  <button key={p.id} onClick={() => selectProvider(p.id)}
                    style={{ padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                      background: provider === p.id ? 'rgba(77,171,247,0.15)' : C.bg3,
                      border: `1px solid ${provider === p.id ? C.blue : C.border}`,
                      color: provider === p.id ? C.blue : C.text2 }}>{p.label}</button>
                ))}
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
              {(() => {
                const preset = PROVIDERS.find(p => p.id === provider) || PROVIDERS[0];
                const noKey = preset.requiresKey === false;
                const fields = [
                  { label: 'Endpoint URL', key: 'endpoint', placeholder: 'https://...', type: 'text', readOnly: provider !== 'custom' },
                  { label: 'Model', key: 'model', placeholder: preset.model || 'model-id', type: 'text', readOnly: false },
                  { label: 'API Key', key: 'key', placeholder: preset.keyPlaceholder, type: 'password', readOnly: noKey },
                ];
                return fields.map(f => (
                  <div key={f.key}>
                    <div style={{ fontSize: 10, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 5 }}>{f.label}</div>
                    <input type={f.type} placeholder={f.placeholder} readOnly={f.readOnly}
                      value={aiConfig[f.key as keyof typeof aiConfig] ?? ''}
                      onChange={e => setAiConfig(prev => ({ ...prev, [f.key]: e.target.value }))}
                      style={{ width: '100%', background: f.readOnly ? C.bg2 : C.bg, border: `1px solid ${C.border2}`, borderRadius: 6,
                        padding: '8px 10px', color: f.readOnly ? C.text2 : C.text, fontSize: 12, fontFamily: 'monospace', outline: 'none' }} />
                  </div>
                ));
              })()}
            </div>
            {(() => {
              const preset = PROVIDERS.find(p => p.id === provider) || PROVIDERS[0];
              return (
                <div style={{ marginTop: 10, fontSize: 11, color: C.text3, lineHeight: 1.6 }}>
                  <div>🔑 <strong style={{ color: C.text2 }}>API key:</strong> {preset.keyHint}</div>
                  <div>🤖 <strong style={{ color: C.text2 }}>Model:</strong> {preset.modelHint}</div>
                </div>
              );
            })()}
            {/* DLP toggle */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginTop: 14, padding: '10px 12px', background: C.bg, borderRadius: 8,
              border: `1px solid ${dlpEnabled ? 'rgba(0,230,118,0.3)' : C.border}` }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.text }}>
                  Data Loss Prevention (DLP)
                </div>
                <div style={{ fontSize: 11, color: C.text3, marginTop: 2 }}>
                  Redacts emails, SSNs, card numbers, API keys, JWTs and private IPs from prompts before they reach the model.
                </div>
              </div>
              <button onClick={() => setDlpEnabled(v => !v)}
                style={{ flexShrink: 0, marginLeft: 12, width: 46, height: 24, borderRadius: 12, cursor: 'pointer',
                  border: 'none', position: 'relative', transition: 'background 0.15s',
                  background: dlpEnabled ? C.green : C.bg4 }}
                aria-pressed={dlpEnabled} aria-label="Toggle Data Loss Prevention">
                <span style={{ position: 'absolute', top: 3, left: dlpEnabled ? 25 : 3, width: 18, height: 18,
                  borderRadius: '50%', background: '#fff', transition: 'left 0.15s' }} />
              </button>
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button onClick={saveConfig}
                style={{ padding: '7px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                  background: C.blue, border: 'none', color: '#000', cursor: 'pointer' }}>Save & Activate</button>
              <button onClick={() => {
                  localStorage.removeItem('sentineliq_ai_settings');
                  setSavedConfig({});
                  setProvider(PROVIDERS[0].id);
                  setAiConfig({ endpoint: PROVIDERS[0].endpoint, model: PROVIDERS[0].model, key: '' });
                  setDlpEnabled(true);
                  setConfigOpen(false);
                }}
                style={{ padding: '7px 16px', borderRadius: 6, fontSize: 12, background: C.bg3,
                  border: `1px solid ${C.border}`, color: C.text2, cursor: 'pointer' }}>Clear</button>
            </div>
            <div style={{ fontSize: 11, color: C.text3, marginTop: 10 }}>
              {liveReady
                ? `✅ Live AI active: ${savedConfig.model} · streaming on · DLP ${savedConfig.dlpEnabled !== false ? 'on' : 'off'}`
                : 'Not configured — using local analyst (no API key required)'}
            </div>
          </div>
        )}

        {/* Chat window */}
        <div ref={chatRef} style={{ flex: 1, overflowY: 'auto', background: C.bg,
          border: `1px solid ${C.border}`, borderBottom: 'none', borderRadius: '10px 10px 0 0',
          padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {messages.length === 0 && !isLoading && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', gap: 12, color: C.text3, padding: '40px 20px', textAlign: 'center' }}>
              <div style={{ fontSize: 40 }}>✦</div>
              <div style={{ fontSize: 16, fontWeight: 600, color: C.text2 }}>SentinelIQ AI Analyst</div>
              <div style={{ fontSize: 13, color: C.text3, maxWidth: 420, lineHeight: 1.6 }}>
                Ask anything about the threat data. Use the quick prompts on the right, or type your own question.
                The analyst has full context of all <strong style={{ color: C.text2 }}>{data.events.length.toLocaleString()}</strong> events and <strong style={{ color: C.text2 }}>{data.profiles.length}</strong> user profiles.
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                {['Top critical threats', 'Who is the highest risk user?', 'CISO executive brief', 'Night access analysis'].map(s => (
                  <button key={s} onClick={() => runQuickPrompt(s)}
                    style={{ padding: '6px 12px', borderRadius: 6, fontSize: 12, background: 'rgba(77,171,247,0.08)',
                      border: `1px solid rgba(77,171,247,0.2)`, color: C.blue, cursor: 'pointer' }}>{s}</button>
                ))}
              </div>
            </div>
          )}

          {messages.map(msg => (
            <div key={msg.id} style={{ display: 'flex', flexDirection: 'column',
              alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start', gap: 4, animation: 'fadeUp 0.2s ease' }}>
              {/* Avatar + meta */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: C.text3,
                flexDirection: msg.role === 'user' ? 'row-reverse' : 'row' }}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center',
                  justifyContent: 'center', fontSize: 11, fontWeight: 700, flexShrink: 0,
                  background: msg.role === 'user' ? 'rgba(77,171,247,0.2)' : 'rgba(198,120,221,0.2)',
                  color: msg.role === 'user' ? C.blue : C.purple }}>
                  {msg.role === 'user' ? 'Y' : '✦'}
                </div>
                <span>{msg.role === 'user' ? 'You' : 'SentinelIQ AI'}</span>
                <span>{msg.ts.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</span>
                {msg.mode && <span style={{ color: C.text3, fontStyle: 'italic' }}>via {msg.mode}</span>}
              </div>

              {/* Bubble */}
              <div style={{ maxWidth: msg.role === 'user' ? '80%' : '100%', width: msg.role === 'assistant' ? '100%' : 'auto',
                padding: '12px 16px', borderRadius: 10,
                ...(msg.role === 'user' ? {
                  background: 'linear-gradient(135deg,rgba(77,171,247,0.18),rgba(77,171,247,0.10))',
                  border: `1px solid rgba(77,171,247,0.25)`, borderBottomRightRadius: 4, color: C.text
                } : {
                  background: 'linear-gradient(135deg,rgba(24,27,34,0.96),rgba(17,19,24,0.98))',
                  border: `1px solid ${C.border2}`, borderBottomLeftRadius: 4
                }) }}>
                {msg.role === 'user'
                  ? <div style={{ fontSize: 13, lineHeight: 1.6, color: C.text, whiteSpace: 'pre-wrap' }}>{msg.text}</div>
                  : <RenderMarkdown text={msg.text} />
                }
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: 6, opacity: 0.7 }}
                onMouseEnter={el => (el.currentTarget.style.opacity = '1')}
                onMouseLeave={el => (el.currentTarget.style.opacity = '0.7')}>
                <button onClick={() => copyMessage(msg.text)}
                  style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, background: C.bg3,
                    border: `1px solid ${C.border}`, color: C.text3, cursor: 'pointer' }}>
                  Copy
                </button>
                {msg.role === 'assistant' && (
                  <button onClick={() => runQuickPrompt('Tell me more about ' + msg.text.split('\n')[0].replace(/[#*]/g,'').trim().slice(0,50))}
                    style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, background: C.bg3,
                      border: `1px solid ${C.border}`, color: C.text3, cursor: 'pointer' }}>
                    Dig deeper
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Loading indicator */}
          {isLoading && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 6, animation: 'fadeUp 0.2s ease' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: C.text3 }}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center',
                  justifyContent: 'center', background: 'rgba(198,120,221,0.2)', color: C.purple, fontSize: 11, fontWeight: 700 }}>✦</div>
                <span>SentinelIQ AI</span>
                <span style={{ color: C.text3, fontStyle: 'italic' }}>{liveReady ? `calling ${savedConfig.model}…` : 'analyzing threat data…'}</span>
              </div>
              <div style={{ padding: '14px 18px', background: 'linear-gradient(135deg,rgba(24,27,34,0.96),rgba(17,19,24,0.98))',
                border: `1px solid ${C.border2}`, borderRadius: 10, borderBottomLeftRadius: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {[0, 0.2, 0.4].map((delay, i) => (
                    <div key={i} style={{ width: 6, height: 6, borderRadius: '50%', background: C.blue,
                      animation: `bounce 1.4s ${delay}s infinite` }} />
                  ))}
                  <span style={{ fontSize: 12, color: C.text3, marginLeft: 6 }}>Processing {data.events.length.toLocaleString()} events…</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Input area */}
        <div style={{ background: C.bg2, border: `1px solid ${C.border2}`, borderTop: 'none',
          borderRadius: '0 0 10px 10px', padding: 12, display: 'flex', gap: 10, alignItems: 'flex-end' }}>
          <textarea ref={textareaRef} value={input} onChange={handleTextareaChange} onKeyDown={handleKey}
            placeholder="Ask about any user, threat, export pattern, department, or compliance issue… (Enter to send, Shift+Enter for newline)"
            style={{ flex: 1, background: C.bg3, border: `1px solid ${C.border2}`, borderRadius: 8,
              padding: '10px 14px', color: C.text, fontFamily: 'inherit', fontSize: 13, resize: 'none',
              minHeight: 44, maxHeight: 160, outline: 'none', lineHeight: 1.5, transition: 'border-color 0.15s' }}
            onFocus={el => (el.currentTarget.style.borderColor = C.blue)}
            onBlur={el => (el.currentTarget.style.borderColor = C.border2)} />
          <button onClick={() => sendMessage()} disabled={!input.trim() || isLoading}
            style={{ width: 44, height: 44, borderRadius: 8, border: 'none', cursor: isLoading || !input.trim() ? 'not-allowed' : 'pointer',
              background: isLoading ? C.bg4 : !input.trim() ? C.bg3 : C.blue,
              color: isLoading ? C.text3 : !input.trim() ? C.text3 : '#000',
              fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0, transition: 'all 0.15s' }}>
            {isLoading ? '⏳' : '↑'}
          </button>
        </div>
      </div>

      {/* Right panel */}
      <div style={{ width: 268, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto' }}>
        {/* Quick prompts */}
        <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.text3 }}>Quick Analysis</div>
            <div style={{ fontSize: 10, color: C.text3, marginLeft: 'auto' }}>{PROMPT_CATEGORIES.reduce((s,c)=>s+c.prompts.length,0)} prompts</div>
          </div>
          <div style={{ padding: '10px 12px 8px' }}>
            <div style={{ display: 'flex', gap: 4, marginBottom: 10, flexWrap: 'wrap' }}>
              {PROMPT_CATEGORIES.map(cat => (
                <button key={cat.id} onClick={() => setActiveCat(cat.id)}
                  style={{ padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                    cursor: 'pointer', border: `1px solid ${activeCat === cat.id ? 'rgba(77,171,247,0.4)' : C.border}`,
                    background: activeCat === cat.id ? C.blueDim : C.bg3,
                    color: activeCat === cat.id ? C.blue : C.text3, transition: 'all 0.15s' }}>
                  {cat.label}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {activeCatData.prompts.map((p, i) => (
                <button key={i} onClick={() => runQuickPrompt(p.q)}
                  style={{ width: '100%', textAlign: 'left', background: C.bg3, border: `1px solid ${C.border}`,
                    borderRadius: 6, padding: '7px 10px', color: C.text2, fontSize: 11, cursor: 'pointer',
                    fontFamily: 'inherit', display: 'flex', alignItems: 'center', gap: 7, lineHeight: 1.4,
                    transition: 'all 0.15s' }}
                  onMouseEnter={el => { el.currentTarget.style.background = C.bg4; el.currentTarget.style.color = C.text; }}
                  onMouseLeave={el => { el.currentTarget.style.background = C.bg3; el.currentTarget.style.color = C.text2; }}>
                  <span style={{ fontSize: 14, flexShrink: 0 }}>{p.icon}</span>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Threat snapshot */}
        <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.text3 }}>Threat Snapshot</div>
          </div>
          <div style={{ padding: 14 }}>
            {[
              { label: 'Critical Events', value: data.critical.length, color: C.red, max: Math.max(data.critical.length, 1) },
              { label: 'High Events', value: data.high.length, color: C.orange, max: Math.max(data.high.length, 1) },
              { label: 'Stale Accounts', value: data.profiles.filter(p=>p.inactive>30).length, color: C.yellow, max: data.profiles.length },
              { label: 'High-Risk Exports', value: data.events.filter(e=>e.action==='export_data'&&(e.sev==='CRITICAL'||e.sev==='HIGH')).length, color: C.purple, max: data.events.filter(e=>e.action==='export_data').length || 1 },
              { label: 'Off-Hours Anomalies', value: data.anomalous.filter(e=>e.tc!=='business_hours').length, color: C.cyan, max: data.anomalous.length || 1 },
            ].map(s => (
              <div key={s.label} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                  <span style={{ color: C.text2 }}>{s.label}</span>
                  <span style={{ fontWeight: 700, color: s.color }}>{s.value}</span>
                </div>
                <div style={{ height: 4, background: C.bg3, borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min((s.value/s.max)*100, 100)}%`, background: s.color, borderRadius: 2, transition: 'width 0.3s' }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top risk users quick list */}
        <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.text3 }}>Top Risk Users</div>
          </div>
          <div style={{ padding: '8px 0' }}>
            {getTopRiskUsers(data, 8).map((u, i) => (
              <div key={u.uid} onClick={() => runQuickPrompt(`Investigate ${u.profile.user || u.uid}`)}
                style={{ padding: '7px 14px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10,
                  transition: 'background 0.15s' }}
                onMouseEnter={el => (el.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
                onMouseLeave={el => (el.currentTarget.style.background = 'transparent')}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center',
                  justifyContent: 'center', fontSize: 9, fontWeight: 700, flexShrink: 0,
                  background: `${scoreColor(u.risk.maxScore)}22`, color: scoreColor(u.risk.maxScore) }}>
                  {(u.profile.user || u.uid).slice(0, 2).toUpperCase()}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.profile.user || u.uid}</div>
                  <div style={{ fontSize: 10, color: C.text3 }}>{u.profile.dept}</div>
                </div>
                <div style={{ fontSize: 12, fontWeight: 700, color: scoreColor(u.risk.maxScore), flexShrink: 0 }}>{u.risk.maxScore}</div>
              </div>
            ))}
          </div>
        </div>

        {/* AI mode status */}
        <div style={{ background: liveReady ? 'rgba(0,230,118,0.06)' : C.bg2,
          border: `1px solid ${liveReady ? 'rgba(0,230,118,0.2)' : C.border}`, borderRadius: 10, padding: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: liveReady ? C.green : C.text3, marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            {liveReady ? '● Live AI Active' : '◎ Local Analyst'}
          </div>
          <div style={{ fontSize: 11, color: C.text3, lineHeight: 1.5 }}>
            {liveReady
              ? `Connected to ${savedConfig.model}. Responses use real-time inference with full dataset context.`
              : 'Using built-in analysis engine. All responses are generated locally from the dataset — no API required. For GPT-4/Claude responses, configure a Live AI endpoint above.'}
          </div>
        </div>
      </div>

      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
        @keyframes bounce { 0%,60%,100%{transform:translateY(0)} 30%{transform:translateY(-6px)} }
      `}</style>
    </div>
  );
}
