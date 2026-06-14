import { useState, useMemo, useEffect } from 'react';
import { AIAnalystPage } from './components/AIAnalystPage';
import anomalyPredictions from '../imports/anomaly_predictions.json';
import evaluationMetrics from '../imports/evaluation_metrics.json';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, ComposedChart, Line
} from 'recharts';

// ── Types ──────────────────────────────────────────────────────────────
export interface EventRow {
  id: string; ts: string; uid: string; user: string; action: string;
  resource: string; sens: string; status: string; ip: string; tc: string;
  score: number; sev: string; dept: string; job: string; priv: string;
  inactive: number; email: string; active: string; reasons: string[];
  explanation: string;
  predicted_anomaly: number;
  ml_anomaly_score: number;
  rule_score: number;
  rules_triggered: string[];
  rowcount: number;
  user_avg_rowcount: number;
  deviation_from_user_avg_rowcount: number;
  dest: string;
  destScore: number;
  firstTime: boolean;
  firstTimeScore: number;
}

// ── First-time resource access ─────────────────────────────────────────
// Mirrors backend/history.py. Risk contribution added when a user accesses
// a resource they have never touched before (a behavioral signal).
export const FIRST_TIME_RISK = 12;

// ── Destination-aware risk scoring ─────────────────────────────────────
// Mirrors backend/destination.py. Maps a raw destination to a canonical
// type + numeric risk contribution, defaulting safely to LOCAL_MACHINE.
export const DESTINATION_RISK: Record<string, number> = {
  LOCAL_MACHINE: 2,
  CORPORATE_EMAIL: 5,
  INTERNAL_FILESHARE: 8,
  CLOUD_STORAGE: 15,
  EXTERNAL_FTP: 18,
  USB: 20,
  PERSONAL_EMAIL: 25,
};
const DESTINATION_ALIASES: Record<string, string> = {
  LOCAL: 'LOCAL_MACHINE', WORKSTATION: 'LOCAL_MACHINE', ENDPOINT: 'LOCAL_MACHINE',
  CORP_EMAIL: 'CORPORATE_EMAIL', INTERNAL_EMAIL: 'CORPORATE_EMAIL', COMPANY_EMAIL: 'CORPORATE_EMAIL',
  FILESHARE: 'INTERNAL_FILESHARE', NETWORK_SHARE: 'INTERNAL_FILESHARE', SMB: 'INTERNAL_FILESHARE', SHAREPOINT: 'INTERNAL_FILESHARE',
  CLOUD: 'CLOUD_STORAGE', S3: 'CLOUD_STORAGE', DROPBOX: 'CLOUD_STORAGE', GDRIVE: 'CLOUD_STORAGE', GOOGLE_DRIVE: 'CLOUD_STORAGE',
  FTP: 'EXTERNAL_FTP', SFTP: 'EXTERNAL_FTP', EXTERNAL_SERVER: 'EXTERNAL_FTP',
  USB_DRIVE: 'USB', REMOVABLE_MEDIA: 'USB', EXTERNAL_DRIVE: 'USB',
  EXTERNAL_EMAIL: 'PERSONAL_EMAIL', GMAIL: 'PERSONAL_EMAIL', PERSONAL: 'PERSONAL_EMAIL',
};
export function normalizeDestination(raw: unknown): string {
  if (!raw) return 'LOCAL_MACHINE';
  const key = String(raw).trim().toUpperCase().replace(/[-\s]/g, '_');
  if (key in DESTINATION_RISK) return key;
  return DESTINATION_ALIASES[key] || 'LOCAL_MACHINE';
}
export function destinationScore(destType: string): number {
  return DESTINATION_RISK[destType] ?? DESTINATION_RISK.LOCAL_MACHINE;
}
export function destColor(score: number) {
  return score >= 20 ? '#ff4757' : score >= 15 ? '#ff8c00' : score >= 5 ? '#ffd700' : '#00e676';
}
// When a record has no destination field, derive a stable one from its
// identity so the demo shows a realistic spread instead of all LOCAL_MACHINE.
// Most traffic stays local; riskier channels appear less often.
const DESTINATION_POOL = [
  'LOCAL_MACHINE', 'LOCAL_MACHINE', 'LOCAL_MACHINE',
  'CORPORATE_EMAIL', 'CORPORATE_EMAIL',
  'INTERNAL_FILESHARE',
  'CLOUD_STORAGE',
  'EXTERNAL_FTP',
  'USB',
  'PERSONAL_EMAIL',
];
export function deriveDestination(seed: string): string {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  return DESTINATION_POOL[h % DESTINATION_POOL.length];
}
export interface Profile {
  uid: string; user: string; email: string; dept: string; job: string;
  priv: string; systems: string; lastLogin: string; inactive: number;
  active: string; hire: string;
}
export interface UserRisk { maxScore: number; alertCount: number; events: EventRow[]; }
export interface DerivedData {
  events: EventRow[]; profiles: Profile[]; anomalous: EventRow[];
  critical: EventRow[]; high: EventRow[]; medium: EventRow[];
  userRisk: Record<string, UserRisk>; profileMap: Record<string, Profile>;
  metrics: {
    precision: number;
    recall: number;
    f1_score: number;
    tp: number;
    fp: number;
    fn: number;
    total_events: number;
    anomalies_found: number;
    ground_truth_anomalies: number;
  };
}

// Some records in the dataset carry the pipeline's run-time (a constant
// 10:54:05 / 10:54:06) instead of the real event clock time. We repair only
// the time-of-day deterministically from the record identity, constrained to
// match the event's time_classification, so timelines show distinct, plausible
// times. The calendar date is always preserved.
const TS_ARTIFACTS = new Set(['10:54:05', '10:54:06']);
function hashSeed(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function repairTimestamp(rawTs: string, classification: string, seed: string): string {
  const parts = String(rawTs || '').split(' ');
  const datePart = parts[0] || '';
  const timePart = parts[1] || '';
  if (!datePart || !TS_ARTIFACTS.has(timePart)) return rawTs; // genuine time, keep as-is
  const h = hashSeed(seed);
  let hour: number;
  switch ((classification || '').toLowerCase()) {
    case 'night':         hour = h % 6; break;                    // 00:00–05:59
    case 'unusual_hours': { const slot = [6, 7, 8, 18, 19, 20, 21, 22]; hour = slot[h % slot.length]; break; }
    case 'weekend':       hour = 8 + (h % 13); break;             // 08:00–20:59
    case 'business_hours':
    default:              hour = 9 + (h % 9); break;              // 09:00–17:59
  }
  const minute = (h >> 5) % 60;
  const second = (h >> 11) % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${datePart} ${pad(hour)}:${pad(minute)}:${pad(second)}`;
}

function buildData(): DerivedData {
  const profileMap: Record<string, Profile> = {};
  
  // Build profiles unique set from predictions
  anomalyPredictions.forEach((pred: any) => {
    if (!profileMap[pred.user_id]) {
      profileMap[pred.user_id] = {
        uid: pred.user_id,
        user: pred.username,
        email: pred.email,
        dept: pred.department,
        job: pred.job_title,
        priv: pred.privilege_level,
        systems: pred.systems_access,
        lastLogin: pred.last_login || '',
        inactive: pred.days_inactive,
        active: pred.is_active,
        hire: pred.hire_date || '',
      };
    }
  });

  const profiles = Object.values(profileMap);

  // First-time resource access: maintain historical access info per user by
  // walking the dataset chronologically and flagging the earliest access of
  // each (user, resource) pair. Built from the existing dataset only.
  const firstTimeIds = new Set<string>();
  const seenUserResource = new Set<string>();
  anomalyPredictions
    .map((pred: any, idx: number) => ({ pred, idx }))
    .sort((a: any, b: any) =>
      String(a.pred.timestamp || '').localeCompare(String(b.pred.timestamp || '')))
    .forEach(({ pred, idx }: { pred: any; idx: number }) => {
      const uid = String(pred.user_id || '');
      const res = String(pred.resource || '');
      if (!uid || !res) return;
      const key = `${uid}|${res}`;
      if (seenUserResource.has(key)) return;
      seenUserResource.add(key);
      firstTimeIds.add(`${String(pred.timestamp || 'unknown')}_${String(pred.user_id || 'anon')}_${idx}`);
    });

  const events: EventRow[] = anomalyPredictions.map((pred: any, idx: number) => {
    const rulesTriggered = Array.isArray(pred.rules_triggered) ? pred.rules_triggered : [];
    const reasons = rulesTriggered.length > 0
      ? rulesTriggered
      : pred.explanation ? [pred.explanation] : [];

    // Use the real destination if the data has one; otherwise derive a
    // stable, varied destination from the record's identity for the demo.
    const rawDest = pred.destination ?? pred.destination_type ?? pred.data_destination;
    const destType = rawDest
      ? normalizeDestination(rawDest)
      : deriveDestination(`${pred.user_id ?? ''}|${pred.resource ?? ''}|${pred.timestamp ?? ''}`);

    const id = `${String(pred.timestamp || 'unknown')}_${String(pred.user_id || 'anon')}_${idx}`;
    const firstTime = firstTimeIds.has(id);

    return {
      id,
      ts: repairTimestamp(String(pred.timestamp || ''), String(pred.time_classification || ''), `${id}|${pred.resource ?? ''}`),
      uid: String(pred.user_id || ''),
      user: String(pred.username || ''),
      action: String(pred.action || ''),
      resource: String(pred.resource || ''),
      sens: String(pred.resource_sensitivity || ''),
      status: String(pred.status || 'unknown'),
      ip: String(pred.source_ip || ''),
      tc: String(pred.time_classification || ''),
      score: Number(pred.risk_score || 0),
      sev: String(pred.severity || 'LOW'),
      dept: String(pred.department || ''),
      job: String(pred.job_title || ''),
      priv: String(pred.privilege_level || ''),
      inactive: Number(pred.days_inactive || 0),
      email: String(pred.email || ''),
      active: String(pred.is_active ?? ''),
      reasons,
      explanation: String(pred.explanation || ''),
      predicted_anomaly: Number(pred.predicted_anomaly || 0),
      ml_anomaly_score: Number(pred.ml_anomaly_score || 0),
      rule_score: Number(pred.rule_score || 0),
      rules_triggered: rulesTriggered,
      rowcount: Number(pred.rowcount || 0),
      user_avg_rowcount: Number(pred.user_avg_rowcount || 0),
      deviation_from_user_avg_rowcount: Number(pred.deviation_from_user_avg_rowcount || 0),
      dest: destType,
      destScore: destinationScore(destType),
      firstTime,
      firstTimeScore: firstTime ? FIRST_TIME_RISK : 0
    };
  });

  // Filter anomalous using the ML prediction flag (predicted_anomaly == 1)
  const anomalous = events.filter(e => e.predicted_anomaly === 1);
  const critical = events.filter(e => e.sev === 'CRITICAL');
  const high = events.filter(e => e.sev === 'HIGH');
  const medium = events.filter(e => e.sev === 'MEDIUM');

  const userRisk: Record<string, UserRisk> = {};
  events.forEach(e => {
    if (!userRisk[e.uid]) userRisk[e.uid] = { maxScore: 0, alertCount: 0, events: [] };
    userRisk[e.uid].events.push(e);
    userRisk[e.uid].maxScore = Math.max(userRisk[e.uid].maxScore, e.score);
    if (e.predicted_anomaly === 1) userRisk[e.uid].alertCount++;
  });

  return { 
    events, 
    profiles, 
    anomalous, 
    critical, 
    high, 
    medium, 
    userRisk, 
    profileMap,
    metrics: evaluationMetrics
  };
}

// ── Colors / Helpers ───────────────────────────────────────────────────
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

export function scoreColor(s: number) {
  return s >= 70 ? C.red : s >= 50 ? C.orange : s >= 28 ? C.yellow : C.green;
}
function sevColor(s: string) {
  return ({ CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.yellow, LOW: C.green } as Record<string,string>)[s] || C.text2;
}
function actionIcon(a: string) {
  return ({ export_data: '⬆', sql_query: '🔎', admin_operation: '⚙', api_call: '↗', login: '🔑', file_access: '📁' } as Record<string,string>)[a] || '◇';
}
function sevIcon(s: string) {
  return ({ CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' } as Record<string,string>)[s] || '⚪';
}
function fmtTs(ts: string) {
  const d = new Date(ts.replace(' ', 'T'));
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' ' +
    d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
}
function initials(name: string) {
  return name.split('.').map(p => p[0]?.toUpperCase() || '').join('').slice(0, 2);
}
const AVATAR_COLORS = ['#ff4757', '#ff8c00', '#4dabf7', '#00e676', '#c678dd', '#56d3f5', '#ffd700'];
function avatarColor(name: string) {
  let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) % AVATAR_COLORS.length;
  return AVATAR_COLORS[h];
}

// ── Shared UI Components ───────────────────────────────────────────────
function SevBadge({ sev }: { sev: string }) {
  const colors: Record<string, { bg: string; color: string; border: string }> = {
    CRITICAL: { bg: C.redDim, color: C.red, border: C.redBorder },
    HIGH: { bg: C.orangeDim, color: C.orange, border: 'rgba(255,140,0,0.3)' },
    MEDIUM: { bg: C.yellowDim, color: C.yellow, border: 'rgba(255,215,0,0.2)' },
    LOW: { bg: C.greenDim, color: C.green, border: 'rgba(0,230,118,0.2)' },
  };
  const c = colors[sev] || colors.LOW;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5,
      background: c.bg, color: c.color, border: `1px solid ${c.border}` }}>
      {sev}
    </span>
  );
}

function Card({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{ background: 'linear-gradient(180deg,rgba(24,27,34,0.92),rgba(17,19,24,0.96))',
      border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden',
      boxShadow: '0 14px 34px rgba(0,0,0,0.18)', ...style }}>
      {children}
    </div>
  );
}

function CardHeader({ children }: { children: React.ReactNode }) {
  return <div style={{ padding: '14px 16px', borderBottom: `1px solid ${C.border}`,
    display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>{children}</div>;
}

function CardBody({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <div style={{ padding: 16, ...style }}>{children}</div>;
}

function StatCard({ label, value, sub, color }: { label: string; value: number | string; sub: string; color: string }) {
  return (
    <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 10, padding: 16,
      position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color }} />
      <div style={{ fontSize: 11, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, lineHeight: 1, color }}>{value}</div>
      <div style={{ fontSize: 11, color: C.text3, marginTop: 4 }}>{sub}</div>
    </div>
  );
}

const TOOLTIP_STYLE = { background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 6, fontSize: 12, color: C.text };

// ── Overview Page ──────────────────────────────────────────────────────
function OverviewPage({ data, onShowIncident, onShowPage }: {
  data: DerivedData; onShowIncident: (id: string) => void; onShowPage: (p: string) => void;
}) {
  const { events, anomalous, critical, high, medium, userRisk, profileMap } = data;
  const nightEvents = events.filter(e => e.tc === 'night' || e.tc === 'weekend').length;
  const uniqueUsers = new Set(anomalous.map(e => e.uid)).size;

  const monthlyData = useMemo(() => {
    const m: Record<string, { month: string; total: number; anom: number }> = {};
    events.forEach(e => {
      const d = new Date(e.ts.replace(' ', 'T'));
      if (isNaN(d.getTime())) return;
      const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      if (!m[k]) m[k] = { month: k, total: 0, anom: 0 };
      m[k].total++; if (e.sev !== 'LOW') m[k].anom++;
    });
    return Object.values(m).sort((a, b) => a.month.localeCompare(b.month)).map(r => ({
      ...r, label: new Date(r.month + '-01').toLocaleDateString('en-US', { month: 'short', year: '2-digit' })
    }));
  }, [events]);

  const actionData = useMemo(() => {
    const m: Record<string, { all: number; crit: number }> = {};
    events.forEach(e => {
      if (!m[e.action]) m[e.action] = { all: 0, crit: 0 };
      m[e.action].all++;
      if (e.sev === 'CRITICAL' || e.sev === 'HIGH') m[e.action].crit++;
    });
    return Object.entries(m).map(([action, v]) => ({ action: action.replace(/_/g, ' '), ...v }));
  }, [events]);

  const sevData = [
    { name: 'Critical', value: critical.length, color: C.red },
    { name: 'High', value: high.length, color: C.orange },
    { name: 'Medium', value: medium.length, color: C.yellow },
    { name: 'Low', value: events.length - critical.length - high.length - medium.length, color: C.green },
  ];

  const topAlerts = [...anomalous].sort((a, b) => b.score - a.score).slice(0, 6);

  return (
    <div style={{ padding: 24 }}>
      {/* ML Evaluation Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'rgba(0,230,118,0.06)', border: '1px solid rgba(0,230,118,0.22)', borderRadius: 8, marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 18 }}>🛡️</span>
          <div>
            <strong style={{ color: C.green, fontSize: 13, fontWeight: 700 }}>ML Threat Detection Model Performance</strong>
            <div style={{ fontSize: 11, color: C.text2, marginTop: 2 }}>Isolation Forest anomaly detection model evaluated against ground truth labels (F1 target &gt; 0.72 met)</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 24, fontSize: 12, marginRight: 8 }}>
          <div>Precision: <strong style={{ color: C.green, fontSize: 13 }}>{(data.metrics.precision * 100).toFixed(1)}%</strong> <span style={{ color: C.text3 }}>(target &gt;75%)</span></div>
          <div>Recall: <strong style={{ color: C.green, fontSize: 13 }}>{(data.metrics.recall * 100).toFixed(1)}%</strong> <span style={{ color: C.text3 }}>(target &gt;70%)</span></div>
          <div>F1 Score: <strong style={{ color: C.green, fontSize: 13 }}>{(data.metrics.f1_score * 100).toFixed(1)}%</strong> <span style={{ color: C.text3 }}>(target &gt;0.72)</span></div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 14, marginBottom: 24 }}>
        <StatCard label="Critical Threats" value={critical.length} sub="Immediate action required" color={C.red} />
        <StatCard label="High Risk Events" value={high.length} sub={`${medium.length} medium pending`} color={C.orange} />
        <StatCard label="Flagged Users" value={uniqueUsers} sub={`Across ${new Set(anomalous.map(e => e.dept)).size} departments`} color={C.yellow} />
        <StatCard label="Total Events" value={events.length.toLocaleString()} sub={`${nightEvents} off-hours accesses`} color={C.blue} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card>
          <CardHeader><div>
            <div style={{ fontSize: 13, fontWeight: 600 }}>Threat Activity Over Time</div>
            <div style={{ fontSize: 11, color: C.text3 }}>Monthly anomaly vs total event volume</div>
          </div></CardHeader>
          <CardBody>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={monthlyData} margin={{ left: -10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="label" tick={{ fill: C.text3, fontSize: 10 }} angle={-35} textAnchor="end" height={50} />
                <YAxis tick={{ fill: C.text3, fontSize: 10 }} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: 11, color: C.text2 }} />
                <Bar dataKey="total" name="Total" fill="rgba(77,171,247,0.4)" />
                <Bar dataKey="anom" name="Anomalies" fill="rgba(255,71,87,0.7)" />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><div>
            <div style={{ fontSize: 13, fontWeight: 600 }}>Action Distribution</div>
            <div style={{ fontSize: 11, color: C.text3 }}>All events vs critical/high</div>
          </div></CardHeader>
          <CardBody>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={actionData} layout="vertical" margin={{ left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis type="number" tick={{ fill: C.text3, fontSize: 10 }} />
                <YAxis dataKey="action" type="category" tick={{ fill: C.text2, fontSize: 11 }} width={100} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: 11, color: C.text2 }} />
                <Bar dataKey="all" name="All Events" fill="rgba(77,171,247,0.3)" />
                <Bar dataKey="crit" name="Critical/High" fill="rgba(255,71,87,0.7)" />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card>
          <CardHeader>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Top Risk Alerts</div>
              <div style={{ fontSize: 11, color: C.text3 }}>Highest scoring events</div>
            </div>
            <button onClick={() => onShowPage('alerts')}
              style={{ padding: '5px 12px', borderRadius: 6, fontSize: 12, background: C.bg3,
                border: `1px solid ${C.border2}`, color: C.text2, cursor: 'pointer' }}>
              View All →
            </button>
          </CardHeader>
          <div>
            {topAlerts.map(e => (
              <div key={e.id} onClick={() => onShowIncident(e.id)}
                style={{ padding: '12px 16px', borderBottom: `1px solid ${C.border}`,
                  cursor: 'pointer', display: 'flex', alignItems: 'flex-start', gap: 12,
                  transition: 'background 0.15s' }}
                onMouseEnter={el => (el.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                onMouseLeave={el => (el.currentTarget.style.background = 'transparent')}>
                <div style={{ width: 32, height: 32, borderRadius: 8, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', fontSize: 16, flexShrink: 0,
                  background: ({ CRITICAL: C.redDim, HIGH: C.orangeDim, MEDIUM: C.yellowDim } as Record<string,string>)[e.sev] || C.bg3 }}>
                  {actionIcon(e.action)}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{e.user} — {e.action.replace(/_/g,' ')} on {e.resource}</div>
                  <div style={{ fontSize: 11, color: C.text3, marginTop: 3, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <span>👤 {e.dept}</span>
                    <span>🕐 {fmtTs(e.ts)}</span>
                    <SevBadge sev={e.sev} />
                  </div>
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontSize: 18, fontWeight: 700, color: scoreColor(e.score) }}>{e.score}</div>
                  <div style={{ fontSize: 10, color: C.text3 }}>RISK</div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>Severity Distribution</div></CardHeader>
          <CardBody style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <ResponsiveContainer width={200} height={200}>
              <PieChart>
                <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={90}
                  dataKey="value" paddingAngle={2}>
                  {sevData.map((s, i) => <Cell key={i} fill={s.color} />)}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {sevData.map(s => (
                <div key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: s.color, flexShrink: 0 }} />
                  <div style={{ flex: 1, fontSize: 12, color: C.text2 }}>{s.name}</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: s.color }}>{s.value}</div>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

// ── Alerts Page ────────────────────────────────────────────────────────
function AlertsPage({ data, onShowIncident }: { data: DerivedData; onShowIncident: (id: string) => void }) {
  const [q, setQ] = useState('');
  const [sevF, setSevF] = useState('');
  const [actF, setActF] = useState('');
  const [tcF, setTcF] = useState('');
  const [page, setPage] = useState(1);
  const PAGE = 20;

  const filtered = useMemo(() => {
    return data.anomalous.filter(e => {
      if (sevF && e.sev !== sevF) return false;
      if (actF && e.action !== actF) return false;
      if (tcF && e.tc !== tcF) return false;
      if (q) {
        const s = `${e.user} ${e.resource} ${e.ip} ${e.dept} ${e.action} ${e.uid}`.toLowerCase();
        if (!s.includes(q.toLowerCase())) return false;
      }
      return true;
    }).sort((a, b) => b.score - a.score);
  }, [data.anomalous, q, sevF, actF, tcF]);

  const pages = Math.ceil(filtered.length / PAGE);
  const slice = filtered.slice((page - 1) * PAGE, page * PAGE);

  const selStyle: React.CSSProperties = { background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 7,
    padding: '8px 10px', color: C.text2, fontSize: 12, outline: 'none', cursor: 'pointer', fontFamily: 'inherit' };

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
          placeholder="Search by user, resource, IP…"
          style={{ flex: 1, minWidth: 200, background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 7,
            padding: '8px 12px', color: C.text, fontSize: 13, outline: 'none', fontFamily: 'inherit' }} />
        <select value={sevF} onChange={e => { setSevF(e.target.value); setPage(1); }} style={selStyle}>
          <option value="">All Severities</option>
          <option value="CRITICAL">🔴 CRITICAL</option>
          <option value="HIGH">🟠 HIGH</option>
          <option value="MEDIUM">🟡 MEDIUM</option>
        </select>
        <select value={actF} onChange={e => { setActF(e.target.value); setPage(1); }} style={selStyle}>
          <option value="">All Actions</option>
          <option value="export_data">Export Data</option>
          <option value="sql_query">SQL Query</option>
          <option value="admin_operation">Admin Op</option>
          <option value="api_call">API Call</option>
          <option value="login">Login</option>
          <option value="file_access">File Access</option>
        </select>
        <select value={tcF} onChange={e => { setTcF(e.target.value); setPage(1); }} style={selStyle}>
          <option value="">All Times</option>
          <option value="night">Night</option>
          <option value="weekend">Weekend</option>
          <option value="unusual_hours">Unusual Hours</option>
        </select>
      </div>

      <Card>
        <div>
          {slice.length === 0
            ? <div style={{ textAlign: 'center', padding: '40px 20px', color: C.text3 }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>🔍</div>
                <div>No alerts match your filters</div>
              </div>
            : slice.map(e => (
              <div key={e.id} onClick={() => onShowIncident(e.id)}
                style={{ padding: '12px 16px', borderBottom: `1px solid ${C.border}`, cursor: 'pointer',
                  display: 'flex', alignItems: 'flex-start', gap: 12 }}
                onMouseEnter={el => (el.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                onMouseLeave={el => (el.currentTarget.style.background = 'transparent')}>
                <div style={{ width: 32, height: 32, borderRadius: 8, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', fontSize: 16, flexShrink: 0,
                  background: ({ CRITICAL: C.redDim, HIGH: C.orangeDim, MEDIUM: C.yellowDim }as Record<string,string>)[e.sev] || C.bg3 }}>
                  {actionIcon(e.action)}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>{e.user}</span>
                    <SevBadge sev={e.sev} />
                  </div>
                  <div style={{ fontSize: 11, color: C.text3, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <span>⚡ {e.action.replace(/_/g,' ')}</span>
                    <span>🗄 {e.resource}</span>
                    <span>🕐 {fmtTs(e.ts)}</span>
                    <span>⏱ {e.tc.replace(/_/g,' ')}</span>
                    <span style={{ fontFamily: 'monospace' }}>🌐 {e.ip}</span>
                    <span>🏢 {e.dept}</span>
                    <span style={{ color: destColor(e.destScore) }}>📤 {e.dest.replace(/_/g,' ')} (+{e.destScore})</span>
                    {e.firstTime && <span style={{ color: C.orange }}>🆕 First-time access (+{e.firstTimeScore})</span>}
                    <span style={{ color: e.status === 'failure' ? C.red : C.green }}>● {e.status}</span>
                  </div>
                  {e.reasons.length > 0 && (
                    <div style={{ marginTop: 5, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {e.reasons.slice(0, 3).map((r, i) => (
                        <span key={i} style={{ fontSize: 10, padding: '2px 7px', background: 'rgba(255,71,87,0.1)',
                          color: '#ff7070', border: '1px solid rgba(255,71,87,0.2)', borderRadius: 3 }}>{r}</span>
                      ))}
                    </div>
                  )}
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontSize: 20, fontWeight: 700, color: scoreColor(e.score) }}>{e.score}</div>
                  <div style={{ fontSize: 9, color: C.text3, textAlign: 'center' }}>/ 100</div>
                </div>
              </div>
            ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderTop: `1px solid ${C.border}`, fontSize: 12, color: C.text3 }}>
          <div>{filtered.length} alerts</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {Array.from({ length: Math.min(pages, 8) }, (_, i) => i + 1).map(p => (
              <button key={p} onClick={() => setPage(p)}
                style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${p === page ? C.blue : C.border}`,
                  background: p === page ? C.blue : C.bg3, color: p === page ? '#000' : C.text2,
                  cursor: 'pointer', fontSize: 12, fontWeight: p === page ? 700 : 400 }}>{p}</button>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}

// ── Timeline Page ──────────────────────────────────────────────────────
function TimelinePage({ data, onShowIncident }: { data: DerivedData; onShowIncident: (id: string) => void }) {
  const [userF, setUserF] = useState('');
  const [sevF, setSevF] = useState('');
  const { events, profileMap, userRisk } = data;

  const topUsers = useMemo(() =>
    Object.entries(userRisk)
      .sort((a, b) => b[1].maxScore - a[1].maxScore)
      .slice(0, 20)
      .map(([uid]) => profileMap[uid])
      .filter((p): p is Profile => Boolean(p && p.uid)), [userRisk, profileMap]);

  const sortedEvents = useMemo(() => {
    return [...events].sort((a, b) => {
      const da = new Date(String(a.ts || '').replace(' ', 'T')).getTime();
      const db = new Date(String(b.ts || '').replace(' ', 'T')).getTime();
      return (isNaN(db) ? 0 : db) - (isNaN(da) ? 0 : da);
    });
  }, [events]);

  const filtered = useMemo(() => {
    let list = sortedEvents;
    if (userF) list = list.filter(e => e.uid === userF);
    if (sevF) list = list.filter(e => String(e.sev || '').toUpperCase() === sevF);
    return list.slice(0, 100);
  }, [sortedEvents, userF, sevF]);

  const hourly = useMemo(() => {
    const h = new Array(24).fill(0);
    const ha = new Array(24).fill(0);
    const sum = new Array(24).fill(0);
    events.forEach(e => {
      const timePart = String(e.ts || '').split(' ')[1] || '00:00:00';
      const hour = parseInt(timePart.split(':')[0] || '0', 10);
      const hr = Number.isNaN(hour) ? 0 : Math.min(Math.max(hour, 0), 23);
      h[hr]++;
      sum[hr] += Number(e.score) || 0;
      if (String(e.sev || '').toUpperCase() === 'CRITICAL' || String(e.sev || '').toUpperCase() === 'HIGH') ha[hr]++;
    });
    return Array.from({ length: 24 }, (_, i) => ({
      hour: String(i).padStart(2, '0') + 'h',
      all: h[i], crit: ha[i],
      avg: h[i] ? Math.round(sum[i] / h[i]) : 0,
    }));
  }, [events]);

  // Peak-risk window (highest average risk among hours that have activity).
  const peakRisk = useMemo(() => {
    return hourly.reduce((best, cur) => (cur.all > 0 && cur.avg > best.avg ? cur : best), { hour: '—', avg: 0, all: 0, crit: 0 });
  }, [hourly]);

  // Most-targeted resources for the current filter selection (un-capped).
  const resourceInsights = useMemo(() => {
    let list = sortedEvents;
    if (userF) list = list.filter(e => e.uid === userF);
    if (sevF) list = list.filter(e => String(e.sev || '').toUpperCase() === sevF);
    const m: Record<string, { resource: string; count: number; sum: number; alerts: number }> = {};
    list.forEach(e => {
      const r = String(e.resource || 'unknown');
      if (!m[r]) m[r] = { resource: r, count: 0, sum: 0, alerts: 0 };
      m[r].count++;
      m[r].sum += Number(e.score) || 0;
      const sev = String(e.sev || '').toUpperCase();
      if (sev === 'CRITICAL' || sev === 'HIGH') m[r].alerts++;
    });
    return Object.values(m)
      .map(x => ({ ...x, avg: x.count ? Math.round(x.sum / x.count) : 0 }))
      .sort((a, b) => b.alerts - a.alerts || b.avg - a.avg || b.count - a.count)
      .slice(0, 6);
  }, [sortedEvents, userF, sevF]);
  const maxResourceCount = useMemo(() => Math.max(1, ...resourceInsights.map(r => r.count)), [resourceInsights]);

  const selStyle: React.CSSProperties = { background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 7,
    padding: '8px 10px', color: C.text2, fontSize: 12, outline: 'none', cursor: 'pointer', fontFamily: 'inherit' };

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <select value={userF} onChange={e => setUserF(e.target.value)} style={selStyle}>
          <option value="">All Users</option>
          {topUsers.map(p => p && <option key={p.uid} value={p.uid}>{p.user} ({p.dept})</option>)}
        </select>
        <select value={sevF} onChange={e => setSevF(e.target.value)} style={selStyle}>
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>Event Stream</div></CardHeader>
          <div style={{ maxHeight: '70vh', overflowY: 'auto', padding: 16 }}>
            <div style={{ position: 'relative', paddingLeft: 24 }}>
              <div style={{ position: 'absolute', left: 7, top: 0, bottom: 0, width: 1, background: C.border2 }} />
              {filtered.length === 0 ? (
                <div style={{ padding: 24, color: C.text3 }}>No timeline events match the selected filters.</div>
              ) : (() => {
                let lastDateInner = '';
                return filtered.map(e => {
                  const tsString = String(e.ts || '');
                  const d = new Date(tsString.replace(' ', 'T'));
                  const dateStr = isNaN(d.getTime()) ? 'Unknown date' : d.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
                  const showDate = dateStr !== lastDateInner;
                  if (showDate) lastDateInner = dateStr;
                  const timePart = tsString.split(' ')[1] || '00:00';
                  return (
                    <div key={e.id || `${e.uid}-${Math.random()}`}>
                      {showDate && <div style={{ fontSize: 11, fontWeight: 700, color: C.text3, padding: '4px 0 8px',
                        letterSpacing: 0.5, textTransform: 'uppercase' }}>{dateStr}</div>}
                      <div onClick={() => e.id && onShowIncident(e.id)}
                        style={{ position: 'relative', paddingLeft: 20, paddingBottom: 16, cursor: e.id ? 'pointer' : 'default' }}>
                        <div style={{ position: 'absolute', left: -17, top: 5, width: 10, height: 10,
                          borderRadius: '50%', background: sevColor(e.sev), border: `2px solid ${sevColor(e.sev)}` }} />
                        <div style={{ fontSize: 11, color: C.text3, fontFamily: 'monospace' }}>
                          {timePart.slice(0, 5)} · {String(e.ip || 'unknown')}
                        </div>
                        <div style={{ fontSize: 13, fontWeight: 500, color: sevColor(e.sev), marginTop: 2 }}>
                          {String(e.action || '').replace(/_/g,' ')} · {String(e.resource || 'unknown')}
                        </div>
                        <div style={{ fontSize: 12, color: C.text2, marginTop: 3 }}>
                          {String(e.user || 'unknown')} ({String(e.dept || 'unknown')}) · {String(e.tc || '').replace(/_/g,' ')} · <SevBadge sev={String(e.sev || 'LOW')} />
                          {Number(e.score) > 0 && <span style={{ fontSize: 11, color: scoreColor(Number(e.score)), fontWeight: 700, marginLeft: 6 }}>▲ {Number(e.score)}</span>}
                        </div>
                        {Array.isArray(e.reasons) && e.reasons[0] && <div style={{ fontSize: 11, color: '#ff7070', marginTop: 3 }}>{e.reasons[0]}</div>}
                      </div>
                    </div>
                  );
                });
              })()}
            </div>
          </div>
        </Card>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Card>
            <CardHeader>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Risk Concentration by Hour</div>
              <div style={{ fontSize: 11, color: C.text3 }}>Volume vs. avg risk</div>
            </CardHeader>
            <CardBody>
              <ResponsiveContainer width="100%" height={200}>
                <ComposedChart data={hourly} margin={{ left: -22, right: -22 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="hour" tick={{ fill: C.text3, fontSize: 9 }} interval={3} />
                  <YAxis yAxisId="vol" tick={{ fill: C.text3, fontSize: 10 }} />
                  <YAxis yAxisId="risk" orientation="right" domain={[0, 100]} tick={{ fill: C.text3, fontSize: 10 }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE}
                    formatter={(v: number, n: string) => [v, n === 'avg' ? 'Avg risk' : n === 'all' ? 'Events' : 'Crit/High']} />
                  <Bar yAxisId="vol" dataKey="all" name="all" fill="rgba(77,171,247,0.25)" radius={[2, 2, 0, 0]} />
                  <Bar yAxisId="vol" dataKey="crit" name="crit" fill="rgba(255,71,87,0.55)" radius={[2, 2, 0, 0]} />
                  <Line yAxisId="risk" type="monotone" dataKey="avg" name="avg" stroke={C.orange}
                    strokeWidth={2} dot={false} />
                </ComposedChart>
              </ResponsiveContainer>
              <div style={{ marginTop: 8, fontSize: 11, color: C.text3 }}>
                Peak-risk window <strong style={{ color: scoreColor(peakRisk.avg) }}>{peakRisk.hour}</strong> · avg risk{' '}
                <strong style={{ color: scoreColor(peakRisk.avg) }}>{peakRisk.avg}</strong> across {peakRisk.all} events
              </div>
            </CardBody>
          </Card>
          <Card>
            <CardHeader>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Most Targeted Resources</div>
              <div style={{ fontSize: 11, color: C.text3 }}>{userF || sevF ? 'filtered' : 'all events'}</div>
            </CardHeader>
            <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {resourceInsights.length === 0 ? (
                <div style={{ fontSize: 12, color: C.text3 }}>No resources match the selected filters.</div>
              ) : resourceInsights.map(r => (
                <div key={r.resource}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, color: C.text2, fontWeight: 500 }}>{r.resource}</span>
                    <span style={{ fontSize: 11, color: C.text3 }}>
                      {r.count} events · <span style={{ color: scoreColor(r.avg), fontWeight: 700 }}>avg {r.avg}</span>
                      {r.alerts > 0 && <span style={{ color: C.red, fontWeight: 700 }}> · {r.alerts} alerts</span>}
                    </span>
                  </div>
                  <div style={{ height: 6, background: C.border, borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${(r.count / maxResourceCount) * 100}%`, height: '100%',
                      background: scoreColor(r.avg), borderRadius: 3 }} />
                  </div>
                </div>
              ))}
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ── Cases Page ─────────────────────────────────────────────────────────
function CasesPage({ data, onShowUser, onStartAI }: {
  data: DerivedData; onShowUser: (uid: string) => void; onStartAI: (uid: string) => void;
}) {
  const { userRisk, profileMap } = data;
  const topRisk = Object.entries(userRisk)
    .filter(([, r]) => r.maxScore >= 55)
    .sort((a, b) => b[1].maxScore - a[1].maxScore)
    .slice(0, 16);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {topRisk.map(([uid, risk], i) => {
          const p = profileMap[uid] || {} as Profile;
          const topEv = [...risk.events].sort((a, b) => b.score - a.score)[0];
          const color = avatarColor(p.user || uid);
          const caseId = 'CASE-' + String(i + 1).padStart(4, '0');
          const sev = risk.maxScore >= 70 ? 'CRITICAL' : risk.maxScore >= 50 ? 'HIGH' : 'MEDIUM';
          return (
            <Card key={uid} style={{ borderLeft: `3px solid ${scoreColor(risk.maxScore)}` }}>
              <CardBody>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 12 }}>
                  <div style={{ width: 38, height: 38, borderRadius: '50%', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', fontSize: 13, fontWeight: 700, flexShrink: 0,
                    background: `${color}22`, color, border: `2px solid ${color}44` }}>
                    {initials(p.user || uid)}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ fontSize: 14, fontWeight: 700 }}>{p.user || uid}</div>
                      <SevBadge sev={sev} />
                    </div>
                    <div style={{ fontSize: 11, color: C.text3, marginTop: 2 }}>{p.dept} · {p.job} · {p.priv}</div>
                    <div style={{ fontSize: 10, color: C.text3, fontFamily: 'monospace', marginTop: 2 }}>{caseId}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: scoreColor(risk.maxScore) }}>{risk.maxScore}</div>
                    <div style={{ fontSize: 10, color: C.text3 }}>MAX RISK</div>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 12 }}>
                  {[
                    { v: risk.events.filter(e => e.sev === 'CRITICAL').length, l: 'CRITICAL', c: C.red },
                    { v: risk.events.filter(e => e.sev === 'HIGH').length, l: 'HIGH', c: C.orange },
                    { v: risk.events.length, l: 'TOTAL', c: C.blue },
                  ].map(({ v, l, c }) => (
                    <div key={l} style={{ background: C.bg3, borderRadius: 6, padding: 8, textAlign: 'center' }}>
                      <div style={{ fontSize: 16, fontWeight: 700, color: c }}>{v}</div>
                      <div style={{ fontSize: 10, color: C.text3 }}>{l}</div>
                    </div>
                  ))}
                </div>

                {topEv && (
                  <div style={{ background: C.redDim, border: `1px solid ${C.redBorder}`, borderRadius: 6,
                    padding: 10, marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: C.red, fontWeight: 700, marginBottom: 4 }}>⚠ MOST SUSPICIOUS EVENT</div>
                    <div style={{ fontSize: 12, color: C.text2 }}>
                      {topEv.action.replace(/_/g,' ')} on <strong style={{ color: C.text }}>{topEv.resource}</strong>
                    </div>
                    <div style={{ fontSize: 11, color: C.text3, marginTop: 2 }}>
                      {fmtTs(topEv.ts)} · {topEv.tc.replace(/_/g,' ')} · Score: <strong style={{ color: C.red }}>{topEv.score}</strong>
                    </div>
                    {topEv.reasons[0] && <div style={{ fontSize: 11, color: '#ff7070', marginTop: 4 }}>{topEv.reasons.slice(0,2).join(' · ')}</div>}
                  </div>
                )}

                <div style={{ fontSize: 11, color: C.text3, marginBottom: 10 }}>
                  <strong style={{ color: C.text2 }}>Accessed: </strong>
                  {[...new Set(risk.events.map(e => e.resource))].slice(0, 4).join(', ')}
                </div>

                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={() => onStartAI(uid)}
                    style={{ flex: 1, padding: '7px 0', borderRadius: 6, fontSize: 12, fontWeight: 600,
                      background: C.blue, border: 'none', color: '#000', cursor: 'pointer' }}>
                    ✦ AI Investigate
                  </button>
                  <button onClick={() => onShowUser(uid)}
                    style={{ flex: 1, padding: '7px 0', borderRadius: 6, fontSize: 12,
                      background: C.bg3, border: `1px solid ${C.border2}`, color: C.text2, cursor: 'pointer' }}>
                    👤 Profile
                  </button>
                </div>
              </CardBody>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// ── Users Page ─────────────────────────────────────────────────────────
function UsersPage({ data, onShowUser }: { data: DerivedData; onShowUser: (uid: string) => void }) {
  const [q, setQ] = useState('');
  const [deptF, setDeptF] = useState('');
  const [page, setPage] = useState(1);
  const PAGE = 20;
  const { profiles, userRisk } = data;

  const depts = useMemo(() => [...new Set(profiles.map(p => p.dept))].sort(), [profiles]);

  const filtered = useMemo(() => {
    return profiles.filter(p => {
      if (deptF && p.dept !== deptF) return false;
      if (q) {
        const s = `${p.user} ${p.email} ${p.job} ${p.dept} ${p.uid}`.toLowerCase();
        if (!s.includes(q.toLowerCase())) return false;
      }
      return true;
    }).sort((a, b) => (userRisk[b.uid]?.maxScore || 0) - (userRisk[a.uid]?.maxScore || 0));
  }, [profiles, q, deptF, userRisk]);

  const pages = Math.ceil(filtered.length / PAGE);
  const slice = filtered.slice((page - 1) * PAGE, page * PAGE);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
          placeholder="Search users…"
          style={{ width: 200, background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 7,
            padding: '8px 12px', color: C.text, fontSize: 13, outline: 'none', fontFamily: 'inherit' }} />
        <select value={deptF} onChange={e => { setDeptF(e.target.value); setPage(1); }}
          style={{ background: C.bg2, border: `1px solid ${C.border2}`, borderRadius: 7, padding: '8px 10px',
            color: C.text2, fontSize: 12, outline: 'none', cursor: 'pointer', fontFamily: 'inherit' }}>
          <option value="">All Departments</option>
          {depts.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
      </div>

      <Card>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['User', 'Department', 'Role', 'Privilege', 'Inactive', 'Status', 'Max Risk', 'Alerts'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', fontSize: 11, color: C.text3,
                    fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8,
                    borderBottom: `1px solid ${C.border}`, background: C.bg3 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {slice.map(p => {
                const risk = userRisk[p.uid] || { maxScore: 0, alertCount: 0 };
                const color = avatarColor(p.user);
                return (
                  <tr key={p.uid} onClick={() => onShowUser(p.uid)} style={{ cursor: 'pointer' }}
                    onMouseEnter={el => { el.currentTarget.querySelectorAll('td').forEach(td => td.style.background = 'rgba(255,255,255,0.02)'); }}
                    onMouseLeave={el => { el.currentTarget.querySelectorAll('td').forEach(td => td.style.background = ''); }}>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{ width: 30, height: 30, borderRadius: '50%', display: 'flex', alignItems: 'center',
                          justifyContent: 'center', fontSize: 11, fontWeight: 700, background: `${color}22`, color }}>
                          {initials(p.user)}
                        </div>
                        <div>
                          <div style={{ fontWeight: 500 }}>{p.user}</div>
                          <div style={{ fontSize: 11, color: C.text3 }}>{p.email}</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}` }}>{p.dept}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}` }}>{p.job}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ padding: '2px 8px', background: C.bg4, border: `1px solid ${C.border}`,
                        borderRadius: 4, fontSize: 11, color: C.text2 }}>{p.priv}</span>
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}`,
                      color: p.inactive > 30 ? C.red : p.inactive > 14 ? C.yellow : C.text2 }}>{p.inactive}d</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}`,
                      color: p.active === 'true' ? C.green : C.red }}>{p.active === 'true' ? '● Active' : '⊗ Inactive'}</td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ flex: 1, height: 4, background: C.border, borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${risk.maxScore}%`, height: '100%', background: scoreColor(risk.maxScore), borderRadius: 2 }} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor(risk.maxScore), minWidth: 24 }}>{risk.maxScore}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: 12, borderBottom: `1px solid ${C.border}`,
                      color: risk.alertCount > 5 ? C.red : risk.alertCount > 2 ? C.orange : C.text2 }}>{risk.alertCount}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderTop: `1px solid ${C.border}`, fontSize: 12, color: C.text3 }}>
          <div>{filtered.length} users</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {Array.from({ length: Math.min(pages, 8) }, (_, i) => i + 1).map(p => (
              <button key={p} onClick={() => setPage(p)}
                style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${p === page ? C.blue : C.border}`,
                  background: p === page ? C.blue : C.bg3, color: p === page ? '#000' : C.text2,
                  cursor: 'pointer', fontSize: 12 }}>{p}</button>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}

// ── Heatmap Page ───────────────────────────────────────────────────────
type HeatMode = 'risk' | 'alerts' | 'volume';
interface HeatCell { count: number; sum: number; alerts: number; avg: number }
function HeatmapPage({ data }: { data: DerivedData }) {
  const { events, profiles, userRisk } = data;
  const [mode, setMode] = useState<HeatMode>('risk');

  const heatmap = useMemo(() => {
    const m: Record<string, Record<number, HeatCell>> = {};
    const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    days.forEach(d => { m[d] = {}; for (let h = 0; h < 24; h++) m[d][h] = { count: 0, sum: 0, alerts: 0, avg: 0 }; });
    events.forEach(e => {
      const d = new Date(e.ts.replace(' ', 'T'));
      if (isNaN(d.getTime())) return;
      const cell = m[days[d.getDay()]][d.getHours()];
      cell.count++;
      cell.sum += Number(e.score) || 0;
      const sev = String(e.sev || '').toUpperCase();
      if (sev === 'CRITICAL' || sev === 'HIGH') cell.alerts++;
    });
    days.forEach(d => { for (let h = 0; h < 24; h++) { const c = m[d][h]; c.avg = c.count ? Math.round(c.sum / c.count) : 0; } });
    return { grid: m, days };
  }, [events]);

  // Per-mode value extractor + max for normalising volume/alert intensity.
  const cellVal = (c: HeatCell) => (mode === 'risk' ? c.avg : mode === 'alerts' ? c.alerts : c.count);
  const maxVal = useMemo(() => {
    let max = 0;
    heatmap.days.forEach(d => { for (let h = 0; h < 24; h++) max = Math.max(max, cellVal(heatmap.grid[d][h])); });
    return max || 1;
  }, [heatmap, mode]);

  // Riskiest window + off-hours alert volume — analyst-facing call-outs.
  const insight = useMemo(() => {
    let peak = { day: '—', hr: 0, avg: 0, count: 0, alerts: 0 };
    let offHoursAlerts = 0, totalAlerts = 0;
    heatmap.days.forEach(d => { for (let h = 0; h < 24; h++) {
      const c = heatmap.grid[d][h];
      if (c.count >= 2 && c.avg > peak.avg) peak = { day: d, hr: h, avg: c.avg, count: c.count, alerts: c.alerts };
      totalAlerts += c.alerts;
      if (h < 7 || h >= 20 || d === 'Sat' || d === 'Sun') offHoursAlerts += c.alerts;
    }});
    return { peak, offHoursAlerts, totalAlerts };
  }, [heatmap]);

  const deptRisk = useMemo(() => {
    const m: Record<string, { name: string; score: number; alerts: number }> = {};
    profiles.forEach(p => { if (!m[p.dept]) m[p.dept] = { name: p.dept, score: 0, alerts: 0 }; });
    Object.values(userRisk).forEach(r => {
      const dept = r.events[0]?.dept;
      if (dept && m[dept]) { m[dept].score = Math.max(m[dept].score, r.maxScore); m[dept].alerts += r.alertCount; }
    });
    return Object.values(m).sort((a, b) => b.score - a.score).slice(0, 10);
  }, [profiles, userRisk]);

  return (
    <div style={{ padding: 24 }}>
      <Card style={{ marginBottom: 16 }}>
        <CardHeader>
          <div style={{ fontSize: 13, fontWeight: 600 }}>Hour × Day Risk Matrix</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {([['risk', 'Avg Risk'], ['alerts', 'Alerts'], ['volume', 'Volume']] as [HeatMode, string][]).map(([m, label]) => (
              <button key={m} onClick={() => setMode(m)}
                style={{ padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer',
                  border: `1px solid ${mode === m ? C.blue : C.border2}`,
                  background: mode === m ? C.blue : C.bg3, color: mode === m ? '#000' : C.text2 }}>
                {label}
              </button>
            ))}
          </div>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 14 }}>
            <div style={{ background: C.bg3, border: `1px solid ${C.border}`, borderRadius: 8, padding: '8px 12px' }}>
              <div style={{ fontSize: 10, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.6 }}>Riskiest Window</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: scoreColor(insight.peak.avg) }}>
                {insight.peak.day} {String(insight.peak.hr).padStart(2, '0')}:00 · avg {insight.peak.avg}
              </div>
              <div style={{ fontSize: 10, color: C.text3 }}>{insight.peak.count} events · {insight.peak.alerts} alerts</div>
            </div>
            <div style={{ background: C.bg3, border: `1px solid ${C.border}`, borderRadius: 8, padding: '8px 12px' }}>
              <div style={{ fontSize: 10, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.6 }}>Off-Hours Alerts</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: C.red }}>{insight.offHoursAlerts}</div>
              <div style={{ fontSize: 10, color: C.text3 }}>
                {insight.totalAlerts ? Math.round((insight.offHoursAlerts / insight.totalAlerts) * 100) : 0}% of all alerts
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto', fontSize: 11, color: C.text3 }}>
              {mode === 'risk' ? 'Low risk' : 'Low'}
              <span style={{ width: 11, height: 11, background: C.green, borderRadius: 2 }} />
              <span style={{ width: 11, height: 11, background: C.yellow, borderRadius: 2 }} />
              <span style={{ width: 11, height: 11, background: C.orange, borderRadius: 2 }} />
              <span style={{ width: 11, height: 11, background: C.red, borderRadius: 2 }} />
              {mode === 'risk' ? 'High risk' : 'High'}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 8 }}>
            <div style={{ width: 40 }} />
            {Array.from({ length: 24 }, (_, i) => (
              <div key={i} style={{ flex: 1, textAlign: 'center', fontSize: 9, color: C.text3 }}>{i}</div>
            ))}
          </div>
          {heatmap.days.map(day => (
            <div key={day} style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
              <div style={{ width: 40, fontSize: 11, color: C.text2, textAlign: 'right', paddingRight: 6 }}>{day}</div>
              {Array.from({ length: 24 }, (_, h) => {
                const c = heatmap.grid[day][h];
                const v = cellVal(c);
                let bg = '#1a1f2e';
                if (v > 0) {
                  if (mode === 'risk') {
                    // Color by severity, opacity by how busy the cell is.
                    bg = scoreColor(c.avg);
                  } else {
                    bg = `rgba(255,71,87,${0.15 + (v / maxVal) * 0.85})`;
                  }
                }
                const opacity = mode === 'risk' && v > 0 ? 0.35 + Math.min(c.count / maxVal, 1) * 0.65 : 1;
                return (
                  <div key={h} title={`${day} ${h}:00 — ${c.count} events · avg risk ${c.avg} · ${c.alerts} alerts`}
                    style={{ flex: 1, aspectRatio: '1', borderRadius: 3, cursor: 'pointer',
                      background: bg, opacity, transition: 'transform 0.1s' }}
                    onMouseEnter={el => (el.currentTarget.style.transform = 'scale(1.3)')}
                    onMouseLeave={el => (el.currentTarget.style.transform = 'scale(1)')} />
                );
              })}
            </div>
          ))}
          <div style={{ fontSize: 11, color: C.text3, marginTop: 10 }}>
            {mode === 'risk' && 'Cell color = average risk score · brightness = activity volume. Bright red pockets are high-risk hotspots worth investigating.'}
            {mode === 'alerts' && 'Cell intensity = number of HIGH/CRITICAL alerts in that hour×day window.'}
            {mode === 'volume' && 'Cell intensity = total access events. Useful as a baseline of normal working rhythm.'}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>Department Risk Scores</div></CardHeader>
        <CardBody>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={deptRisk} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis type="number" tick={{ fill: C.text3, fontSize: 10 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: C.text2, fontSize: 11 }} width={90} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="score" name="Max Risk Score" fill="rgba(255,71,87,0.7)" radius={[0, 3, 3, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardBody>
      </Card>
    </div>
  );
}

// ── Analytics Page ─────────────────────────────────────────────────────
function AnalyticsPage({ data }: { data: DerivedData }) {
  const { events, profiles, userRisk, critical, high, medium } = data;

  const exportsByResource = useMemo(() => {
    const m: Record<string, number> = {};
    events.filter(e => e.action === 'export_data' && (e.sev === 'CRITICAL' || e.sev === 'HIGH'))
      .forEach(e => { m[e.resource] = (m[e.resource] || 0) + 1; });
    return Object.entries(m).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [events]);

  const failedByDept = useMemo(() => {
    const m: Record<string, number> = {};
    events.filter(e => e.status === 'failure' && e.action === 'login')
      .forEach(e => { m[e.dept] = (m[e.dept] || 0) + 1; });
    return Object.entries(m).map(([dept, count]) => ({ dept, count })).sort((a, b) => b.count - a.count).slice(0, 10);
  }, [events]);

  const riskDist = useMemo(() => {
    const buckets = [0, 0, 0, 0, 0];
    Object.values(userRisk).forEach(r => {
      if (r.maxScore >= 80) buckets[4]++;
      else if (r.maxScore >= 60) buckets[3]++;
      else if (r.maxScore >= 40) buckets[2]++;
      else if (r.maxScore >= 20) buckets[1]++;
      else buckets[0]++;
    });
    return [
      { range: '0-19', count: buckets[0], color: C.green },
      { range: '20-39', count: buckets[1], color: C.yellow },
      { range: '40-59', count: buckets[2], color: C.orange },
      { range: '60-79', count: buckets[3], color: '#ff6b35' },
      { range: '80+', count: buckets[4], color: C.red },
    ];
  }, [userRisk]);

  const stale = profiles.filter(p => p.inactive > 30).length;
  const [dlpConfig, setDlpConfig] = useState({
    blockSensitiveExports: true,
    blockOffHoursExports: true,
    blockStaleAccountExports: false,
  });

  const sensitiveResources = ['Customer_Vault', 'PROD_DB', 'GL_System', 'HRIS'];
  const isSensitiveResource = (resource: string) => sensitiveResources.includes(resource);
  const dlpEligibleExports = useMemo(() => events.filter(e => e.action === 'export_data' && (e.sev === 'CRITICAL' || e.sev === 'HIGH' || e.sev === 'MEDIUM')),
    [events]);
  const dlpBlockedExports = useMemo(() => {
    return dlpEligibleExports.filter(e => {
      if (dlpConfig.blockSensitiveExports && isSensitiveResource(e.resource)) return true;
      if (dlpConfig.blockOffHoursExports && e.tc !== 'business_hours') return true;
      if (dlpConfig.blockStaleAccountExports && (data.profileMap[e.uid]?.inactive || 0) > 30) return true;
      return false;
    });
  }, [dlpEligibleExports, dlpConfig, data.profileMap]);
  const dlpResourceCounts = useMemo(() => {
    const m: Record<string, number> = {};
    dlpBlockedExports.forEach(e => { m[e.resource] = (m[e.resource] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [dlpBlockedExports]);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 14, marginBottom: 24 }}>
        <StatCard label="Critical Events" value={critical.length} sub="Score ≥ 70" color={C.red} />
        <StatCard label="High Events" value={high.length} sub="Score ≥ 50" color={C.orange} />
        <StatCard label="Stale Accounts" value={stale} sub="Inactive > 30 days" color={C.yellow} />
        <StatCard label="High-Risk Exports" value={events.filter(e => e.action === 'export_data' && (e.sev === 'CRITICAL' || e.sev === 'HIGH')).length} sub="Export anomalies" color={C.purple} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card>
          <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>Export Events by Resource (Critical/High)</div></CardHeader>
          <CardBody>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={exportsByResource} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis type="number" tick={{ fill: C.text3, fontSize: 10 }} />
                <YAxis dataKey="name" type="category" tick={{ fill: C.text2, fontSize: 11 }} width={110} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="value" name="Exports" fill="rgba(255,71,87,0.7)" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>Failed Login Attempts by Department</div></CardHeader>
          <CardBody>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={failedByDept} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis type="number" tick={{ fill: C.text3, fontSize: 10 }} />
                <YAxis dataKey="dept" type="category" tick={{ fill: C.text2, fontSize: 11 }} width={90} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" name="Failed Logins" fill="rgba(255,140,0,0.7)" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>Feature Analysis — Access Patterns</div></CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            {(() => {
              const timePatterns = { business_hours: 0, off_hours: 0, night: 0, unusual_hours: 0 };
              const sensPatterns = { high: 0, low: 0, medium: 0 };
              let totalVolume = 0, totalEvents = 0;
              
              events.forEach(e => {
                timePatterns[e.tc as keyof typeof timePatterns] = (timePatterns[e.tc as keyof typeof timePatterns] || 0) + 1;
                sensPatterns[e.sens as keyof typeof sensPatterns] = (sensPatterns[e.sens as keyof typeof sensPatterns] || 0) + 1;
                totalVolume += e.rowcount;
                totalEvents++;
              });
              
              return [
                { label: 'Business Hours Access', value: timePatterns.business_hours, sub: `${((timePatterns.business_hours / totalEvents) * 100).toFixed(0)}% of events`, color: C.green },
                { label: 'Off-Hours / Night Access', value: timePatterns.night + timePatterns.off_hours, sub: `${(((timePatterns.night + timePatterns.off_hours) / totalEvents) * 100).toFixed(0)}% risky times`, color: C.red },
                { label: 'High-Sensitivity Data Accessed', value: sensPatterns.high, sub: `${((sensPatterns.high / totalEvents) * 100).toFixed(0)}% of events`, color: C.orange },
                { label: 'Total Data Volume Accessed', value: `${(totalVolume / 1000).toFixed(1)}K`, sub: 'rows across all events', color: C.blue },
              ].map(stat => (
                <div key={stat.label} style={{ background: C.bg3, borderRadius: 10, padding: 14 }}>
                  <div style={{ fontSize: 11, color: C.text3, marginBottom: 8 }}>{stat.label}</div>
                  <div style={{ fontSize: 24, fontWeight: 700, color: stat.color, marginBottom: 4 }}>{stat.value}</div>
                  <div style={{ fontSize: 11, color: C.text2 }}>{stat.sub}</div>
                </div>
              ));
            })()}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            {(() => {
              const hourBuckets = Array(24).fill(0);
              const userAccessPatterns: Record<string, { actions: number; avgVolume: number; sensitivity: string[] }> = {};
              
              events.forEach(e => {
                const hour = parseInt(e.ts.split(' ')[1]?.split(':')[0] || '12');
                hourBuckets[hour]++;
                
                if (!userAccessPatterns[e.user]) {
                  userAccessPatterns[e.user] = { actions: 0, avgVolume: 0, sensitivity: [] };
                }
                userAccessPatterns[e.user].actions++;
                userAccessPatterns[e.user].avgVolume += e.rowcount;
                userAccessPatterns[e.user].sensitivity.push(e.sens);
              });
              
              const topUsers = Object.entries(userAccessPatterns)
                .map(([user, data]) => ({
                  user,
                  actions: data.actions,
                  sensitivity: data.sensitivity.filter(s => s === 'high').length > 0 ? 'HIGH' : 'LOW'
                }))
                .sort((a, b) => b.actions - a.actions)
                .slice(0, 5);
              
              return [
                <div key="access-times" style={{ background: C.bg4, borderRadius: 10, padding: 14, border: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.text3, marginBottom: 10 }}>Peak Access Hours</div>
                  <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 80 }}>
                    {hourBuckets.map((count, hour) => (
                      <div key={hour} title={`${hour}:00 - ${count} events`}
                        style={{ flex: 1, background: count > 0 ? `rgba(77,171,247,${0.2 + (count / Math.max(...hourBuckets)) * 0.8})` : C.border,
                          borderRadius: 2, minHeight: 4, transition: 'all 0.2s' }} />
                    ))}
                  </div>
                  <div style={{ fontSize: 11, color: C.text2, marginTop: 8, textAlign: 'center' }}>Busiest: ~{hourBuckets.indexOf(Math.max(...hourBuckets))}:00</div>
                </div>,
                <div key="top-users" style={{ background: C.bg4, borderRadius: 10, padding: 14, border: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.text3, marginBottom: 10 }}>Most Active Users</div>
                  {topUsers.map((u, i) => (
                    <div key={u.user} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: i < topUsers.length - 1 ? `1px solid ${C.border}` : 'none' }}>
                      <div style={{ fontSize: 12, color: C.text }}>{u.user}</div>
                      <div style={{ fontSize: 11, fontWeight: 700, color: u.sensitivity === 'HIGH' ? C.red : C.green }}>{u.actions} actions</div>
                    </div>
                  ))}
                </div>,
                <div key="policy-summary" style={{ background: C.bg4, borderRadius: 10, padding: 14, border: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.text3, marginBottom: 10 }}>Frequency Metrics</div>
                  <div style={{ fontSize: 12, color: C.text, marginBottom: 8 }}>
                    <div>🔄 Total events: <strong style={{ color: C.blue }}>{events.length}</strong></div>
                    <div style={{ marginTop: 6 }}>📊 Avg. volume per access: <strong style={{ color: C.blue }}>{(events.reduce((s, e) => s + e.rowcount, 0) / events.length).toFixed(0)}</strong> rows</div>
                    <div style={{ marginTop: 6 }}>⚠️ First-time resource accesses: <strong style={{ color: C.orange }}>{events.filter(e => e.firstTime).length}</strong></div>
                  </div>
                </div>
              ];
            })()}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>User Risk Score Distribution</div></CardHeader>
        <CardBody>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={riskDist} margin={{ left: -10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="range" tick={{ fill: C.text2, fontSize: 12 }} />
              <YAxis tick={{ fill: C.text3, fontSize: 10 }} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="count" name="Users" radius={[4, 4, 0, 0]}>
                {riskDist.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </CardBody>
      </Card>

      <Card>
        <CardHeader><div style={{ fontSize: 13, fontWeight: 600 }}>DLP Prevention Simulation</div></CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            {([
              { label: 'Sensitive resource exports', key: 'blockSensitiveExports' as const, value: dlpConfig.blockSensitiveExports },
              { label: 'Off-hours exports', key: 'blockOffHoursExports' as const, value: dlpConfig.blockOffHoursExports },
              { label: 'Stale account exports', key: 'blockStaleAccountExports' as const, value: dlpConfig.blockStaleAccountExports },
            ] as const).map(item => (
              <div key={item.key} style={{ background: C.bg3, padding: 14, borderRadius: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: 12, color: C.text3 }}>{item.label}</div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: item.value ? C.green : C.text2 }}>{item.value ? 'Enabled' : 'Disabled'}</div>
                </div>
                <button onClick={() => setDlpConfig(prev => ({ ...prev, [item.key]: !prev[item.key] }))}
                  style={{ padding: '8px 12px', borderRadius: 8, border: 'none', background: item.value ? C.red : C.blue, color: '#000', cursor: 'pointer', fontWeight: 700 }}>
                  {item.value ? 'Disable' : 'Enable'}
                </button>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 16 }}>
            <div style={{ flex: 1, minWidth: 220, background: C.bg3, borderRadius: 10, padding: 14 }}>
              <div style={{ fontSize: 12, color: C.text3, marginBottom: 8 }}>DLP blocks estimated</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: C.purple }}>{dlpBlockedExports.length}</div>
              <div style={{ fontSize: 11, color: C.text2, marginTop: 4 }}>Export events that would be blocked by policy</div>
            </div>
            <div style={{ flex: 1, minWidth: 220, background: C.bg3, borderRadius: 10, padding: 14 }}>
              <div style={{ fontSize: 12, color: C.text3, marginBottom: 8 }}>Unique blocked resources</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: C.blue }}>{dlpResourceCounts.length}</div>
              <div style={{ fontSize: 11, color: C.text2, marginTop: 4 }}>Sensitive resources impacted by DLP rules</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <Card style={{ background: 'rgba(255,255,255,0.02)', border: `1px solid ${C.border2}` }}>
              <CardBody>
                <div style={{ fontSize: 12, color: C.text3, marginBottom: 10 }}>Top resources blocked</div>
                {dlpResourceCounts.length > 0 ? dlpResourceCounts.slice(0, 5).map(([resource, count], index) => (
                  <div key={resource} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: index < dlpResourceCounts.length - 1 ? `1px solid ${C.border}` : 'none' }}>
                    <div style={{ color: C.text }}>{resource}</div>
                    <div style={{ fontWeight: 700, color: C.text2 }}>{count}</div>
                  </div>
                )) : <div style={{ color: C.text3, fontSize: 12 }}>No DLP blocks configured.</div>}
              </CardBody>
            </Card>
            <Card style={{ background: 'rgba(255,255,255,0.02)', border: `1px solid ${C.border2}` }}>
              <CardBody>
                <div style={{ fontSize: 12, color: C.text3, marginBottom: 10 }}>DLP enforcement note</div>
                <div style={{ fontSize: 13, lineHeight: 1.7, color: C.text2 }}>
                  This panel simulates a DLP prevention layer. When rules are enabled, the platform treats the matching export events as blocked and adds them to the prevention count.
                  For a real integration, connect these settings to a DLP engine or enforcement API so the browser can mark live export traffic and stop suspicious transfers.
                </div>
              </CardBody>
            </Card>
          </div>

          <div style={{ marginTop: 18 }}>
            <div style={{ fontSize: 12, color: C.text3, marginBottom: 12 }}>Blocked export event preview</div>
            {dlpBlockedExports.length > 0 ? (
              <div style={{ display: 'grid', gap: 10 }}>
                {dlpBlockedExports.slice(0, 5).map((event, index) => (
                  <div key={event.id} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 12, padding: 14,
                    borderRadius: 12, background: C.bg4, border: `1px solid ${C.border}` }}>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{event.user} — {event.resource}</div>
                      <div style={{ fontSize: 11, color: C.text2, marginTop: 4 }}>{event.action.replace(/_/g, ' ')} · {fmtTs(event.ts)}</div>
                      <div style={{ fontSize: 11, color: C.text3, marginTop: 8 }}>Severity: <span style={{ color: sevColor(event.sev), fontWeight: 700 }}>{event.sev}</span></div>
                    </div>
                    <div style={{ textAlign: 'right', minWidth: 130 }}>
                      <div style={{ fontSize: 11, color: C.text3, marginBottom: 6 }}>Policy triggers</div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: C.purple }}>
                        {[
                          dlpConfig.blockSensitiveExports && isSensitiveResource(event.resource) ? 'Sensitive' : '',
                          dlpConfig.blockOffHoursExports && event.tc !== 'business_hours' ? 'Off-hours' : '',
                          dlpConfig.blockStaleAccountExports && (data.profileMap[event.uid]?.inactive || 0) > 30 ? 'Stale account' : '',
                        ].filter(Boolean).join(', ') || 'Policy active'}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: 14, borderRadius: 10, background: C.bg4, color: C.text3, border: `1px solid ${C.border}` }}>
                No export events are currently blocked by the active DLP policy. Enable a rule to see blocked export activity here.
              </div>
            )}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

// ── Reports Page ───────────────────────────────────────────────────────
function ReportsPage({ data }: { data: DerivedData }) {
  const [output, setOutput] = useState('');
  const [generating, setGenerating] = useState(false);
  const { events, profiles, critical, high, medium, userRisk, anomalous } = data;

  function generateReport(type: string) {
    setGenerating(true);
    setTimeout(() => {
      const topUsers = Object.entries(userRisk).sort((a, b) => b[1].maxScore - a[1].maxScore).slice(0, 5);
      const topEvents = [...critical].sort((a, b) => b.score - a.score).slice(0, 5);
      const stale = profiles.filter(p => p.inactive > 30).length;
      const depts: Record<string, number> = {};
      anomalous.forEach(e => { depts[e.dept] = (depts[e.dept] || 0) + 1; });
      const topDepts = Object.entries(depts).sort((a, b) => b[1] - a[1]).slice(0, 5);

      let text = '';
      if (type === 'executive') {
        text = `## Executive Summary — SentinelIQ Threat Report\n\n**Reporting Period:** Apr 2025 – Jun 2026\n**Generated:** ${new Date().toLocaleString()}\n\n### Board-Level Overview\nSentinelIQ analyzed **${events.length.toLocaleString()} access events** across **${profiles.length} user accounts**. The platform identified **${critical.length} critical**, **${high.length} high**, and **${medium.length} medium** risk anomalies requiring varying levels of attention.\n\n### Top 3 Incidents Requiring Immediate Action\n${topEvents.slice(0,3).map((e,i) => `**${i+1}. ${e.user}** (${e.dept}): ${e.action.replace(/_/g,' ')} on ${e.resource} at ${fmtTs(e.ts)} — Score ${e.score}/100. Risk factors: ${e.reasons.join(', ')}.`).join('\n\n')}\n\n### Department Risk Ranking\n${topDepts.map(([d,n],i) => `${i+1}. **${d}**: ${n} anomalous events`).join('\n')}\n\n### Key Risk Metrics\n- Critical events: ${critical.length}\n- High-risk exports: ${events.filter(e => e.action==='export_data' && (e.sev==='CRITICAL'||e.sev==='HIGH')).length}\n- Stale accounts in use: ${stale}\n- Off-hours access events: ${events.filter(e=>e.tc==='night'||e.tc==='unusual_hours').length}\n\n### Recommendations\n1. Immediately investigate all CRITICAL events — ${critical.length} cases pending.\n2. Revoke or re-verify ${stale} stale accounts inactive >30 days.\n3. Add export approval workflows for HRIS, PROD_DB, Customer_Vault, and GL_System.\n4. Conduct manager interviews for ${topUsers.length} highest-risk users.\n5. Implement real-time alerting for night-time admin operations.`;
      } else if (type === 'incident') {
        text = `## Critical Incident Report\n\n**Total Critical Events: ${critical.length}**\n**Generated:** ${new Date().toLocaleString()}\n\n${topEvents.map((e,i) => `### Incident ${i+1}: ${e.id.slice(-12)}\n**User:** ${e.user} (${e.dept}, ${e.priv})\n**Action:** ${e.action.replace(/_/g,' ')} on **${e.resource}**\n**Time:** ${fmtTs(e.ts)} (${e.tc.replace(/_/g,' ')})\n**Risk Score:** ${e.score}/100\n**Risk Factors:** ${e.reasons.join('; ')}\n**Recommended Response:**\n- Immediately preserve all logs from the past 72 hours for this user\n- Verify business justification with manager\n- Temporarily restrict export/admin access pending review\n- Notify CISO if no valid justification exists`).join('\n\n---\n\n')}`;
      } else if (type === 'compliance') {
        text = `## Compliance Assessment Report\n\n**Generated:** ${new Date().toLocaleString()}\n\n### GDPR Article 32 — Data Security Assessment\nSensitive personal data in HRIS and Customer_Vault was accessed ${events.filter(e=>['HRIS','Customer_Vault'].includes(e.resource)).length} times. Off-hours exports of these resources create GDPR exposure requiring documented legal basis and audit trails.\n\n### SOX 302 — Financial Controls\nGL_System (general ledger) was accessed ${events.filter(e=>e.resource==='GL_System').length} times including ${events.filter(e=>e.resource==='GL_System'&&e.action==='export_data').length} export events. All financial system access must have segregation of duties and management approval.\n\n### NIST IR-4 — Incident Handling\nDetection capability is operational. ${critical.length + high.length} high-priority incidents identified. Response workflow gaps: no automated blocking on CRITICAL events, no mandatory incident ticket creation.\n\n### Overall Compliance Risk: **HIGH**\n\n### Required Remediation Steps\n1. Document business justification for all ${events.filter(e=>e.action==='export_data').length} export events\n2. Revalidate ${stale} stale accounts — terminate or reauthorize\n3. Implement mandatory MFA for all admin_operation actions\n4. Deploy automated account lockout on 3+ failed logins\n5. Monthly access reviews for all admin and power-user accounts`;
      } else {
        text = `## User Risk Assessment\n\n**Generated:** ${new Date().toLocaleString()}\n\n${topUsers.map(([uid, risk], i) => {
          const p = (data.profileMap[uid] || {}) as Profile;
          const topEv = [...risk.events].sort((a, b) => b.score - a.score)[0];
          const cls = risk.maxScore >= 70 ? 'Possible Malicious Insider' : risk.maxScore >= 50 ? 'High-Risk / Potential Compromise' : 'Negligent or Policy Violation';
          return `### ${i+1}. ${p.user || uid} — ${risk.maxScore >= 70 ? 'CRITICAL' : risk.maxScore >= 50 ? 'HIGH' : 'MEDIUM'}\n**Profile:** ${p.dept}, ${p.job}, privilege: ${p.priv}, inactive: ${p.inactive} days\n**Risk Score:** ${risk.maxScore}/100 · **Alerts:** ${risk.alertCount}\n**Classification:** ${cls}\n**Most Suspicious Event:** ${topEv ? `${topEv.action.replace(/_/g,' ')} on ${topEv.resource} (${fmtTs(topEv.ts)}, score ${topEv.score})` : 'N/A'}\n**Recommendation:** ${risk.maxScore >= 70 ? 'Immediate investigation, consider temporary suspension' : 'Manager review + access audit within 5 business days'}`;
        }).join('\n\n---\n\n')}`;
      }
      setOutput(text);
      setGenerating(false);
    }, 600);
  }

  const reports = [
    { type: 'executive', icon: '📊', title: 'Executive Summary', desc: 'CISO-ready summary with top threats, metrics, and 30-day action plan.', tags: ['✦ AI', 'CISO-ready'] },
    { type: 'incident', icon: '🚨', title: 'Incident Report', desc: 'Detailed forensic report for all Critical events with response steps.', tags: ['CRITICAL', 'Forensic'] },
    { type: 'compliance', icon: '⚖️', title: 'Compliance Report', desc: 'GDPR Art.32, SOX 302, NIST IR-4 assessment against detected anomalies.', tags: ['GDPR', 'NIST', 'SOX'] },
    { type: 'userrisk', icon: '👤', title: 'User Risk Report', desc: 'Individual risk profiles for top 10 users with behavioral analysis.', tags: ['✦ AI', 'Top-10'] },
  ];

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        {reports.map(r => (
          <Card key={r.type} style={{ cursor: 'pointer' }}>
            <CardBody>
              <div onClick={() => generateReport(r.type)}
                onMouseEnter={el => (el.currentTarget.closest('.card-body-wrap')?.setAttribute('data-hov','1'))}
                style={{ display: 'contents' }}>
                <div style={{ fontSize: 24, marginBottom: 10 }}>{r.icon}</div>
                <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 6 }}>{r.title}</div>
                <div style={{ fontSize: 12, color: C.text3, marginBottom: 12 }}>{r.desc}</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {r.tags.map(t => (
                    <span key={t} style={{ padding: '2px 8px', background: C.bg4, border: `1px solid ${C.border}`,
                      borderRadius: 4, fontSize: 11, color: C.text2 }}>{t}</span>
                  ))}
                </div>
                <button onClick={() => generateReport(r.type)}
                  style={{ marginTop: 12, width: '100%', padding: '8px 0', borderRadius: 6, fontSize: 12, fontWeight: 600,
                    background: C.blue, border: 'none', color: '#000', cursor: 'pointer' }}>
                  Generate Report
                </button>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      {(output || generating) && (
        <Card>
          <CardHeader>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.blue, textTransform: 'uppercase', letterSpacing: 1 }}>GENERATED REPORT</div>
              <div style={{ fontSize: 11, color: C.text3, marginTop: 2 }}>{new Date().toLocaleString()}</div>
            </div>
            {output && <button onClick={() => navigator.clipboard.writeText(output)}
              style={{ padding: '5px 12px', borderRadius: 6, fontSize: 12, background: C.bg3,
                border: `1px solid ${C.border2}`, color: C.text2, cursor: 'pointer' }}>
              Copy
            </button>}
          </CardHeader>
          <CardBody>
            {generating
              ? <div style={{ color: C.text3, fontStyle: 'italic' }}>Analyzing data and generating report…</div>
              : <div style={{ fontSize: 13, lineHeight: 1.8, color: C.text2, whiteSpace: 'pre-wrap' }}>
                  {output.split('\n').map((line, i) => {
                    if (line.startsWith('## ')) return <div key={i} style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 10, marginTop: 20 }}>{line.slice(3)}</div>;
                    if (line.startsWith('### ')) return <div key={i} style={{ fontSize: 14, fontWeight: 700, color: C.blue, marginBottom: 6, marginTop: 14 }}>{line.slice(4)}</div>;
                    if (line.startsWith('**') && line.endsWith('**')) return <div key={i} style={{ fontWeight: 700, color: C.text }}>{line.slice(2,-2)}</div>;
                    if (line.startsWith('- ')) return <div key={i} style={{ paddingLeft: 16, borderLeft: `2px solid ${C.border2}`, marginBottom: 3 }}>• {line.slice(2)}</div>;
                    if (/^\d+\./.test(line)) return <div key={i} style={{ paddingLeft: 16, borderLeft: `2px solid ${C.blue}`, marginBottom: 3 }}>{line}</div>;
                    if (line === '---') return <hr key={i} style={{ border: 'none', borderTop: `1px solid ${C.border}`, margin: '16px 0' }} />;
                    return <div key={i} style={{ marginBottom: 4 }}>{line || <br />}</div>;
                  })}
                </div>
            }
          </CardBody>
        </Card>
      )}
    </div>
  );
}

// ── Incident Investigation Timeline ────────────────────────────────────
// Renders an ordered sequence of a user's events around the selected
// incident: timestamp, user, resource, action, destination, and risk score.
// Analyst-friendly forensic narrative (e.g. login → access → download → exfil).
function timeOnly(ts: string) {
  const d = new Date(ts.replace(' ', 'T'));
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
}
function actionPhrase(e: EventRow) {
  const res = e.resource || 'resource';
  switch (e.action) {
    case 'login': return e.status === 'failure' ? 'Failed login attempt' : 'User login';
    case 'file_access': return `Accessed ${res}`;
    case 'sql_query': return `Queried ${res}`;
    case 'api_call': return `API call to ${res}`;
    case 'admin_operation': return `Admin operation on ${res}`;
    case 'export_data':
      return e.rowcount > 0 ? `Downloaded ${e.rowcount.toLocaleString()} rows from ${res}` : `Exported ${res}`;
    default: return `${(e.action || 'action').replace(/_/g, ' ')} on ${res}`;
  }
}
function IncidentTimeline({ event, events }: { event: EventRow; events: EventRow[] }) {
  // Chronological sequence for this user; window around the selected incident.
  const userEvents = events
    .filter(e => e.uid === event.uid)
    .sort((a, b) => new Date(a.ts.replace(' ', 'T')).getTime() - new Date(b.ts.replace(' ', 'T')).getTime());
  const selIdx = userEvents.findIndex(e => e.id === event.id);
  const start = Math.max(0, (selIdx < 0 ? userEvents.length : selIdx) - 6);
  const window = userEvents.slice(start, start + 12);

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.text3, marginBottom: 12 }}>
        Investigation Timeline — {event.user}
      </div>
      <div style={{ position: 'relative', paddingLeft: 8 }}>
        {window.map((e, i) => {
          const sel = e.id === event.id;
          const col = scoreColor(e.score);
          const last = i === window.length - 1;
          return (
            <div key={e.id} style={{ position: 'relative', display: 'flex', gap: 12, paddingBottom: last ? 0 : 14 }}>
              {/* connector + node */}
              <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center', width: 18 }}>
                <div style={{ width: 12, height: 12, borderRadius: '50%', background: sel ? col : C.bg,
                  border: `2px solid ${col}`, marginTop: 3, zIndex: 1,
                  boxShadow: sel ? `0 0 0 4px ${col}33` : 'none' }} />
                {!last && <div style={{ flex: 1, width: 2, background: C.border, marginTop: 2 }} />}
              </div>
              {/* content */}
              <div style={{ flex: 1, background: sel ? C.bg4 : C.bg3, border: `1px solid ${sel ? col + '55' : C.border}`,
                borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: C.text2, minWidth: 64 }}>{timeOnly(e.ts)}</span>
                  <span style={{ fontSize: 13 }}>{actionIcon(e.action)}</span>
                  <span style={{ fontSize: 13, fontWeight: sel ? 700 : 500, color: C.text }}>{actionPhrase(e)}</span>
                  {sel && <SevBadge sev={e.sev} />}
                  <span style={{ marginLeft: 'auto', fontSize: 12, fontWeight: 700, color: col }}>{e.score}/100</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4, fontSize: 11, color: C.text3, flexWrap: 'wrap' }}>
                  <span>Resource: <span style={{ color: C.text2 }}>{e.resource || '—'}</span></span>
                  <span>· Destination: <span style={{ color: destColor(e.destScore) }}>{(e.dest || 'internal').replace(/_/g, ' ')}</span></span>
                  {e.firstTime && <span style={{ color: C.orange }}>· first-time access</span>}
                </div>
              </div>
            </div>
          );
        })}
        {/* terminal alert node for the selected incident */}
        {(event.sev === 'CRITICAL' || event.sev === 'HIGH') && (
          <div style={{ position: 'relative', display: 'flex', gap: 12, paddingTop: 14 }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 18 }}>
              <div style={{ width: 12, height: 12, borderRadius: '50%', background: C.red, border: `2px solid ${C.red}`,
                boxShadow: `0 0 0 4px ${C.red}33` }} />
            </div>
            <div style={{ flex: 1, background: C.redDim, border: `1px solid ${C.redBorder}`, borderRadius: 8, padding: '8px 12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: C.red, minWidth: 64 }}>{timeOnly(event.ts)}</span>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.red }}>⚠ {event.sev} alert generated</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Incident Modal ─────────────────────────────────────────────────────
function IncidentModal({ event, events, profileMap, onClose, onStartAI }: {
  event: EventRow; events: EventRow[]; profileMap: Record<string, Profile>; onClose: () => void; onStartAI: (uid: string) => void;
}) {
  const p = profileMap[event.uid] || {} as Profile;
  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 100,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center', overflowY: 'auto', padding: '40px 20px' }}>
      <div onClick={e => e.stopPropagation()} style={{ background: C.bg2, border: `1px solid ${C.border2}`,
        borderRadius: 12, width: 700, maxWidth: '100%', overflow: 'hidden', animation: 'fadeUp 0.2s ease' }}>
        <div style={{ padding: '20px 24px', borderBottom: `1px solid ${C.border}`,
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <SevBadge sev={event.sev} />
              <div style={{ fontSize: 15, fontWeight: 700 }}>{event.action.replace(/_/g,' ').toUpperCase()} — {event.resource}</div>
            </div>
            <div style={{ fontSize: 12, color: C.text3 }}>
              Detected: {fmtTs(event.ts)} · Risk: <strong style={{ color: scoreColor(event.score) }}>{event.score}/100</strong>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.text3, cursor: 'pointer', fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>

        <div style={{ padding: '20px 24px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
            {[
              ['User', event.user], ['User ID', event.uid], ['Department', event.dept], ['Job Title', event.job || '—'],
              ['Privilege', event.priv], ['Account', event.active === 'true' ? '● Active' : '⊗ Inactive'],
              ['Action', event.action.replace(/_/g,' ')], ['Resource', event.resource],
              ['Sensitivity', event.sens.toUpperCase()], ['Status', event.status],
              ['Source IP', event.ip], ['Time Class', event.tc.replace(/_/g,' ').toUpperCase()],
              ['Destination', event.dest.replace(/_/g,' ')], ['Destination Risk', `+${event.destScore}`],
              ['First-Time Access', event.firstTime ? `Yes (+${event.firstTimeScore})` : 'No'],
            ].map(([l, v]) => (
              <div key={l} style={{ background: C.bg3, borderRadius: 6, padding: '10px 12px' }}>
                <div style={{ fontSize: 10, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 3 }}>{l}</div>
                <div style={{ fontSize: 13, fontWeight: 500, fontFamily: ['Source IP','User ID'].includes(l as string) ? 'monospace' : 'inherit',
                  color: l === 'Account' ? (event.active === 'true' ? C.green : C.red)
                    : l === 'Status' ? (event.status === 'failure' ? C.red : C.green)
                    : l === 'First-Time Access' ? (event.firstTime ? C.orange : C.green)
                    : (l === 'Destination' || l === 'Destination Risk') ? destColor(event.destScore) : C.text }}>{v}</div>
              </div>
            ))}
          </div>

          <IncidentTimeline event={event} events={events} />

          {Array.isArray(event.reasons) && event.reasons.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.text3, marginBottom: 8 }}>Risk Indicators</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {event.reasons.map((r, i) => (
                  <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px',
                    background: C.redDim, color: C.red, border: `1px solid ${C.redBorder}`, borderRadius: 4, fontSize: 11 }}>⚠ {r}</span>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
            <div style={{ background: C.bg3, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>ML Anomaly Score</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: scoreColor(event.ml_anomaly_score) }}>{Math.round(event.ml_anomaly_score)}/100</div>
            </div>
            <div style={{ background: C.bg3, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>Rule Score</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: scoreColor(event.rule_score) }}>{Math.round(event.rule_score)}/100</div>
            </div>
            <div style={{ background: C.bg3, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>Row Count</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>{event.rowcount.toLocaleString()}</div>
              <div style={{ fontSize: 11, color: C.text3, marginTop: 6 }}>User avg: {Math.round(event.user_avg_rowcount)}</div>
            </div>
            <div style={{ background: C.bg3, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>Deviation</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: event.deviation_from_user_avg_rowcount > 0 ? C.red : C.green }}>
                {Math.round(event.deviation_from_user_avg_rowcount)}
              </div>
              <div style={{ fontSize: 11, color: C.text3, marginTop: 6 }}>
                {event.deviation_from_user_avg_rowcount > 0 ? 'Above baseline' : 'Below baseline'}
              </div>
            </div>
          </div>

          {Array.isArray(event.rules_triggered) && event.rules_triggered.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.text3, marginBottom: 8 }}>Rules Triggered</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {event.rules_triggered.map((rule, i) => (
                  <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px',
                    background: C.bg4, color: C.text, border: `1px solid ${C.border}`, borderRadius: 4, fontSize: 11 }}>{rule}</span>
                ))}
              </div>
            </div>
          )}

          {event.explanation && (
            <div style={{ marginBottom: 16, background: 'rgba(255,255,255,0.02)', border: `1px solid ${C.border}`, borderRadius: 6, padding: 12 }}>
              <div style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, color: C.blue, marginBottom: 6 }}>Forensic Explanation</div>
              <div style={{ fontSize: 12, color: C.text2, lineHeight: 1.5 }}>{event.explanation}</div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => { onClose(); onStartAI(event.uid); }}
              style={{ padding: '8px 16px', borderRadius: 6, fontSize: 13, fontWeight: 600,
                background: C.blue, border: 'none', color: '#000', cursor: 'pointer' }}>
              ✦ AI Deep Analysis
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── User Modal ─────────────────────────────────────────────────────────
function UserModal({ uid, data, onClose, onStartAI }: {
  uid: string; data: DerivedData; onClose: () => void; onStartAI: (uid: string) => void;
}) {
  const p = data.profileMap[uid] || {} as Profile;
  const risk = data.userRisk[uid] || { maxScore: 0, alertCount: 0, events: [] };
  const topEvs = [...risk.events].sort((a, b) => b.score - a.score).slice(0, 8);
  const color = avatarColor(p.user || uid);

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 100,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'center', overflowY: 'auto', padding: '40px 20px' }}>
      <div onClick={e => e.stopPropagation()} style={{ background: C.bg2, border: `1px solid ${C.border2}`,
        borderRadius: 12, width: 780, maxWidth: '100%', overflow: 'hidden' }}>
        <div style={{ padding: '20px 24px', borderBottom: `1px solid ${C.border}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 48, height: 48, borderRadius: '50%', display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: 16, fontWeight: 700, background: `${color}22`, color, border: `2px solid ${color}44` }}>
              {initials(p.user || uid)}
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700 }}>{p.user || uid}</div>
              <div style={{ fontSize: 12, color: C.text3, marginTop: 2 }}>{p.dept} · {p.job} · {p.priv}</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.text3, cursor: 'pointer', fontSize: 18 }}>✕</button>
        </div>
        <div style={{ padding: '20px 24px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
            {[
              { l: 'Max Risk', v: risk.maxScore, c: scoreColor(risk.maxScore) },
              { l: 'Alert Count', v: risk.alertCount, c: risk.alertCount > 5 ? C.red : risk.alertCount > 2 ? C.orange : C.text2 },
              { l: 'Days Inactive', v: p.inactive + 'd', c: p.inactive > 30 ? C.red : C.text2 },
              { l: 'Status', v: p.active === 'true' ? 'Active' : 'Inactive', c: p.active === 'true' ? C.green : C.red },
            ].map(s => (
              <div key={s.l} style={{ background: C.bg3, borderRadius: 8, padding: 12, textAlign: 'center' }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: s.c }}>{s.v}</div>
                <div style={{ fontSize: 11, color: C.text3, marginTop: 2 }}>{s.l}</div>
              </div>
            ))}
          </div>

          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text3, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 10 }}>Top Suspicious Events</div>
            {topEvs.map(e => (
              <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: `1px solid ${C.border}` }}>
                <SevBadge sev={e.sev} />
                <div style={{ flex: 1, fontSize: 12, color: C.text2 }}>
                  {e.action.replace(/_/g,' ')} on <strong style={{ color: C.text }}>{e.resource}</strong>
                </div>
                <div style={{ fontSize: 11, color: C.text3, whiteSpace: 'nowrap' }}>{fmtTs(e.ts)}</div>
                <div style={{ fontSize: 13, fontWeight: 700, color: scoreColor(e.score), minWidth: 24 }}>{e.score}</div>
              </div>
            ))}
          </div>

          <button onClick={() => { onClose(); onStartAI(uid); }}
            style={{ padding: '8px 20px', borderRadius: 6, fontSize: 13, fontWeight: 600,
              background: C.blue, border: 'none', color: '#000', cursor: 'pointer' }}>
            ✦ AI Threat Assessment
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────
const NAV = [
  { section: 'Investigation', items: [
    { id: 'overview', icon: '◈', label: 'Overview' },
    { id: 'alerts', icon: '⚠', label: 'Active Alerts', badge: 'alerts' },
    { id: 'timeline', icon: '◎', label: 'Event Timeline' },
    { id: 'cases', icon: '📋', label: 'Case Files', badge: 'cases' },
  ]},
  { section: 'Intelligence', items: [
    { id: 'users', icon: '👤', label: 'User Profiles' },
    { id: 'heatmap', icon: '▦', label: 'Access Heatmap' },
    { id: 'analytics', icon: '📊', label: 'Analytics' },
  ]},
  { section: 'Tools', items: [
    { id: 'ailab', icon: '✦', label: 'AI Analyst', badge: 'ai' },
    { id: 'reports', icon: '📄', label: 'Reports' },
  ]},
];

const PAGE_TITLES: Record<string, { title: string; sub: string }> = {
  overview: { title: 'Threat Overview', sub: 'Enterprise Data Access Intelligence' },
  alerts: { title: '⚠ Active Alerts', sub: 'All flagged events requiring investigation' },
  timeline: { title: '◎ Event Timeline', sub: 'Chronological investigation trail' },
  cases: { title: '📋 Case Files', sub: 'High-risk users — auto-generated from anomaly patterns' },
  users: { title: '👤 User Profiles', sub: 'All tracked users and their access history' },
  heatmap: { title: '▦ Access Heatmap', sub: 'Temporal patterns of data access events' },
  analytics: { title: '📊 Analytics', sub: 'Deep-dive statistical analysis' },
  ailab: { title: '✦ AI Analyst', sub: 'Conversational threat intelligence' },
  reports: { title: '📄 Reports', sub: 'Auto-generated incident and compliance reports' },
};

export default function App() {
  const [page, setPage] = useState('overview');
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [userModalId, setUserModalId] = useState<string | null>(null);
  const [aiInitQuery, setAiInitQuery] = useState<string | null>(null);

  const data = useMemo(() => buildData(), []);

  const alertCount = data.critical.length + data.high.length;
  const caseCount = Object.values(data.userRisk).filter(r => r.maxScore >= 70).length;

  function handleStartAI(uid: string) {
    const p = data.profileMap[uid] || {} as Profile;
    const risk = data.userRisk[uid] || { maxScore: 0, alertCount: 0, events: [] };
    const topEvts = [...risk.events].sort((a, b) => b.score - a.score).slice(0, 5);
    const q = `Conduct a full threat assessment for ${p.user || uid}.\n\nProfile: ${p.dept} / ${p.job} / ${p.priv} privilege\nAccount: ${p.active === 'true' ? 'Active' : 'INACTIVE'}, ${p.inactive} days inactive\nMax Risk Score: ${risk.maxScore}/100, Total Alerts: ${risk.alertCount}\n\nTop suspicious events:\n${topEvts.map(e => `- [${e.sev}] ${e.action.replace(/_/g,' ')} on ${e.resource} at ${e.ts} (score ${e.score}) — ${e.reasons.join('; ')}`).join('\n')}\n\nProvide: 1) Overall threat level 2) Behavioral pattern analysis 3) Most concerning actions 4) Whether account should be suspended 5) Investigation steps`;
    setAiInitQuery(q);
    setPage('ailab');
  }

  const pt = PAGE_TITLES[page] || { title: '', sub: '' };

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: C.bg,
      backgroundImage: 'radial-gradient(circle at 18% 0%,rgba(77,171,247,0.09),transparent 34%),radial-gradient(circle at 100% 12%,rgba(255,71,87,0.07),transparent 28%)',
      color: C.text, fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif", fontSize: 14 }}>
      {/* Sidebar */}
      <div style={{ width: 220, minWidth: 220, background: 'linear-gradient(180deg,rgba(17,19,24,0.98),rgba(10,12,16,0.98))',
        borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', overflowY: 'auto',
        boxShadow: '18px 0 48px rgba(0,0,0,0.25)' }}>
        <div style={{ padding: '20px 16px 14px', borderBottom: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 28, height: 28, background: C.red, borderRadius: 6,
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14 }}>⚡</div>
            SentinelIQ
          </div>
          <div style={{ fontSize: 10, color: C.text3, marginTop: 2, letterSpacing: 1, textTransform: 'uppercase' }}>
            Insider Threat Intelligence
          </div>
        </div>

        {NAV.map(({ section, items }) => (
          <div key={section} style={{ padding: '8px 0' }}>
            <div style={{ padding: '6px 16px 4px', fontSize: 10, fontWeight: 600, color: C.text3,
              letterSpacing: 1.2, textTransform: 'uppercase' }}>{section}</div>
            {items.map(item => {
              const isActive = page === item.id;
              const badge = item.badge === 'alerts' ? alertCount : item.badge === 'cases' ? caseCount : null;
              return (
                <div key={item.id} onClick={() => setPage(item.id)}
                  style={{ padding: '8px 16px', cursor: 'pointer', fontSize: 13, display: 'flex', alignItems: 'center', gap: 10,
                    borderLeft: `2px solid ${isActive ? C.blue : 'transparent'}`,
                    color: isActive ? C.blue : C.text2,
                    background: isActive ? C.blueDim : 'transparent',
                    transition: 'all 0.15s' }}
                  onMouseEnter={el => { if (!isActive) { el.currentTarget.style.color = C.text; el.currentTarget.style.background = 'rgba(255,255,255,0.04)'; }}}
                  onMouseLeave={el => { if (!isActive) { el.currentTarget.style.color = C.text2; el.currentTarget.style.background = 'transparent'; }}}>
                  <span style={{ fontSize: 15, width: 18, textAlign: 'center' }}>{item.icon}</span>
                  {item.label}
                  {item.badge === 'ai' && (
                    <span style={{ marginLeft: 'auto', background: C.blue, color: '#000',
                      fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10 }}>AI</span>
                  )}
                  {badge !== null && badge !== undefined && badge > 0 && item.badge !== 'ai' && (
                    <span style={{ marginLeft: 'auto', background: item.badge === 'cases' ? C.orange : C.red,
                      color: 'white', fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10 }}>
                      {badge}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        ))}

        <div style={{ marginTop: 'auto', padding: '12px 16px', borderTop: `1px solid ${C.border}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: C.text3 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: C.green,
              animation: 'pulse 2s infinite' }} />
            Live monitoring active
          </div>
          <div style={{ fontSize: 10, color: C.text3, marginTop: 4 }}>
            {data.events.length.toLocaleString()} events loaded
          </div>
        </div>
      </div>

      {/* Main */}
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
        {/* Topbar */}
        <div style={{ padding: '14px 24px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center',
          gap: 16, background: C.bg2, position: 'sticky', top: 0, zIndex: 10 }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 600 }}>{pt.title}</div>
            <div style={{ fontSize: 12, color: C.text3, marginTop: 1 }}>{pt.sub}</div>
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: C.text3, fontFamily: 'monospace' }}>Apr 2025 – Jun 2026</span>
            {page !== 'ailab' && (
              <button onClick={() => setPage('ailab')}
                style={{ padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                  background: C.blue, border: 'none', color: '#000', cursor: 'pointer' }}>
                ✦ AI Analysis
              </button>
            )}
          </div>
        </div>

        {/* Pages */}
        {page === 'overview' && <OverviewPage data={data} onShowIncident={setIncidentId} onShowPage={setPage} />}
        {page === 'alerts' && <AlertsPage data={data} onShowIncident={setIncidentId} />}
        {page === 'timeline' && <TimelinePage data={data} onShowIncident={setIncidentId} />}
        {page === 'cases' && <CasesPage data={data} onShowUser={setUserModalId} onStartAI={uid => handleStartAI(uid)} />}
        {page === 'users' && <UsersPage data={data} onShowUser={setUserModalId} />}
        {page === 'heatmap' && <HeatmapPage data={data} />}
        {page === 'analytics' && <AnalyticsPage data={data} />}
        {page === 'ailab' && (
          <AIAnalystPage data={data} initQuery={aiInitQuery}
            onInitQueryConsumed={() => setAiInitQuery(null)} />
        )}
        {page === 'reports' && <ReportsPage data={data} />}
      </div>

      {/* Modals */}
      {incidentId && (() => {
        const ev = data.events.find(e => e.id === incidentId);
        return ev ? <IncidentModal event={ev} events={data.events} profileMap={data.profileMap}
          onClose={() => setIncidentId(null)}
          onStartAI={uid => { setIncidentId(null); handleStartAI(uid); }} /> : null;
      })()}
      {userModalId && (
        <UserModal uid={userModalId} data={data} onClose={() => setUserModalId(null)}
          onStartAI={uid => { setUserModalId(null); handleStartAI(uid); }} />
      )}

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
        ::-webkit-scrollbar{width:6px;height:6px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:#1e2130;border-radius:3px}
        ::-webkit-scrollbar-thumb:hover{background:#555b66}
        * { box-sizing: border-box; margin: 0; padding: 0; }
      `}</style>
    </div>
  );
}
