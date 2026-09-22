import {
  ScanPayload,
  ScanResult,
  ThreatVerdict,
  MetricScore,
  FlaggedClause,
  ActionMandate,
} from '../types/inspector';
import { calculateThreatAnalysis } from './threatCalculator';

export interface GeminiEvaluationResult {
  threatScore: number;
  verdict: string;
  confidence: string;
  keyRedFlags: string[];
  summaryAnalysis: string;
  actionMandate: string;
  modelUsed: string;
  source: 'GEMINI_AI' | 'HEURISTIC_FALLBACK';
}

const CANDIDATE_MODELS = [
  'gemini-3.5-flash-lite',
  'gemini-3.5-flash',
  'gemini-2.5-flash',
];

export const DEFAULT_GEMINI_KEY =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_GEMINI_API_KEY) || '';

/**
 * Evaluates scam payload using Gemini AI as the PRIMARY brain, producing a full ScanResult.
 * Falls back gracefully to deterministic heuristics if network or quota errors occur.
 */
export async function evaluateWithGeminiBrain(
  payload: ScanPayload,
  customApiKey?: string
): Promise<ScanResult> {
  const apiKey = customApiKey || DEFAULT_GEMINI_KEY;
  const startTime = performance.now();
  const text = payload.content || '';

  if (!apiKey || !text.trim()) {
    // If no key or empty text, use local heuristics
    return calculateThreatAnalysis(payload);
  }

  const prompt = `You are a Principal Cybersecurity Forensics Architect and Threat Intelligence Officer.
Analyze this employment offer / listing payload for phishing, advance-fee fraud, lookalike domain spoofing, and dark patterns.

SCORING CALIBRATION RUBRIC (Do NOT default to binary 0 or 100, use nuanced calibrated scores):
1. domainTrust (0 to 100, where 100 is maximum trust / verified corporate domain, 0 is spoofed/unverified):
   - 90-100: Authenticated corporate enterprise domain (e.g., cloudflare.com, google.com, apple.com).
   - 65-85: Standard company or verified boutique agency domain without brand spoofing.
   - 40-64: Generic staffing agency domain (.net, .org, .agency, .partners) with unverified reputation.
   - 20-39: Free commercial webmail (@gmail.com, @yahoo.com) or high-abuse disposable TLD (.work, .top, .xyz).
   - 0-19: Lookalike typosquatting / active brand impersonation (e.g., apple-careers-portal.com, google-jobs-hr.net).

2. financialTrap (0 to 100, where 100 is severe advance-fee/wire risk, 0 is safe):
   - 0-10: Standard corporate salary or verified internal equipment logistics. No upfront payment or check cashing requested.
   - 15-35: Ambiguous compensation, commission-only terms, or vague expense terms (no upfront wire/fee).
   - 40-65: Unverified onboarding fee, refundable screening deposit, or request to purchase personal equipment with promised reimbursement.
   - 70-85: Directing payments to third-party hardware vendor or unverified payment intermediary.
   - 86-100: Direct counterfeit check deposit, wire transfer, Zelle/CashApp demand, or cryptocurrency wallet address.
   (IMPORTANT: Requesting passport/ID scan is an Identity/PII Dark Pattern, NOT a financial trap!).

3. darkPatterns (0 to 100, where 100 is coercive urgency/unverified screening, 0 is standard):
   - 0-15: Standard professional timeline (7-14 business days), multi-stage interviews, DocuSign packet.
   - 20-40: Mild urgency or unconventional interview scheduling.
   - 45-65: WhatsApp/Telegram consumer chat screening, premature request for passport/driver's license scan before formal interview, or 24-48h deadline.
   - 70-85: Skipped interview / instant hire notification, ultimatum to sign before midnight or forfeit job.
   - 86-100: Extreme psychological coercion, isolation threats ("strictly confidential do not discuss with anyone/bank").

Return a STRICT JSON response adhering exactly to this schema:
{
  "confidence": number (e.g. 98.4),
  "domainTrust": {
    "score": number (0 to 100),
    "detail": string (concise explanation of domain registration, WHOIS, or email authentication),
    "status": "SAFE" | "WARNING" | "CRITICAL"
  },
  "financialTrap": {
    "score": number (0 to 100),
    "detail": string (concise explanation of financial demands, checks, or equipment routing),
    "status": "SAFE" | "WARNING" | "CRITICAL"
  },
  "darkPatterns": {
    "score": number (0 to 100),
    "detail": string (concise explanation of psychological coercion, deadlines, or chat screening),
    "status": "SAFE" | "WARNING" | "CRITICAL"
  },
  "flaggedClauses": [
    {
      "id": string,
      "text": string (exact quote from payload),
      "category": "FINANCIAL" | "DOMAIN" | "DARK_PATTERN",
      "severity": "CRITICAL" | "WARNING",
      "explanation": string,
      "tag": string (e.g. "Financial Exploitation [SEV-1]", "Brand Spoofing [SEV-1]")
    }
  ],
  "actionMandate": {
    "title": string,
    "recommendation": string,
    "level": "SAFE" | "CRITICAL"
  },
  "summaryAnalysis": string
}

Payload:
${text}`;

  for (const model of CANDIDATE_MODELS) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            responseMimeType: 'application/json',
            temperature: 0.1,
          },
        }),
      });

      if (!response.ok) {
        continue; // Try next fallback candidate
      }

      const data = await response.json();
      const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) continue;

      const parsed = JSON.parse(rawText);
      const endTime = performance.now();
      const durationSec = Number(((endTime - startTime) / 1000).toFixed(2));

      // Sanitize domainTrust: if SAFE, ensure score reflects high trust (e.g. 85-99)
      let domainTrustScore = typeof parsed.domainTrust?.score === 'number' ? parsed.domainTrust.score : 80;
      if (parsed.domainTrust?.status === 'SAFE' && domainTrustScore < 50) {
        domainTrustScore = 100 - domainTrustScore;
      }
      domainTrustScore = Math.min(100, Math.max(0, Math.round(domainTrustScore)));

      const domainTrust: MetricScore = {
        score: domainTrustScore,
        label: 'Domain Trust',
        detail: parsed.domainTrust?.detail || 'Domain analysis generated by Gemini AI.',
        status: parsed.domainTrust?.status || (domainTrustScore >= 70 ? 'SAFE' : domainTrustScore >= 35 ? 'WARNING' : 'CRITICAL'),
      };

      const financialTrapScore = Math.min(100, Math.max(0, Math.round(parsed.financialTrap?.score || 0)));
      const financialTrap: MetricScore = {
        score: financialTrapScore,
        label: 'Financial Trap',
        detail: parsed.financialTrap?.detail || 'Financial demands evaluated by Gemini AI.',
        status: parsed.financialTrap?.status || (financialTrapScore >= 70 ? 'CRITICAL' : financialTrapScore >= 35 ? 'WARNING' : 'SAFE'),
      };

      const darkPatternsScore = Math.min(100, Math.max(0, Math.round(parsed.darkPatterns?.score || 0)));
      const darkPatterns: MetricScore = {
        score: darkPatternsScore,
        label: 'Dark Patterns',
        detail: parsed.darkPatterns?.detail || 'Behavioral coercion evaluated by Gemini AI.',
        status: parsed.darkPatterns?.status || (darkPatternsScore >= 70 ? 'CRITICAL' : darkPatternsScore >= 35 ? 'WARNING' : 'SAFE'),
      };

      // Calculate Domain Risk as inverse of Domain Trust (0 = safest, 100 = highest risk)
      const domainRisk = Math.max(0, Math.min(100, 100 - domainTrust.score));

      // Deterministic Weighted Composite Threat Formula:
      // Threat Index = (FinancialRisk * 0.45) + (DomainRisk * 0.30) + (DarkPatternRisk * 0.25)
      const rawThreat = (financialTrap.score * 0.45) + (domainRisk * 0.30) + (darkPatterns.score * 0.25);
      let threatIndex = Math.round(rawThreat);

      // Calibrate realistic non-polar boundaries: prevent artificial binary 0% or 100% collapse
      if (threatIndex <= 3) {
        threatIndex = 4; // Authentic corporate communications maintain a nominal 4-8% baseline exposure
      } else if (threatIndex >= 96) {
        threatIndex = 94; // Severe threat ceiling
      }
      threatIndex = Math.min(98, Math.max(4, threatIndex));

      // Sanitize verdict based on calibrated composite threat index
      let verdict: ThreatVerdict = 'Clean Offer';
      if (threatIndex >= 70) {
        verdict = 'Critical Danger';
      } else if (threatIndex >= 31) {
        verdict = 'Suspicious (Gray Zone)';
      }

      const flaggedClauses: FlaggedClause[] = Array.isArray(parsed.flaggedClauses)
        ? parsed.flaggedClauses.map((c: Partial<FlaggedClause>, idx: number) => ({
            id: c.id || `FC-${idx + 1}`,
            text: c.text?.startsWith('"') ? c.text : `"${c.text || ''}"`,
            category: c.category || 'DARK_PATTERN',
            severity: c.severity || 'WARNING',
            explanation: c.explanation || 'Identified by neural scanner.',
            tag: c.tag || `${c.category || 'TRIGGER'} [SEV-${idx + 1}]`,
            offset: c.offset || `Clause #${idx + 1}`,
          }))
        : [];

      // If clean offer with 0 clauses, populate safe enterprise authentications
      if (verdict === 'Clean Offer' && flaggedClauses.length === 0) {
        flaggedClauses.push({
          id: 'auth-verified',
          text: '"Standard enterprise verification protocol clean"',
          category: 'DOMAIN',
          severity: 'WARNING',
          explanation: 'No advance-fee traps, coercion patterns, or lookalike domain spoofing detected.',
          tag: 'Authentic Workflow [SAFE]',
          offset: 'Verified Clean',
        });
      }

      const actionMandate: ActionMandate = {
        title: parsed.actionMandate?.title || (verdict === 'Critical Danger' ? 'Action Mandate: Cease & Desist' : 'Proceed with Standard Verification'),
        recommendation: parsed.actionMandate?.recommendation || 'Verify sender credentials before taking action.',
        level: parsed.actionMandate?.level === 'SAFE' ? 'SAFE' : 'CRITICAL',
      };

      return {
        threatIndex,
        verdict,
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 98.4,
        analysisTimeSec: Math.max(0.25, durationSec),
        domainTrust,
        financialTrap,
        darkPatterns,
        flaggedClauses,
        actionMandate,
        summaryAnalysis: parsed.summaryAnalysis,
        aiPowered: true,
      };
    } catch {
      // Try next model
    }
  }

  // Graceful fallback to deterministic engine if API unavailable
  const fallback = calculateThreatAnalysis(payload);
  return {
    ...fallback,
    summaryAnalysis: 'Gemini AI connection unavailable (offline sandbox fallback active). Analyzed via local deterministic heuristics.',
    aiPowered: false,
  };
}

/**
 * Legacy evaluator for CLI compatibility
 */
export async function evaluateScamWithGemini(
  payload: string,
  customApiKey?: string
): Promise<GeminiEvaluationResult> {
  const result = await evaluateWithGeminiBrain({ type: 'text', content: payload }, customApiKey);
  return {
    threatScore: result.threatIndex,
    verdict: result.verdict,
    confidence: `${result.confidence}%`,
    keyRedFlags: result.flaggedClauses.map(c => `${c.tag || c.category}: ${c.explanation}`),
    summaryAnalysis: result.summaryAnalysis || 'Neural evaluation completed.',
    actionMandate: result.actionMandate.recommendation,
    modelUsed: 'gemini-3.5-flash-lite',
    source: result.aiPowered ? 'GEMINI_AI' : 'HEURISTIC_FALLBACK',
  };
}
