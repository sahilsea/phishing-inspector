import { FlaggedClause, MetricScore } from '../types/inspector';

export interface PaymentDetectionResult {
  financialTrap: MetricScore;
  financialRisk: number; // 0 (no risk) to 100 (extreme risk)
  flaggedClauses: FlaggedClause[];
}

interface PaymentPatternRule {
  id: string;
  name: string;
  pattern: RegExp;
  weight: number;
  severity: 'CRITICAL' | 'WARNING';
  explanation: string;
  tag: string;
}

const PAYMENT_RULES: PaymentPatternRule[] = [
  {
    id: 'fin-check-deposit',
    name: 'Advance Check Cashing',
    pattern: /(?:electronic|cashier'?s|reimbursement|advance)?\s*check\s*(?:of\s*)?\$[0-9,]+|(?:deposit\s*(?:this|the|an)\s*check)|(?:issue\s*an\s*electronic\s*check)/i,
    weight: 40,
    severity: 'CRITICAL',
    explanation: 'Classic counterfeit check scam pattern: victim is asked to deposit a forged check before the bank completes clearance.',
    tag: 'Counterfeit Check Trap [SEV-1]',
  },
  {
    id: 'fin-wire-zelle',
    name: 'Irreversible P2P / Wire Transfer',
    pattern: /(?:transfer|send|wire)\s*(?:\$[0-9,]+\s*)?(?:via\s*)?(?:zelle|cash\s*app|venmo|wire\s*transfer|western\s*union|moneygram)/i,
    weight: 45,
    severity: 'CRITICAL',
    explanation: 'Demanding immediate payment via non-reversible instant payment channels (Zelle, CashApp, Wire) to bypass consumer fraud protections.',
    tag: 'Financial Exploitation [SEV-1]',
  },
  {
    id: 'fin-vendor-redirection',
    name: 'Third-Party Hardware Vendor Redirection',
    pattern: /(?:certified|approved|authorized)\s*(?:apple|hardware|equipment|technology)?\s*(?:vendor|supplier|distributor|merchant|provider)|(?:equipment|telework|workstation)[-_ ](?:dispatch|vendor)/i,
    weight: 35,
    severity: 'CRITICAL',
    explanation: 'Directing candidate to wire money to an alleged "certified vendor" or unverified hardware dispatch service.',
    tag: 'Bogus Vendor Routing [SEV-1]',
  },
  {
    id: 'fin-crypto-demand',
    name: 'Cryptocurrency Wallet Transfer',
    pattern: /(?:bitcoin|btc|ethereum|eth|usdt|crypto\s*wallet|crypto\s*transfer)\b|\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\b0x[a-fA-F0-9]{40}\b/i,
    weight: 50,
    severity: 'CRITICAL',
    explanation: 'Soliciting cryptocurrency payments eliminates chargeback mechanisms and anonymizes recipient transaction trails.',
    tag: 'Crypto Asset Demand [SEV-1]',
  },
  {
    id: 'fin-onboarding-fee',
    name: 'Upfront Onboarding or Training Fee',
    pattern: /(?:onboarding|training|registration|application|background\s*check|equipment)\s*fee|(?:refundable\s*deposit)/i,
    weight: 35,
    severity: 'CRITICAL',
    explanation: 'Legitimate employers never charge candidates upfront fees, security deposits, or screening costs.',
    tag: 'Advance Fee Trap [SEV-1]',
  },
  {
    id: 'fin-purchase-equipment-personally',
    name: 'Personal Equipment Procurement Requirement',
    pattern: /(?:purchase|buy)\s*(?:your\s*own\s*)?(?:home\s*office|workstation|laptop|equipment)\s*(?:and\s*we\s*will\s*reimburse)/i,
    weight: 25,
    severity: 'WARNING',
    explanation: 'Shifting hardware procurement financial liability to candidate prior to verified contract execution.',
    tag: 'Procurement Risk [SEV-2]',
  },
];

/**
 * Extracts the surrounding sentence or full clause for context
 */
function extractClauseQuote(fullText: string, matchIndex: number, matchLength: number): { quote: string; offset: string } {
  // Find sentence or newline boundaries
  let cleanStart = fullText.lastIndexOf('\n', matchIndex);
  if (cleanStart === -1 || matchIndex - cleanStart > 120) {
    cleanStart = Math.max(0, matchIndex - 40);
  } else {
    cleanStart += 1;
  }

  let cleanEnd = fullText.indexOf('\n', matchIndex + matchLength);
  if (cleanEnd === -1 || cleanEnd - matchIndex > 180) {
    cleanEnd = Math.min(fullText.length, matchIndex + matchLength + 60);
  }

  const excerpt = fullText.substring(cleanStart, cleanEnd).trim();
  const offset = `Offset: ${matchIndex}–${matchIndex + matchLength}`;
  return {
    quote: excerpt.startsWith('"') ? excerpt : `"${excerpt}"`,
    offset,
  };
}

/**
 * Scans payload for advance-fee traps, wire transfers, crypto wallets, and check cashing schemes
 */
export function detectPaymentTraps(payloadText: string): PaymentDetectionResult {
  const flaggedClauses: FlaggedClause[] = [];
  let accumulatedRisk = 0;
  const triggeredRuleIds = new Set<string>();

  // Check if text explicitly states equipment provided internally by employer (legitimate sign)
  const isCorporateProvidedLogistics = /equipment provided strictly via.*logistics|never ask for banking information/i.test(payloadText);

  for (const rule of PAYMENT_RULES) {
    const match = rule.pattern.exec(payloadText);
    if (match) {
      triggeredRuleIds.add(rule.id);
      accumulatedRisk += rule.weight;
      
      const { quote, offset } = extractClauseQuote(payloadText, match.index, match[0].length);
      flaggedClauses.push({
        id: rule.id,
        text: quote,
        category: 'FINANCIAL',
        severity: rule.severity,
        explanation: rule.explanation,
        offset,
        tag: rule.tag,
      });
    }
  }

  // Calculate normalized Financial Risk score (0 to 100)
  let financialRisk = Math.min(100, accumulatedRisk);

  // If both check cashing and wire/Zelle transfer are found, amplify to critical danger (98%)
  if (triggeredRuleIds.has('fin-check-deposit') && (triggeredRuleIds.has('fin-wire-zelle') || triggeredRuleIds.has('fin-vendor-redirection'))) {
    financialRisk = 98;
  }

  // If legitimate enterprise logistics explicitly verified and no fraud patterns triggered
  if (isCorporateProvidedLogistics && financialRisk === 0) {
    financialRisk = 0;
  } else if (financialRisk === 0 && (payloadText.toLowerCase().includes('hourly') || payloadText.toLowerCase().includes('contract'))) {
    // Gray zone or normal contract with no upfront fees
    financialRisk = 8;
  }

  // Determine MetricScore representation
  let status: MetricScore['status'] = 'SAFE';
  let detail = 'No cashier checks, wire demands, or off-platform vendor routing.';

  if (financialRisk >= 70) {
    status = 'CRITICAL';
    detail = 'Advance-fee equipment purchase demand detected.';
  } else if (financialRisk >= 25) {
    status = 'WARNING';
    detail = 'Suspicious payment or equipment reimbursement clause identified.';
  } else if (financialRisk > 0) {
    status = 'SAFE';
    detail = 'Zero wire transfer or upfront fee indicators found.';
  }

  const financialTrap: MetricScore = {
    score: financialRisk,
    label: 'Financial Trap',
    detail,
    status,
  };

  return {
    financialTrap,
    financialRisk,
    flaggedClauses,
  };
}
