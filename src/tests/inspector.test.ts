import { describe, it, expect } from 'vitest';
import { calculateThreatAnalysis } from '../engine/threatCalculator';
import { inspectDomains, checkLookalikeDomain, extractNetworkEntities } from '../engine/domainInspector';
import { detectPaymentTraps } from '../engine/paymentDetector';
import { scanDarkPatterns } from '../engine/darkPatternScanner';
import {
  BLATANT_SCAM_SAMPLE,
  GRAY_ZONE_SAMPLE,
  CLEAN_OFFER_SAMPLE,
  SAMPLE_URL_SCAM,
  SAMPLE_URL_CLEAN,
} from '../engine/sampleData';

describe('Phishing Inspector Engine Verification Suite', () => {
  describe('Heuristic Sample Evaluation', () => {
    it('evaluates BLATANT_SCAM_SAMPLE at >= 85% threat index and Critical Danger verdict', () => {
      const result = calculateThreatAnalysis({
        type: 'text',
        content: BLATANT_SCAM_SAMPLE,
      });

      expect(result.threatIndex).toBeGreaterThanOrEqual(85);
      expect(result.verdict).toBe('Critical Danger');
      expect(result.actionMandate.level).toBe('CRITICAL');
      expect(result.financialTrap.status).toBe('CRITICAL');
      expect(result.confidence).toBeGreaterThanOrEqual(95);

      // Verify triggered clauses include financial exploitation and unverified channel
      const clauseCategories = result.flaggedClauses.map((c) => c.category);
      expect(clauseCategories).toContain('FINANCIAL');
      expect(clauseCategories).toContain('DARK_PATTERN');
    });

    it('evaluates CLEAN_OFFER_SAMPLE at <= 20% threat index and Clean Offer verdict', () => {
      const result = calculateThreatAnalysis({
        type: 'text',
        content: CLEAN_OFFER_SAMPLE,
      });

      expect(result.threatIndex).toBeLessThanOrEqual(20);
      expect(result.verdict).toBe('Clean Offer');
      expect(result.actionMandate.level).toBe('SAFE');
      expect(result.domainTrust.status).toBe('SAFE');
      expect(result.confidence).toBeGreaterThanOrEqual(90);
    });

    it('evaluates GRAY_ZONE_SAMPLE between 31% and 69% threat index and Suspicious (Gray Zone) verdict', () => {
      const result = calculateThreatAnalysis({
        type: 'text',
        content: GRAY_ZONE_SAMPLE,
      });

      expect(result.threatIndex).toBeGreaterThanOrEqual(31);
      expect(result.threatIndex).toBeLessThanOrEqual(69);
      expect(result.verdict).toBe('Suspicious (Gray Zone)');
      expect(result.darkPatterns.score).toBeGreaterThanOrEqual(50);
    });
  });

  describe('Payment Detector Engine', () => {
    it('correctly catches advance checks and electronic check cashing schemes', () => {
      const payload = 'We will send you an electronic check of $5,000 to deposit immediately into your checking account.';
      const res = detectPaymentTraps(payload);

      expect(res.financialRisk).toBeGreaterThanOrEqual(40);
      expect(res.flaggedClauses.some((c) => c.id === 'fin-check-deposit')).toBe(true);
    });

    it('correctly catches wire transfers and Zelle/Venmo demands', () => {
      const payload = 'Please send $3,500 via Zelle or wire transfer to our certified equipment supplier.';
      const res = detectPaymentTraps(payload);

      expect(res.financialRisk).toBeGreaterThanOrEqual(45);
      expect(res.flaggedClauses.some((c) => c.id === 'fin-wire-zelle')).toBe(true);
      expect(res.flaggedClauses.some((c) => c.id === 'fin-vendor-redirection')).toBe(true);
    });

    it('amplifies risk to 98% when counterfeit check is coupled with vendor wire redirect', () => {
      const payload = 'Deposit this check of $4,850 and transfer $4,200 via wire transfer to our approved hardware vendor.';
      const res = detectPaymentTraps(payload);

      expect(res.financialRisk).toBe(98);
      expect(res.financialTrap.status).toBe('CRITICAL');
    });

    it('identifies cryptocurrency addresses and crypto wallet demands', () => {
      const payload = 'Transfer the onboarding registration fee to Bitcoin wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately.';
      const res = detectPaymentTraps(payload);

      expect(res.financialRisk).toBeGreaterThanOrEqual(50);
      expect(res.flaggedClauses.some((c) => c.id === 'fin-crypto-demand')).toBe(true);
    });

    it('identifies upfront onboarding fees and refundable deposits', () => {
      const payload = 'A refundable deposit of $250 is required for background check fee processing.';
      const res = detectPaymentTraps(payload);

      expect(res.financialRisk).toBeGreaterThanOrEqual(35);
      expect(res.flaggedClauses.some((c) => c.id === 'fin-onboarding-fee')).toBe(true);
    });
  });

  describe('Domain Inspector Engine', () => {
    it('extracts URLs, hostnames, and recruiter emails accurately', () => {
      const text = 'Contact recruiter.jane@apple-careers-portal.com or visit https://apple-careers-portal.com/apply';
      const entities = extractNetworkEntities(text);

      expect(entities.emails).toContain('recruiter.jane@apple-careers-portal.com');
      expect(entities.domains).toContain('apple-careers-portal.com');
      expect(entities.urls).toContain('https://apple-careers-portal.com/apply');
    });

    it('flags lookalike/typosquatted domains impersonating major tech enterprises', () => {
      const checkApple = checkLookalikeDomain('apple-careers-portal.com');
      expect(checkApple.isLookalike).toBe(true);
      expect(checkApple.impersonatedBrand).toBe('apple');

      const checkMeta = checkLookalikeDomain('meta-recruiting-desk.net');
      expect(checkMeta.isLookalike).toBe(true);
      expect(checkMeta.impersonatedBrand).toBe('meta');

      const checkGoogle = checkLookalikeDomain('google.com');
      expect(checkGoogle.isLookalike).toBe(false);
    });

    it('flags corporate hiring official using free commercial webmail (@gmail.com)', () => {
      const text = 'From: apple.recruiter.lead@gmail.com\nSubject: Job Offer';
      const res = inspectDomains(text);

      expect(res.domainTrust.score).toBeLessThanOrEqual(30);
      expect(res.flaggedClauses.some((c) => c.id.startsWith('dom-free-email-'))).toBe(true);
    });

    it('grants 99% trust to validated corporate enterprise domains (cloudflare.com)', () => {
      const text = 'From: hr@cloudflare.com\nSubject: Official Offer';
      const res = inspectDomains(text);

      expect(res.domainTrust.score).toBe(99);
      expect(res.domainTrust.status).toBe('SAFE');
      expect(res.domainRisk).toBe(1);
    });
  });

  describe('Dark Pattern & Psychological Coercion Scanner', () => {
    it('flags artificial urgency deadlines under 48 hours', () => {
      const payload = 'Offer valid for 24 hours only. You must sign before midnight today.';
      const res = scanDarkPatterns(payload);

      expect(res.darkPatternRisk).toBeGreaterThanOrEqual(30);
      expect(res.flaggedClauses.some((c) => c.id === 'dp-artificial-urgency')).toBe(true);
    });

    it('flags recruitment conducted via consumer messaging apps (Telegram / WhatsApp)', () => {
      const payload = 'Following your brief interview via Telegram messenger, you are hired.';
      const res = scanDarkPatterns(payload);

      expect(res.darkPatternRisk).toBeGreaterThanOrEqual(35);
      expect(res.flaggedClauses.some((c) => c.id === 'dp-messenger-interview')).toBe(true);
    });

    it('flags premature high-value identity requests prior to interviews', () => {
      const payload = 'Please submit a color scan of your government photo ID or passport scan for credential onboarding.';
      const res = scanDarkPatterns(payload);

      expect(res.darkPatternRisk).toBeGreaterThanOrEqual(45);
      expect(res.flaggedClauses.some((c) => c.id === 'dp-premature-pii')).toBe(true);
    });
  });

  describe('Composite Scoring Formula & Boundary Calibration', () => {
    it('adheres to exact mathematical weights (45% Fin, 30% Dom, 25% Dark) and bounds', () => {
      // Clean boundary: (0 * 0.45) + (1 * 0.30) + (0 * 0.25) = 0.3 -> rounded to 0
      const cleanResult = calculateThreatAnalysis({
        type: 'text',
        content: 'From: hr@cloudflare.com\nRelocation & WFH equipment provided strictly via Cloudflare Internal Logistics portal. 14 business days to consider.',
      });
      expect(cleanResult.threatIndex).toBeLessThanOrEqual(30);
      expect(cleanResult.verdict).toBe('Clean Offer');

      // Extreme boundary cap: should never exceed 100
      const extremeResult = calculateThreatAnalysis({
        type: 'text',
        content: 'Deposit this electronic check of $5,000 and wire $4,500 via Zelle to bitcoin wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Sign within 24 hours. Contact via Telegram @fake_recruiter from apple-careers-portal.com',
      });
      expect(extremeResult.threatIndex).toBeLessThanOrEqual(100);
      expect(extremeResult.threatIndex).toBeGreaterThanOrEqual(85);
      expect(extremeResult.verdict).toBe('Critical Danger');
    });

    it('supports URL target scan mode seamlessly', () => {
      const resultScamUrl = calculateThreatAnalysis({
        type: 'url',
        content: SAMPLE_URL_SCAM,
      });

      expect(resultScamUrl.threatIndex).toBeGreaterThanOrEqual(30);
      expect(resultScamUrl.domainTrust.score).toBeLessThanOrEqual(40);

      const resultCleanUrl = calculateThreatAnalysis({
        type: 'url',
        content: SAMPLE_URL_CLEAN,
      });
      expect(resultCleanUrl.threatIndex).toBeLessThanOrEqual(30);
      expect(resultCleanUrl.verdict).toBe('Clean Offer');
    });
  });
});
