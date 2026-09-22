import fs from 'node:fs';

// Load from environment or local .env
let envKey = process.env.VITE_GEMINI_API_KEY || process.env.GEMINI_API_KEY || '';
if (!envKey && fs.existsSync('.env')) {
  const envContent = fs.readFileSync('.env', 'utf-8');
  const match = /VITE_GEMINI_API_KEY=([^\r\n]+)/.exec(envContent);
  if (match) envKey = match[1].trim();
}

const API_KEY = envKey;
const MODEL = 'gemini-3.5-flash-lite';

const BLATANT_SCAM_SAMPLE = `Subject: Formal Job Offer: Senior Data Analyst - Remote ($95/hr)
From: recruitment-hr@apple-careers-portal.com
Reply-To: director.apple.hiring@gmail.com

Dear Applicant,

Following your brief interview via Telegram messenger with our HR Director, we are thrilled to offer you the position of Senior Data Analyst. Compensation is set at $95.00/hr paid bi-weekly, with full remote flexibility.

To expedite your home office configuration, our finance department will issue an electronic check of $4,850. You must immediately deposit this check into your bank account and transfer $4,200 via Zelle, CashApp, or wire transfer to our certified Apple hardware vendor within 24 hours to secure equipment dispatch and workstation setup.

Please sign, date, and return this agreement before midnight today to lock in your onboarding slot.`;

const GRAY_ZONE_SAMPLE = `From: recruiter@apex-talentpartners.net
Subject: Contract Opportunity: Technical Writer ($55-65/hr)

Hi Candidate,

We reviewed your profile and believe you are a strong candidate for an immediate 6-month contract role with an enterprise client. The hourly compensation is $60.00/hr on W-2, commission-only performance bonus eligible.

All team communications and initial candidate screening are being handled directly via WhatsApp (+1-555-019-2831).

Prior to client submission, please submit a color scan of your government photo ID (driver's license or passport) and confirm your primary tax residency for credential onboarding.

Kindly confirm interest by end of day, as interviews conclude within 48 hours.`;

const CLEAN_OFFER_SAMPLE = `From: talent-team@cloudflare.com
Subject: Official Cloudflare Offer: Senior Infrastructure Engineer

Dear Candidate,

On behalf of Cloudflare, Inc., we are delighted to offer you the position of Senior Infrastructure Engineer. 

Compensation & Benefits Overview:
- Base Salary: $192,000 annually paid semi-monthly
- Initial Equity Grant: $260,000 RSUs (subject to our standard 4-year vesting schedule)
- Comprehensive Healthcare: Medical, dental, and vision insurance effective on Day 1
- Background Check: Standard employment reference and criminal background check required prior to start
- Equipment: Relocation & WFH equipment provided strictly via Cloudflare Internal Logistics portal upon your official start date

Please review and sign your offer packet hosted securely within DocuSign. We will never ask for banking information via email, SMS, or third-party messaging apps. This offer remains open for review and consideration for 14 business days.`;

async function evaluatePayload(title, text) {
  console.log(`\n================================================================`);
  console.log(`🔍 EVALUATING WITH GEMINI AI: ${title}`);
  console.log(`================================================================`);

  const prompt = `You are a Senior Principal Cybersecurity Forensics Architect.
Analyze this job offer payload for phishing and scams.
Provide a JSON response with:
- threatScore (number 0-100)
- verdict (string)
- confidence (string)
- keyRedFlags (array of strings)
- summaryAnalysis (string)
- actionMandate (string)

Payload:
${text}`;

  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: 'application/json' }
    })
  });

  const data = await res.json();
  if (data.candidates && data.candidates[0]) {
    const parsed = JSON.parse(data.candidates[0].content.parts[0].text);
    console.log(`📊 AI Threat Score : ${parsed.threatScore}%`);
    console.log(`⚖️  AI Verdict      : ${parsed.verdict}`);
    console.log(`🎯 AI Confidence   : ${parsed.confidence}`);
    console.log(`\n🚩 Key Red Flags:`);
    parsed.keyRedFlags.forEach((flag, idx) => console.log(`   [${idx + 1}] ${flag}`));
    console.log(`\n📝 Forensic Summary:\n   ${parsed.summaryAnalysis}`);
    console.log(`\n🛡️  Action Mandate:\n   ${parsed.actionMandate}`);
  } else {
    console.error('API Error:', JSON.stringify(data, null, 2));
  }
}

async function main() {
  console.log('🤖 Initializing Gemini 3.5 AI Scam Forensics Evaluator...');
  console.log(`🔑 Using API Key: ${API_KEY.substring(0, 10)}... (Length: ${API_KEY.length})`);
  console.log(`⚡ Model: ${MODEL}`);

  await evaluatePayload('1. BLATANT SCAM SAMPLE (Advance-Fee Equipment Fraud)', BLATANT_SCAM_SAMPLE);
  await evaluatePayload('2. GRAY ZONE SAMPLE (Premature PII Extraction)', GRAY_ZONE_SAMPLE);
  await evaluatePayload('3. CLEAN OFFER SAMPLE (Verified Enterprise Corporate Offer)', CLEAN_OFFER_SAMPLE);

  console.log('\n================================================================');
  console.log('✅ ALL SAMPLES EVALUATED SUCCESSFULLY WITH GEMINI 3.5 AI');
  console.log('================================================================\n');
}

main().catch(console.error);
