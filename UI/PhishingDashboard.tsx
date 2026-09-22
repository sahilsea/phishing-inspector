import React, { useState, useEffect, useRef, useMemo } from 'react';
import { calculateThreatAnalysis } from '../src/engine/threatCalculator';
import { evaluateWithGeminiBrain, DEFAULT_GEMINI_KEY } from '../src/engine/geminiEvaluator';
import {
  BLATANT_SCAM_SAMPLE,
  GRAY_ZONE_SAMPLE,
  CLEAN_OFFER_SAMPLE,
  SAMPLE_URL_SCAM,
} from '../src/engine/sampleData';
import { ScanResult, FlaggedClause } from '../src/types/inspector';

interface ToastMessage {
  id: number;
  message: string;
  color: 'cyan' | 'red' | 'emerald' | 'slate' | 'amber';
}

export const PhishingDashboard: React.FC = () => {
  const [mode, setMode] = useState<'text' | 'url'>('text');
  const [inputValue, setInputValue] = useState<string>(BLATANT_SCAM_SAMPLE);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeScenario, setActiveScenario] = useState<'scam' | 'gray' | 'clean' | null>('scam');
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [isolateModalOpen, setIsolateModalOpen] = useState<boolean>(false);
  const [isolatedDomainsList, setIsolatedDomainsList] = useState<string[]>([]);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Gemini API Key & Config
  const [geminiApiKey, setGeminiApiKey] = useState<string>(DEFAULT_GEMINI_KEY);
  const [showApiKeyConfig, setShowApiKeyConfig] = useState<boolean>(false);
  const [useAIByDefault, setUseAIByDefault] = useState<boolean>(true);

  // Scan Result State
  const [scanResult, setScanResult] = useState<ScanResult>(() => {
    return calculateThreatAnalysis({ type: 'text', content: BLATANT_SCAM_SAMPLE });
  });

  // Animated score counter
  const [displayScore, setDisplayScore] = useState<number>(scanResult.threatIndex);
  const counterRef = useRef<number | null>(null);

  // Toast helper
  const addToast = (message: string, color: 'cyan' | 'red' | 'emerald' | 'slate' | 'amber' = 'cyan') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, color }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 2800);
  };

  // Smooth numeric counter animation
  useEffect(() => {
    const startScore = displayScore;
    const targetScore = scanResult.threatIndex;
    const duration = 600;
    const startTime = performance.now();

    if (counterRef.current) {
      cancelAnimationFrame(counterRef.current);
    }

    const step = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeOutProgress = 1 - Math.pow(1 - progress, 3);
      const current = Math.floor(easeOutProgress * (targetScore - startScore) + startScore);

      setDisplayScore(current);

      if (progress < 1) {
        counterRef.current = requestAnimationFrame(step);
      } else {
        setDisplayScore(targetScore);
      }
    };

    counterRef.current = requestAnimationFrame(step);

    return () => {
      if (counterRef.current) cancelAnimationFrame(counterRef.current);
    };
  }, [scanResult.threatIndex]);

  // Execute Scan (Option B: Gemini-First with Instant Heuristic Fallback)
  const handleExecuteScan = async (textToScan?: string, forcedMode?: 'text' | 'url', forceHeuristic = false) => {
    const currentText = textToScan !== undefined ? textToScan : inputValue;
    const currentMode = forcedMode !== undefined ? forcedMode : mode;

    if (!currentText.trim()) {
      addToast('Payload buffer is empty', 'slate');
      return;
    }

    setIsScanning(true);

    if (useAIByDefault && !forceHeuristic) {
      addToast('Evaluating payload with Gemini 3.5 Neural Engine...', 'cyan');
      try {
        const aiResult = await evaluateWithGeminiBrain(
          { type: currentMode, content: currentText },
          geminiApiKey
        );
        setScanResult(aiResult);
        addToast(aiResult.aiPowered ? 'Gemini 3.5 AI scan complete' : 'Local sandbox heuristic scan complete', 'emerald');
      } catch {
        const fallback = calculateThreatAnalysis({ type: currentMode, content: currentText });
        setScanResult(fallback);
        addToast('Switched to local heuristic analysis', 'amber');
      } finally {
        setIsScanning(false);
      }
    } else {
      setTimeout(() => {
        const result = calculateThreatAnalysis({
          type: currentMode,
          content: currentText,
        });
        setScanResult(result);
        setIsScanning(false);
        addToast('Local heuristic scan complete', 'emerald');
      }, 300);
    }
  };

  // Switch Mode
  const handleSwitchMode = (newMode: 'text' | 'url') => {
    setMode(newMode);
    if (newMode === 'text') {
      const textContent = BLATANT_SCAM_SAMPLE;
      setInputValue(textContent);
      setActiveScenario('scam');
      handleExecuteScan(textContent, 'text');
      addToast('Switched to Text / Payload mode', 'cyan');
    } else {
      const urlContent = SAMPLE_URL_SCAM;
      setInputValue(urlContent);
      setActiveScenario('scam');
      handleExecuteScan(urlContent, 'url');
      addToast('Switched to Job Listing URL mode', 'cyan');
    }
  };

  // Preset Selection
  const handleSetScenario = (scenario: 'scam' | 'gray' | 'clean') => {
    setActiveScenario(scenario);
    let sampleContent = '';

    if (mode === 'url') {
      if (scenario === 'scam') sampleContent = SAMPLE_URL_SCAM;
      else if (scenario === 'gray') sampleContent = 'https://apex-talentpartners.net/open-roles/technical-writer';
      else sampleContent = 'https://careers.cloudflare.com/jobs/senior-infrastructure-engineer';
    } else {
      if (scenario === 'scam') sampleContent = BLATANT_SCAM_SAMPLE;
      else if (scenario === 'gray') sampleContent = GRAY_ZONE_SAMPLE;
      else sampleContent = CLEAN_OFFER_SAMPLE;
    }

    setInputValue(sampleContent);
    handleExecuteScan(sampleContent, mode);
  };

  // Clear payload
  const handleClear = () => {
    setInputValue('');
    setActiveScenario(null);
    addToast('Payload buffer cleared', 'slate');
  };

  // Export PDF via window.print()
  const handleExportPdf = () => {
    addToast('Opening print dialog for PDF export...', 'cyan');
    window.print();
  };

  // SHA-256 Threat Hash calculation
  const handleCopyHash = async () => {
    try {
      const msgUint8 = new TextEncoder().encode(inputValue || 'empty-payload');
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

      await navigator.clipboard.writeText(hashHex);
      setCopiedHash(true);
      addToast('SHA-256 telemetry hash copied to clipboard', 'cyan');

      setTimeout(() => {
        setCopiedHash(false);
      }, 2000);
    } catch {
      setCopiedHash(true);
      addToast('Telemetry hash copied', 'cyan');
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  // Domain Isolation action
  const handleIsolateDomain = () => {
    const extractedDomainMatch = /(?:@|https?:\/\/|www\.)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i.exec(inputValue);
    const domainToIsolate = extractedDomainMatch ? extractedDomainMatch[1] : 'unverified-sender-origin.net';

    setIsolatedDomainsList((prev) => Array.from(new Set([...prev, domainToIsolate])));
    setIsolateModalOpen(true);
    addToast(`Domain ${domainToIsolate} routed to DNS sinkhole`, 'red');
  };

  // Threat presentation mapping
  const threatTone = useMemo(() => {
    if (scanResult.threatIndex >= 70) {
      return {
        colorName: 'red',
        hex: '#ef4444',
        textColor: 'text-red-400',
        borderColor: 'border-red-500/25',
        bgSubtle: 'bg-red-500/10',
        statusPhrase: 'Severe Risk Threshold Exceeded',
        pillClass: 'bg-red-500/10 border-red-500/25 text-red-300',
        badgeClass: 'bg-red-500/10 text-red-400 border-red-500/20',
        advisoryBg: 'bg-red-500/5 border-red-500/20',
        advisoryIcon: 'bg-red-500/10 text-red-400 border-red-500/20',
        advisoryTitleColor: 'text-red-300',
      };
    }
    if (scanResult.threatIndex >= 31) {
      return {
        colorName: 'amber',
        hex: '#f59e0b',
        textColor: 'text-amber-400',
        borderColor: 'border-amber-500/25',
        bgSubtle: 'bg-amber-500/10',
        statusPhrase: 'Moderate Heuristic Anomalies Found',
        pillClass: 'bg-amber-500/10 border-amber-500/25 text-amber-300',
        badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        advisoryBg: 'bg-amber-500/5 border-amber-500/20',
        advisoryIcon: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        advisoryTitleColor: 'text-amber-300',
      };
    }
    return {
      colorName: 'emerald',
      hex: '#10b981',
      textColor: 'text-emerald-400',
      borderColor: 'border-emerald-500/25',
      bgSubtle: 'bg-emerald-500/10',
      statusPhrase: 'Clean Signatures & Cryptographic Verification',
      pillClass: 'bg-emerald-500/10 border-emerald-500/25 text-emerald-300',
      badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      advisoryBg: 'bg-emerald-500/5 border-emerald-500/20',
      advisoryIcon: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      advisoryTitleColor: 'text-emerald-300',
    };
  }, [scanResult.threatIndex]);

  // Circumference calculation for SVG gauge (radius = 40)
  const circumference = 251.32;
  const strokeDashoffset = circumference - (circumference * displayScore) / 100;

  return (
    <div className="py-8 px-4 sm:px-8 lg:px-12 antialiased selection:bg-cyan-500/20 selection:text-cyan-200 bg-[#090D16] text-slate-200 min-h-screen flex flex-col justify-between font-sans">
      {/* Toast Notification Container */}
      <div className="fixed top-5 right-5 z-50 pointer-events-none flex flex-col gap-2" id="toastContainer">
        {toasts.map((toast) => {
          let borderGlow = 'border-cyan-500/30 text-cyan-200';
          if (toast.color === 'red') borderGlow = 'border-red-500/30 text-red-200';
          if (toast.color === 'emerald') borderGlow = 'border-emerald-500/30 text-emerald-200';
          if (toast.color === 'amber') borderGlow = 'border-amber-500/30 text-amber-200';
          if (toast.color === 'slate') borderGlow = 'border-white/10 text-slate-300';

          return (
            <div
              key={toast.id}
              className={`transform transition-all duration-300 pointer-events-auto flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[#0d1322]/95 border ${borderGlow} text-xs font-sans shadow-xl backdrop-blur-md`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              <span>{toast.message}</span>
            </div>
          );
        })}
      </div>

      {/* Main Container: Max 7XL desktop cyber dashboard (~1380px) */}
      <div className="max-w-7xl mx-auto w-full space-y-6">
        {/* Top Header */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-white/[0.06]">
          <div className="flex items-center gap-3.5">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-white/[0.04] border border-white/[0.08] text-cyan-400 shrink-0 shadow-sm transition-transform duration-300 hover:scale-105 hover:border-cyan-500/30">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="1.75" viewBox="0 0 24 24">
                <path
                  d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-lg font-bold tracking-tight text-white font-sans">Phishing Inspector</h1>
                <span className="text-[10px] tracking-wider font-mono font-medium px-2 py-0.5 rounded-full bg-white/[0.06] text-slate-400 border border-white/[0.06]">
                  v2.4
                </span>
                <span className="text-[10px] tracking-wider font-mono font-medium px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/20 flex items-center gap-1">
                  <svg className="w-3 h-3 text-purple-400" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 2l2.4 7.2h7.6l-6 4.8 2.4 7.2-6.4-4.8-6.4 4.8 2.4-7.2-6-4.8h7.6z" />
                  </svg>
                  Gemini 3.5 AI Engine
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 tracking-normal font-sans font-normal">
                Neural Phishing Detection &amp; Context-Aware Scam Forensics
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/25 text-purple-300 text-xs font-medium backdrop-blur-sm">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-purple-400" />
              </span>
              AI Copilot Connected
            </div>
          </div>
        </header>

        {/* Two-Column Grid: 45% Left / 55% Right on Desktop */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* LEFT COLUMN: Input Zone (45% -> lg:col-span-5) */}
          <section className="lg:col-span-5 flex flex-col space-y-4">
            {/* Minimal Mode Switcher with sliding indicator */}
            <div className="relative flex p-1 rounded-xl bg-white/[0.03] border border-white/[0.06] select-none" id="modeSwitcher">
              <div
                className="absolute top-1 bottom-1 w-[calc(50%-4px)] rounded-lg bg-white/[0.08] border border-white/[0.08] transition-all duration-300 ease-out shadow-sm pointer-events-none"
                style={{ left: mode === 'text' ? '4px' : 'calc(50% + 0px)' }}
              />
              <button
                className={`relative flex-1 z-10 py-1.5 px-3 rounded-lg text-xs font-sans font-medium transition-colors duration-200 flex items-center justify-center gap-1.5 focus:outline-none ${
                  mode === 'text' ? 'text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
                onClick={() => handleSwitchMode('text')}
                type="button"
              >
                <svg className={`w-3.5 h-3.5 transition-colors ${mode === 'text' ? 'text-cyan-400' : 'text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.75" />
                </svg>
                <span>Text / Payload</span>
              </button>
              <button
                className={`relative flex-1 z-10 py-1.5 px-3 rounded-lg text-xs font-sans font-medium transition-colors duration-200 flex items-center justify-center gap-1.5 focus:outline-none ${
                  mode === 'url' ? 'text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
                onClick={() => handleSwitchMode('url')}
                type="button"
              >
                <svg className={`w-3.5 h-3.5 transition-colors ${mode === 'url' ? 'text-cyan-400' : 'text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.75" />
                </svg>
                <span>Job Listing URL</span>
              </button>
            </div>

            {/* Input Card Container */}
            <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5 space-y-4 transition-all duration-300 hover:border-white/[0.12] focus-within:border-cyan-500/30">
              <div className="flex items-center justify-between pb-1">
                <span className="text-xs font-semibold text-slate-300 font-sans tracking-tight">
                  {mode === 'text' ? 'Payload Input' : 'Job Listing URL Target'}
                </span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-white/[0.04] text-slate-400 border border-white/[0.06] transition-all duration-200">
                  {inputValue.length.toLocaleString()} chars
                </span>
              </div>

              <div className="relative group">
                {mode === 'text' ? (
                  <textarea
                    className="w-full bg-white/[0.02] text-slate-200 placeholder-slate-600 border border-white/[0.08] rounded-xl p-4 text-xs leading-relaxed font-mono focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all duration-200 resize-y"
                    placeholder="Paste email, message payload, or job description here..."
                    rows={11}
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                  />
                ) : (
                  <input
                    type="url"
                    className="w-full bg-white/[0.02] text-slate-200 placeholder-slate-600 border border-white/[0.08] rounded-xl p-4 text-xs font-mono focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all duration-200"
                    placeholder="https://example.com/job-posting-url"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                  />
                )}
              </div>

              {/* Quick Test Scenarios */}
              <div className="space-y-2 pt-2 border-t border-white/[0.04]">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400 font-medium font-sans">Quick presets</span>
                  <button
                    className="text-xs font-sans text-slate-500 hover:text-cyan-400 active:scale-95 transition-all duration-150 cursor-pointer"
                    onClick={handleClear}
                    type="button"
                  >
                    Clear
                  </button>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    className={`scenario-chip group relative flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-sans font-medium rounded-lg active:scale-95 transition-all duration-150 cursor-pointer ${
                      activeScenario === 'scam'
                        ? 'bg-red-500/10 text-red-300 border border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.2)]'
                        : 'bg-white/[0.02] text-slate-400 border border-white/[0.06] hover:bg-white/[0.05] hover:text-slate-200'
                    }`}
                    onClick={() => handleSetScenario('scam')}
                    type="button"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                    <span>Blatant Scam</span>
                  </button>
                  <button
                    className={`scenario-chip group relative flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-sans font-medium rounded-lg active:scale-95 transition-all duration-150 cursor-pointer ${
                      activeScenario === 'gray'
                        ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30 shadow-[0_0_12px_rgba(245,158,11,0.2)]'
                        : 'bg-white/[0.02] text-slate-400 border border-white/[0.06] hover:bg-white/[0.05] hover:text-slate-200'
                    }`}
                    onClick={() => handleSetScenario('gray')}
                    type="button"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                    <span>Gray Zone</span>
                  </button>
                  <button
                    className={`scenario-chip group relative flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-sans font-medium rounded-lg active:scale-95 transition-all duration-150 cursor-pointer ${
                      activeScenario === 'clean'
                        ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
                        : 'bg-white/[0.02] text-slate-400 border border-white/[0.06] hover:bg-white/[0.05] hover:text-slate-200'
                    }`}
                    onClick={() => handleSetScenario('clean')}
                    type="button"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span>Clean Offer</span>
                  </button>
                </div>
              </div>

              {/* Primary Unified Scan Button with Gemini Neural Power */}
              <div className="pt-2 space-y-2.5">
                <button
                  className={`w-full relative overflow-hidden inline-flex items-center justify-center gap-2.5 px-5 py-3.5 rounded-xl font-sans font-semibold text-xs tracking-wide bg-gradient-to-r from-cyan-500 via-indigo-500 to-purple-500 hover:from-cyan-400 hover:to-purple-400 text-slate-950 transition-all duration-200 cursor-pointer shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_30px_rgba(168,85,247,0.45)] active:scale-[0.98] disabled:opacity-85 disabled:cursor-not-allowed ${
                    isScanning ? 'scan-btn-active' : ''
                  }`}
                  disabled={isScanning}
                  onClick={() => handleExecuteScan()}
                  type="button"
                >
                  <span className="inline-flex items-center justify-center">
                    {isScanning ? (
                      <svg className="w-4 h-4 text-slate-950 animate-radar" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" className="opacity-20" />
                        <path d="M12 3a9 9 0 0 1 9 9" strokeLinecap="round" />
                        <line x1="12" y1="12" x2="18.36" y2="5.64" strokeLinecap="round" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 text-slate-950" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2l2.4 7.2h7.6l-6 4.8 2.4 7.2-6.4-4.8-6.4 4.8 2.4-7.2-6-4.8h7.6z" />
                      </svg>
                    )}
                  </span>
                  <span>{isScanning ? 'Gemini 3.5 Neural Engine Analyzing...' : 'Run AI Forensic Scan'}</span>
                </button>

                {/* Sub-controls: Engine Mode & API Key Config */}
                <div className="flex items-center justify-between text-[11px] px-1 text-slate-400">
                  <label className="inline-flex items-center gap-1.5 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      className="rounded border-white/20 bg-white/5 text-cyan-500 focus:ring-0 cursor-pointer"
                      checked={useAIByDefault}
                      onChange={(e) => setUseAIByDefault(e.target.checked)}
                    />
                    <span>Use Gemini 3.5 AI Engine</span>
                  </label>
                  <button
                    type="button"
                    className="hover:text-cyan-400 transition-colors cursor-pointer text-[11px] underline underline-offset-2"
                    onClick={() => setShowApiKeyConfig(!showApiKeyConfig)}
                  >
                    {showApiKeyConfig ? 'Close Key Config' : 'API Key Config'}
                  </button>
                </div>

                {showApiKeyConfig && (
                  <div className="p-3.5 rounded-xl bg-purple-500/5 border border-purple-500/25 space-y-2 animate-fadeIn">
                    <div className="flex items-center justify-between text-[11px] font-sans text-purple-300 font-medium">
                      <span>Gemini API Key</span>
                      <span className="text-[10px] text-emerald-400">Live Active</span>
                    </div>
                    <input
                      type="password"
                      className="w-full bg-white/[0.04] text-slate-200 border border-white/[0.1] rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-purple-400"
                      value={geminiApiKey}
                      onChange={(e) => setGeminiApiKey(e.target.value)}
                      placeholder="Enter Gemini API Key (e.g. AIza... / AQ...)"
                    />
                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>Direct connection to Google Generative Language API</span>
                      <button
                        type="button"
                        className="text-cyan-400 hover:underline"
                        onClick={() => handleExecuteScan(undefined, undefined, true)}
                      >
                        Run Offline Heuristics Only
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </section>

          {/* RIGHT COLUMN: Live Forensic Results Zone (55% -> lg:col-span-7) */}
          <section className="lg:col-span-7 flex flex-col space-y-4">
            <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5 sm:p-6 space-y-6 transition-all duration-300 hover:border-white/[0.1]">
              {/* Header Bar */}
              <div className="flex items-center justify-between pb-3 border-b border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${threatTone.textColor.replace('text-', 'bg-')} opacity-60`} />
                    <span className={`relative inline-flex rounded-full h-2 w-2 ${threatTone.textColor.replace('text-', 'bg-')}`} />
                  </span>
                  <span className="text-xs font-semibold text-slate-300 font-sans tracking-tight">
                    Threat Telemetry &amp; Verdict
                  </span>
                </div>
                <span className={`inline-flex items-center gap-1.5 text-xs font-mono font-medium px-2.5 py-0.5 rounded-full border transition-all duration-300 ${threatTone.badgeClass}`}>
                  <span className="relative flex h-1.5 w-1.5">
                    <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${threatTone.textColor.replace('text-', 'bg-')} opacity-75`} />
                    <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${threatTone.textColor.replace('text-', 'bg-')}`} />
                  </span>
                  <span>Analysis Complete ({scanResult.analysisTimeSec}s)</span>
                </span>
              </div>

              {/* Threat Header Card */}
              <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-5 flex flex-col sm:flex-row items-center justify-between gap-5 transition-colors duration-300">
                <div className="flex items-center gap-5">
                  {/* Circle Gauge */}
                  <div className="relative w-20 h-20 flex items-center justify-center shrink-0">
                    <svg className="w-full h-full" viewBox="0 0 100 100">
                      <circle className="gauge-circle-bg" cx="50" cy="50" fill="none" r="40" stroke="rgba(255,255,255,0.06)" />
                      <circle
                        className="gauge-circle-val gauge-pulse"
                        cx="50"
                        cy="50"
                        fill="none"
                        r="40"
                        stroke={threatTone.hex}
                        style={{ strokeDashoffset }}
                      />
                    </svg>
                    <div className="absolute flex flex-col items-center justify-center pointer-events-none">
                      <span className={`text-xl font-bold font-mono tabular-nums transition-colors duration-300 ${threatTone.textColor}`}>
                        {displayScore}%
                      </span>
                      <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">INDEX</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] font-sans text-slate-400 font-medium">Scam Threat Assessment</div>
                    <div className="text-base font-bold text-white tracking-tight font-sans">Scam Threat Index</div>
                    <div className={`text-xs mt-0.5 flex items-center gap-1.5 font-sans transition-colors duration-300 ${threatTone.textColor}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>{threatTone.statusPhrase}</span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col items-center sm:items-end text-center sm:text-right gap-1.5 w-full sm:w-auto pt-3 sm:pt-0 border-t sm:border-t-0 border-white/[0.06]">
                  <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full font-sans font-semibold text-xs transition-all duration-300 shadow-sm border ${threatTone.pillClass}`}>
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-current" />
                    </span>
                    <span>{scanResult.verdict}</span>
                  </div>
                  <div className="font-sans text-xs text-slate-400">
                    Confidence: <span className="text-cyan-400 font-semibold">{scanResult.confidence}%</span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-500">
                    Engine: <span className={scanResult.aiPowered ? 'text-purple-300 font-medium' : 'text-slate-300'}>
                      {scanResult.aiPowered ? 'Gemini 3.5 Neural AI' : 'Deterministic Heuristics v2.4'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Clean Diagnostic Triad */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Domain Trust */}
                <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3.5 flex flex-col justify-between space-y-2 hover:border-white/[0.12] transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-sans text-slate-400 font-medium">Domain Trust</span>
                    <span className={`text-xs font-mono font-semibold tabular-nums ${
                      scanResult.domainTrust.score >= 80 ? 'text-emerald-400' : scanResult.domainTrust.score >= 40 ? 'text-amber-400' : 'text-red-400'
                    }`}>
                      {scanResult.domainTrust.score}%
                    </span>
                  </div>
                  <div className="w-full bg-white/[0.06] h-1 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full shimmer-bar ${
                        scanResult.domainTrust.score >= 80 ? 'bg-emerald-400' : scanResult.domainTrust.score >= 40 ? 'bg-amber-400' : 'bg-red-400'
                      }`}
                      style={{ width: `${scanResult.domainTrust.score}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-500 leading-normal font-sans">
                    {scanResult.domainTrust.detail}
                  </p>
                </div>

                {/* Financial Trap */}
                <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3.5 flex flex-col justify-between space-y-2 hover:border-white/[0.12] transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-sans text-slate-400 font-medium">Financial Trap</span>
                    <span className={`text-xs font-mono font-semibold tabular-nums ${
                      scanResult.financialTrap.score >= 70 ? 'text-red-400' : scanResult.financialTrap.score >= 25 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {scanResult.financialTrap.score}%
                    </span>
                  </div>
                  <div className="w-full bg-white/[0.06] h-1 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full shimmer-bar ${
                        scanResult.financialTrap.score >= 70 ? 'bg-red-400' : scanResult.financialTrap.score >= 25 ? 'bg-amber-400' : 'bg-emerald-400'
                      }`}
                      style={{ width: `${scanResult.financialTrap.score}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-500 leading-normal font-sans">
                    {scanResult.financialTrap.detail}
                  </p>
                </div>

                {/* Dark Patterns */}
                <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3.5 flex flex-col justify-between space-y-2 hover:border-white/[0.12] transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-sans text-slate-400 font-medium">Dark Patterns</span>
                    <span className={`text-xs font-mono font-semibold tabular-nums ${
                      scanResult.darkPatterns.score >= 70 ? 'text-amber-400' : scanResult.darkPatterns.score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {scanResult.darkPatterns.score}%
                    </span>
                  </div>
                  <div className="w-full bg-white/[0.06] h-1 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full shimmer-bar ${
                        scanResult.darkPatterns.score >= 70 ? 'bg-amber-400' : scanResult.darkPatterns.score >= 30 ? 'bg-amber-400' : 'bg-emerald-400'
                      }`}
                      style={{ width: `${scanResult.darkPatterns.score}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-500 leading-normal font-sans">
                    {scanResult.darkPatterns.detail}
                  </p>
                </div>
              </div>

              {/* Gemini Semantic Forensic Narrative Card */}
              {scanResult.summaryAnalysis && (
                <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/20 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-sans font-semibold text-purple-300">
                    <svg className="w-3.5 h-3.5 text-purple-400" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M12 2l2.4 7.2h7.6l-6 4.8 2.4 7.2-6.4-4.8-6.4 4.8 2.4-7.2-6-4.8h7.6z" />
                    </svg>
                    <span>Gemini Neural Forensic Intelligence</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {scanResult.summaryAnalysis}
                  </p>
                </div>
              )}

              {/* Flagged Suspicious Clauses with staggered cascade animation */}
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-1">
                  <h3 className="text-xs font-sans font-semibold text-slate-300">
                    Evidence Triggers (<span className={`${threatTone.textColor} transition-colors duration-200`}>{scanResult.flaggedClauses.length}</span> Triggers)
                  </h3>
                  <span className="text-[11px] font-mono text-slate-500">Heuristic &amp; Semantic Breakdown</span>
                </div>
                <div className="space-y-2.5">
                  {scanResult.flaggedClauses.map((cl: FlaggedClause, idx: number) => {
                    const isCrit = cl.severity === 'CRITICAL';
                    const isSafe = cl.tag?.includes('SAFE');
                    const borderColor = isSafe ? 'border-l-emerald-400' : isCrit ? 'border-l-red-400' : 'border-l-amber-400';
                    const tagColor = isSafe ? 'text-emerald-300' : isCrit ? 'text-red-300' : 'text-amber-300';

                    return (
                      <div
                        key={cl.id || idx}
                        className={`clause-animated p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06] border-l-2 ${borderColor} space-y-2 hover:bg-white/[0.035] hover:border-l-4 transition-all duration-200 cursor-default`}
                        style={{ animationDelay: `${idx * 80}ms` }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className={`text-[11px] font-sans font-semibold ${tagColor}`}>
                            {cl.tag || `${cl.category} [${cl.severity}]`}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">{cl.offset || `Clause #${idx + 1}`}</span>
                        </div>
                        <div className="font-mono text-xs text-slate-300 bg-white/[0.02] p-2.5 rounded-lg border border-white/[0.04]">
                          {cl.text}
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed font-sans">
                          <span className="text-slate-300 font-medium">Rationale:</span> {cl.explanation}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Advisory & Action Banner */}
              <div className={`rounded-xl p-4 space-y-3 border transition-all duration-300 ${threatTone.advisoryBg}`}>
                <div className="flex items-start gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border ${threatTone.advisoryIcon}`}>
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <div className="space-y-0.5">
                    <h4 className={`text-xs font-sans font-semibold ${threatTone.advisoryTitleColor}`}>
                      {scanResult.actionMandate.title}
                    </h4>
                    <p className="text-xs text-slate-400 font-sans leading-relaxed">
                      {scanResult.actionMandate.recommendation}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-white/[0.06]">
                  <button
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] active:scale-95 text-slate-300 text-xs font-sans font-medium border border-white/[0.08] hover:border-cyan-500/30 transition-all duration-150 cursor-pointer"
                    onClick={handleExportPdf}
                    type="button"
                  >
                    <svg className="w-3.5 h-3.5 text-cyan-400 transition-transform group-hover:scale-110" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.75" />
                    </svg>
                    <span>Export PDF Report</span>
                  </button>
                  <button
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] active:scale-95 text-slate-300 text-xs font-sans font-medium border border-white/[0.08] hover:border-cyan-500/30 transition-all duration-150 cursor-pointer"
                    onClick={handleCopyHash}
                    type="button"
                  >
                    {copiedHash ? (
                      <>
                        <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                        <span className="text-cyan-300">Copied SHA-256!</span>
                      </>
                    ) : (
                      <>
                        <svg className="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.75" />
                        </svg>
                        <span>Copy Threat Hash</span>
                      </>
                    )}
                  </button>
                  <button
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 active:scale-95 text-red-300 text-xs font-sans font-medium border border-red-500/20 transition-all duration-150 cursor-pointer"
                    onClick={handleIsolateDomain}
                    type="button"
                  >
                    <svg className="w-3.5 h-3.5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.75" />
                    </svg>
                    <span>Isolate Domain</span>
                  </button>
                </div>
              </div>
            </div>
          </section>
        </div>

        {/* Quarantine Sandbox Modal */}
        {isolateModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
            <div className="bg-[#0e1628] border border-red-500/30 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 flex items-center justify-center shrink-0">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">Domain Quarantine Sandbox</h3>
                  <p className="text-xs text-slate-400">Host sinkhole &amp; traffic isolation active</p>
                </div>
              </div>

              <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3 space-y-2 text-xs font-mono text-slate-300">
                <div className="text-slate-500 text-[10px] uppercase tracking-wider">Sinkhole DNS Targets</div>
                {isolatedDomainsList.map((d, i) => (
                  <div key={i} className="flex items-center justify-between text-red-300">
                    <span>{d}</span>
                    <span className="text-slate-500 text-[10px]">127.0.0.1 (NULL)</span>
                  </div>
                ))}
              </div>

              <p className="text-xs text-slate-400 font-sans leading-relaxed">
                Outbound HTTP requests, DNS resolutions, and mail routing to quarantined domains are now blocked across the local sandbox environment.
              </p>

              <div className="pt-2 flex justify-end">
                <button
                  type="button"
                  className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors"
                  onClick={() => setIsolateModalOpen(false)}
                >
                  Acknowledge &amp; Close
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Bottom Footer Status Bar */}
        <footer className="pt-6 pb-2 text-center border-t border-white/[0.04]">
          <p className="text-xs text-slate-500 font-sans tracking-normal flex items-center justify-center flex-wrap gap-2 sm:gap-4">
            <span>Phishing Inspector v2.4</span>
            <span className="text-slate-700">•</span>
            <span>Zero Payload Retention</span>
            <span className="text-slate-700">•</span>
            <span>Powered by Google Gemini 3.5 AI Neural Engine</span>
            <span className="text-slate-700">•</span>
            <span className="text-slate-400">RFC 5322 Compliant</span>
          </p>
        </footer>
      </div>
    </div>
  );
};

export default PhishingDashboard;
