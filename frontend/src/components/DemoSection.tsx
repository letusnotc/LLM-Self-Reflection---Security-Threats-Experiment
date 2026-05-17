"use client";
import { useState, useRef, useEffect } from "react";

const MODEL_OPTIONS = [
  { id: "gemini-2.5-flash-lite",                              label: "Gemini 2.5 Flash-Lite",   provider: "Google" },
  { id: "gemini-2.5-flash",                                   label: "Gemini 2.5 Flash",         provider: "Google" },
  { id: "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free", label: "Nemotron 30B Reasoning",  provider: "OpenRouter · free" },
  { id: "nvidia/nemotron-3-super-120b-a12b:free",             label: "Nemotron 120B Super",      provider: "OpenRouter · free" },
  { id: "google/gemma-4-31b-it:free",                         label: "Gemma 4 31B",              provider: "OpenRouter · free" },
];

const SAMPLE_EMAIL = `Subject: Urgent: Your PayPal account has been limited
From: security@paypa1-support.com
To: user@example.com

Dear Valued Customer,

We have detected unusual activity on your PayPal account and it has been temporarily limited.

To restore full access, you must verify your identity immediately:
→ Click here: http://paypal-secure-verify.tk/confirm?token=8x92k

Failure to verify within 24 hours will result in permanent account suspension and loss of funds.

PayPal Security Team
© PayPal Inc. 2024`;

type LogEntry = {
  id: number;
  level: string;
  message: string;
  type: "thinking" | "result" | "round" | "error" | "done";
};

type LevelCard = {
  label: string;
  confidence: number;
  reasoning: string;
  extra: string;
  model: string;
  tokens: { input_tokens: number; output_tokens: number; cost_usd: number } | null;
  status: "idle" | "thinking" | "done";
  changed?: boolean;
  rounds_taken?: number;
};

type CostBreakdown = {
  level: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
};

type CostSummary = {
  total_cost_usd: number;
  total_input_tokens: number;
  total_output_tokens: number;
  breakdown: CostBreakdown[];
};

const EMPTY_CARD: LevelCard = {
  label: "", confidence: 0, reasoning: "", extra: "",
  model: "", tokens: null, status: "idle",
};

export default function DemoSection() {
  const [input, setInput] = useState(SAMPLE_EMAIL);
  const [l0Model, setL0Model] = useState("gemini-2.5-flash-lite");
  const [l1Model, setL1Model] = useState("gemini-2.5-flash");
  const [l2Model, setL2Model] = useState("gemini-2.5-flash");
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [l0, setL0] = useState<LevelCard>(EMPTY_CARD);
  const [l1, setL1] = useState<LevelCard>(EMPTY_CARD);
  const [l2, setL2] = useState<LevelCard>(EMPTY_CARD);
  const [cost, setCost] = useState<CostSummary | null>(null);
  const [timings, setTimings] = useState<{ L0: number | null; L1: number | null; L2: number | null }>({ L0: null, L1: null, L2: null });
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const logId = useRef(0);
  const startTimes = useRef<{ L0: number; L1: number; L2: number }>({ L0: 0, L1: 0, L2: 0 });

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [log]);

  const addLog = (level: string, message: string, type: LogEntry["type"]) => {
    setLog(prev => [...prev, { id: logId.current++, level, message, type }]);
  };

  const reset = () => {
    setLog([]);
    setL0(EMPTY_CARD);
    setL1(EMPTY_CARD);
    setL2(EMPTY_CARD);
    setCost(null);
    setTimings({ L0: null, L1: null, L2: null });
    setExpandedCard(null);
    logId.current = 0;
  };

  const analyze = async () => {
    if (!input.trim() || running) return;
    reset();
    setRunning(true);

    try {
      const response = await fetch("http://localhost:8000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input, l0_model: l0Model, l1_model: l1Model, l2_model: l2Model }),
      });

      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            handleEvent(ev);
          } catch {}
        }
      }
    } catch (e: unknown) {
      addLog("ERR", e instanceof Error ? e.message : "Connection failed", "error");
    } finally {
      setRunning(false);
    }
  };

  const handleEvent = (ev: Record<string, unknown>) => {
    switch (ev.event) {
      case "l0_thinking":
        startTimes.current.L0 = Date.now();
        addLog("L0", `Analyzing with ${ev.message ?? "..."}`, "thinking");
        setL0(prev => ({ ...prev, status: "thinking" }));
        break;
      case "l0_result":
        setTimings(prev => ({ ...prev, L0: Date.now() - startTimes.current.L0 }));
        addLog("L0", `${ev.label} — ${Math.round((ev.confidence as number) * 100)}% confidence`, "result");
        setL0({
          label: ev.label as string,
          confidence: ev.confidence as number,
          reasoning: ev.reasoning as string,
          extra: `Indicators: ${(ev.indicators as string[]).join(", ")}`,
          model: ev.model as string,
          tokens: ev.tokens as LevelCard["tokens"],
          status: "done",
        });
        break;
      case "l1_thinking":
        startTimes.current.L1 = Date.now();
        addLog("L1", "Critiquing L0 analysis...", "thinking");
        setL1(prev => ({ ...prev, status: "thinking" }));
        break;
      case "l1_result":
        setTimings(prev => ({ ...prev, L1: Date.now() - startTimes.current.L1 }));
        addLog("L1",
          `${ev.label} — ${Math.round((ev.confidence as number) * 100)}% confidence${ev.changed ? " (changed)" : " (confirmed)"}`,
          "result"
        );
        setL1({
          label: ev.label as string,
          confidence: ev.confidence as number,
          reasoning: ev.revised_reasoning as string,
          extra: ev.critique as string,
          model: ev.model as string,
          tokens: ev.tokens as LevelCard["tokens"],
          status: "done",
          changed: ev.changed as boolean,
        });
        break;
      case "l2_thinking":
        startTimes.current.L2 = Date.now();
        addLog("L2", "Starting consensus loop...", "thinking");
        setL2(prev => ({ ...prev, status: "thinking" }));
        break;
      case "l2_round":
        addLog("L2",
          `Round ${ev.round} — ${Math.round((ev.confidence as number) * 100)}% — ${ev.agreed ? "✓ agreed" : "iterating..."}`,
          "round"
        );
        break;
      case "l2_result":
        setTimings(prev => ({ ...prev, L2: Date.now() - startTimes.current.L2 }));
        addLog("L2",
          `Final: ${ev.label} — ${Math.round((ev.confidence as number) * 100)}% (${ev.rounds_taken} round${(ev.rounds_taken as number) > 1 ? "s" : ""})`,
          "result"
        );
        setL2(prev => ({
          ...prev,
          label: ev.label as string,
          confidence: ev.confidence as number,
          model: ev.model as string,
          tokens: ev.tokens as LevelCard["tokens"],
          status: "done",
          rounds_taken: ev.rounds_taken as number,
        }));
        break;
      case "cost_summary":
        setCost({
          total_cost_usd: ev.total_cost_usd as number,
          total_input_tokens: ev.total_input_tokens as number,
          total_output_tokens: ev.total_output_tokens as number,
          breakdown: ev.breakdown as CostBreakdown[],
        });
        break;
      case "done":
        addLog("✓", "Analysis complete", "done");
        break;
      case "error":
        addLog("ERR", ev.message as string, "error");
        break;
    }
  };

  const labelColor = (label: string) =>
    label === "Phishing" ? "text-red-600" : label === "Legitimate" ? "text-green-600" : "text-stone-400";

  const levelCards = [
    { key: "L0", title: "No Reflection", data: l0 },
    { key: "L1", title: "Self-Critique", data: l1 },
    { key: "L2", title: "Consensus Loop", data: l2 },
  ];

  return (
    <section id="demo" className="py-28 px-6 bg-white">
      <div className="max-w-7xl mx-auto">

        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-block px-3 py-1 bg-stone-100 text-stone-500 text-xs font-medium rounded-full mb-4 tracking-widest uppercase">
            Live Demo
          </span>
          <h2 className="font-serif text-5xl lg:text-6xl font-bold text-stone-800 mt-4">
            Try It Yourself.
          </h2>
          <p className="mt-5 text-stone-500 max-w-lg mx-auto text-lg leading-relaxed">
            Paste an email and watch the self-reflection chain reason through it level by level.
          </p>
        </div>

        {/* ── Top row: input panel + monitor (stretch to same height) ── */}
        <div className="flex gap-10 items-stretch">

          {/* Input panel */}
          <div className="flex-1 flex flex-col gap-5">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-semibold text-stone-700">Email Input</label>
                <div className="flex items-center gap-4">
                  <button
                    onClick={() => setInput(SAMPLE_EMAIL)}
                    className="text-xs text-orange-500 hover:text-orange-600 transition-colors"
                  >
                    Load sample phishing email
                  </button>
                  <button
                    onClick={analyze}
                    disabled={running || !input.trim()}
                    className="px-6 py-2 bg-orange-500 hover:bg-orange-600 disabled:bg-stone-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-colors"
                  >
                    {running ? "Analyzing..." : "Analyze →"}
                  </button>
                </div>
              </div>
              <textarea
                value={input}
                onChange={e => setInput(e.target.value)}
                rows={14}
                className="w-full bg-stone-50 border border-stone-300 rounded-xl px-4 py-3 text-sm text-stone-700 font-mono resize-none focus:outline-none focus:border-orange-400 focus:ring-2 focus:ring-orange-100 transition-all"
                placeholder="Paste an email here..."
              />
            </div>

            {/* Model selectors */}
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-sm font-semibold text-stone-600 mb-2">L0 — Baseline</p>
                <select
                  value={l0Model}
                  onChange={e => setL0Model(e.target.value)}
                  disabled={running}
                  className="w-full bg-white border-2 border-stone-300 rounded-lg px-3 py-2.5 text-sm text-stone-800 focus:outline-none focus:border-orange-400 disabled:opacity-50 transition-colors"
                >
                  {MODEL_OPTIONS.map(m => (
                    <option key={m.id} value={m.id}>{m.label} · {m.provider}</option>
                  ))}
                </select>
              </div>
              <div>
                <p className="text-sm font-semibold text-stone-600 mb-2">L1 — Self-Critique</p>
                <select
                  value={l1Model}
                  onChange={e => setL1Model(e.target.value)}
                  disabled={running}
                  className="w-full bg-white border-2 border-stone-300 rounded-lg px-3 py-2.5 text-sm text-stone-800 focus:outline-none focus:border-orange-400 disabled:opacity-50 transition-colors"
                >
                  {MODEL_OPTIONS.map(m => (
                    <option key={m.id} value={m.id}>{m.label} · {m.provider}</option>
                  ))}
                </select>
              </div>
              <div>
                <p className="text-sm font-semibold text-stone-600 mb-2">L2 — Consensus</p>
                <select
                  value={l2Model}
                  onChange={e => setL2Model(e.target.value)}
                  disabled={running}
                  className="w-full bg-white border-2 border-stone-300 rounded-lg px-3 py-2.5 text-sm text-stone-800 focus:outline-none focus:border-orange-400 disabled:opacity-50 transition-colors"
                >
                  {MODEL_OPTIONS.map(m => (
                    <option key={m.id} value={m.id}>{m.label} · {m.provider}</option>
                  ))}
                </select>
              </div>
            </div>

          </div>

          {/* Monitor — stretches to match input panel height */}
          <div className="w-[420px] shrink-0 flex flex-col">
            {/* Bezel */}
            <div className="bg-stone-800 rounded-2xl p-3 shadow-2xl border border-stone-700 flex flex-col flex-1">
              {/* Title bar */}
              <div className="flex items-center gap-2 px-2 pb-3 shrink-0">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <div className="w-3 h-3 rounded-full bg-yellow-400" />
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="ml-3 text-xs font-mono text-stone-400 uppercase tracking-widest">agent log</span>
              </div>
              {/* Screen */}
              <div
                ref={logRef}
                className="bg-stone-950 rounded-xl px-5 py-4 overflow-y-auto font-mono text-xs space-y-2 flex-1"
              >
                {log.length === 0 ? (
                  <p className="text-stone-600 italic">Waiting for analysis...</p>
                ) : (
                  log.map(entry => (
                    <div key={entry.id} className="flex items-start gap-3">
                      <span className={`shrink-0 font-bold w-8 ${
                        entry.level === "L0" ? "text-blue-400" :
                        entry.level === "L1" ? "text-purple-400" :
                        entry.level === "L2" ? "text-orange-400" :
                        entry.level === "✓"  ? "text-green-400" : "text-red-400"
                      }`}>
                        [{entry.level}]
                      </span>
                      <span className={`leading-relaxed ${
                        entry.type === "thinking" ? "text-stone-500" :
                        entry.type === "done"     ? "text-green-400" :
                        entry.type === "error"    ? "text-red-400"   : "text-stone-200"
                      }`}>
                        {entry.message}
                      </span>
                    </div>
                  ))
                )}
                {running && <div className="text-stone-500 animate-pulse">▌</div>}
              </div>
            </div>
            {/* Stand — sits right below the bezel, level with dropdowns */}
            <div className="flex flex-col items-center mt-1">
              <div className="w-20 h-4 bg-stone-400 rounded-b-sm" />
              <div className="w-36 h-2.5 bg-stone-400 rounded-b-xl" />
            </div>
          </div>

        </div>

        {/* ── Level cards (full width, below the top row) ── */}
        {log.length > 0 && (
          <div className="mt-8 space-y-3">
            {levelCards.map(({ key, title, data }) => (
              <div
                key={key}
                className={`bg-white border rounded-xl transition-[border-color,box-shadow] duration-300 overflow-hidden ${
                  data.status === "thinking" ? "border-orange-200 shadow-md" :
                  data.status === "done"     ? "border-stone-200 hover:shadow-md" :
                                               "border-stone-100"
                }`}
              >
                <div
                  className="flex items-center justify-between px-5 py-4 cursor-pointer"
                  onClick={() => data.status === "done" && setExpandedCard(expandedCard === key ? null : key)}
                >
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-bold tracking-widest ${
                      key === "L0" ? "text-blue-400" :
                      key === "L1" ? "text-purple-400" : "text-orange-500"
                    }`}>
                      {key}
                    </span>
                    <span className="text-sm font-medium text-stone-700">{title}</span>
                    {data.status === "thinking" && (
                      <span className="text-xs text-orange-400 animate-pulse">thinking...</span>
                    )}
                    {key === "L1" && data.status === "done" && (
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        data.changed ? "bg-orange-100 text-orange-600" : "bg-stone-100 text-stone-500"
                      }`}>
                        {data.changed ? "changed" : "confirmed"}
                      </span>
                    )}
                    {key === "L2" && data.status === "done" && data.rounds_taken && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-stone-100 text-stone-500">
                        {data.rounds_taken} round{data.rounds_taken > 1 ? "s" : ""}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    {data.status === "done" && (
                      <>
                        <span className={`text-sm font-bold ${labelColor(data.label)}`}>{data.label}</span>
                        <span className="text-sm text-stone-500">{Math.round(data.confidence * 100)}%</span>
                        <span className="text-stone-300 text-xs">{expandedCard === key ? "▲" : "▼"}</span>
                      </>
                    )}
                  </div>
                </div>

                {expandedCard === key && data.status === "done" && (
                  <div className="px-5 pb-5 border-t border-stone-100 pt-4 space-y-3">
                    {key === "L1" && data.extra && (
                      <div>
                        <p className="text-xs font-medium text-stone-400 uppercase tracking-wider mb-1">Critique</p>
                        <p className="text-sm text-stone-600 leading-relaxed">{data.extra}</p>
                      </div>
                    )}
                    <div>
                      <p className="text-xs font-medium text-stone-400 uppercase tracking-wider mb-1">
                        {key === "L1" ? "Revised Reasoning" : "Reasoning"}
                      </p>
                      <p className="text-sm text-stone-600 leading-relaxed">{data.reasoning}</p>
                    </div>
                    {key === "L0" && data.extra && (
                      <div>
                        <p className="text-xs font-medium text-stone-400 uppercase tracking-wider mb-1">Indicators</p>
                        <p className="text-sm text-stone-600 leading-relaxed">{data.extra}</p>
                      </div>
                    )}
                    {data.model && (
                      <p className="text-xs text-stone-400 font-mono pt-1">
                        {data.model} · {data.tokens?.input_tokens}↑ {data.tokens?.output_tokens}↓ tokens · ${data.tokens?.cost_usd.toFixed(6)}
                      </p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── Analysis charts (full width) ── */}
        {cost && (() => {
          const LEVEL_COLORS: Record<string, string> = { L0: "#60a5fa", L1: "#a78bfa", L2: "#f97316" };
          const maxTime = Math.max(timings.L0 ?? 0, timings.L1 ?? 0, timings.L2 ?? 0, 1);
          const maxCost = Math.max(...cost.breakdown.map(b => b.cost_usd), 0.000001);
          const BAR_H = 100;

          const timeRows = [
            { label: "L0", value: timings.L0 ?? 0 },
            { label: "L1", value: timings.L1 ?? 0 },
            { label: "L2", value: timings.L2 ?? 0 },
          ];

          return (
            <div className="mt-8 bg-stone-50 border border-stone-200 rounded-2xl p-8">
              <p className="text-xs font-medium text-stone-400 uppercase tracking-widest mb-8">Analysis Results</p>

              <div className="grid grid-cols-2 gap-12 mb-8">

                {/* Time bar chart */}
                <div>
                  <p className="text-sm font-semibold text-stone-700 mb-6">Processing Time</p>
                  <div className="flex items-end gap-6" style={{ height: `${BAR_H + 48}px` }}>
                    {timeRows.map(b => {
                      const h = b.value > 0 ? Math.max((b.value / maxTime) * BAR_H, 6) : 0;
                      return (
                        <div key={b.label} className="flex-1 flex flex-col items-center gap-2">
                          <span className="text-xs text-stone-500 font-mono">
                            {b.value > 0 ? `${(b.value / 1000).toFixed(1)}s` : "—"}
                          </span>
                          <div className="w-full relative flex items-end" style={{ height: `${BAR_H}px` }}>
                            <div
                              className="w-full rounded-t-lg transition-all duration-700"
                              style={{ height: `${h}px`, backgroundColor: LEVEL_COLORS[b.label] }}
                            />
                          </div>
                          <span className="text-xs font-bold" style={{ color: LEVEL_COLORS[b.label] }}>{b.label}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Cost bar chart */}
                <div>
                  <p className="text-sm font-semibold text-stone-700 mb-6">Cost per Level</p>
                  <div className="flex items-end gap-6" style={{ height: `${BAR_H + 48}px` }}>
                    {cost.breakdown.map(b => {
                      const h = b.cost_usd > 0 ? Math.max((b.cost_usd / maxCost) * BAR_H, 6) : 0;
                      return (
                        <div key={b.level} className="flex-1 flex flex-col items-center gap-2">
                          <span className="text-xs text-stone-500 font-mono">
                            {b.cost_usd > 0 ? `$${b.cost_usd.toFixed(5)}` : "free"}
                          </span>
                          <div className="w-full relative flex items-end" style={{ height: `${BAR_H}px` }}>
                            <div
                              className="w-full rounded-t-lg transition-all duration-700"
                              style={{
                                height: b.cost_usd > 0 ? `${h}px` : "4px",
                                backgroundColor: b.cost_usd > 0 ? LEVEL_COLORS[b.level] : "#e7e5e4",
                              }}
                            />
                          </div>
                          <span className="text-xs font-bold" style={{ color: LEVEL_COLORS[b.level] }}>{b.level}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

              </div>

              {/* Summary stats */}
              <div className="grid grid-cols-3 gap-6 border-t border-stone-200 pt-6">
                <div>
                  <p className="text-2xl font-serif font-bold text-stone-800">${cost.total_cost_usd.toFixed(6)}</p>
                  <p className="text-xs text-stone-400 mt-1">Total cost</p>
                </div>
                <div>
                  <p className="text-2xl font-serif font-bold text-stone-800">{cost.total_input_tokens}</p>
                  <p className="text-xs text-stone-400 mt-1">Input tokens</p>
                </div>
                <div>
                  <p className="text-2xl font-serif font-bold text-stone-800">{cost.total_output_tokens}</p>
                  <p className="text-xs text-stone-400 mt-1">Output tokens</p>
                </div>
              </div>
            </div>
          );
        })()}

      </div>
    </section>
  );
}
