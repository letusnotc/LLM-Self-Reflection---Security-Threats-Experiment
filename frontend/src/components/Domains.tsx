const domains = [
  {
    tag: "Network Intrusion",
    title: "Network Traffic",
    description:
      "Detects DoS, Probe, R2L, and U2R attacks using NSL-KDD dataset features. Self-reflection improves accuracy by up to 3.4% over the baseline pass.",
    stat: "93.8%",
    statLabel: "accuracy",
    dataset: "NSL-KDD",
  },
  {
    tag: "Insider Threat",
    title: "Insider Behavior",
    description:
      "Identifies malicious insider patterns from the CERT dataset. The highest-improvement domain — reflection adds +4.1 points to F1 score.",
    stat: "91.2%",
    statLabel: "F1 score",
    dataset: "CERT r4.2",
  },
  {
    tag: "Malware",
    title: "Malware Detection",
    description:
      "Classifies binaries using ClaMP static analysis features. Flash-Lite accuracy ceiling constrains reflection gains; larger models clear the gap.",
    stat: "78.3%",
    statLabel: "accuracy",
    dataset: "ClaMP",
  },
  {
    tag: "Log Analysis",
    title: "System Logs",
    description:
      "Analyzes HDFS log sequences for anomalies. Structured JSON output constraints expose fundamental weaknesses in open-source model families.",
    stat: "84.6%",
    statLabel: "accuracy",
    dataset: "HDFS",
  },
];

export default function Domains() {
  return (
    <section id="domains" className="py-28 px-6 bg-[#f5f4f0]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-20">
          <span className="inline-block px-3 py-1 bg-stone-200 text-stone-500 text-xs font-medium rounded-full mb-4 tracking-widest uppercase">
            Detection Domains
          </span>
          <h2 className="font-serif text-5xl lg:text-6xl font-bold text-stone-800 mt-4">
            Where AI Defends Best.
          </h2>
          <p className="mt-5 text-stone-500 max-w-lg mx-auto text-lg leading-relaxed">
            Four cybersecurity threat domains evaluated with LLM self-reflection
            agents using real benchmark datasets.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-4">
          {domains.map((d) => (
            <div
              key={d.title}
              className="group card-lift bg-white rounded-2xl border border-stone-200 overflow-hidden h-full"
            >
              <div className="h-0.5 bg-orange-500 w-0 group-hover:w-full transition-[width] duration-500" />
              <div className="p-8">
                <div className="flex items-start justify-between mb-6">
                  <span className="inline-block px-2.5 py-1 bg-stone-100 text-stone-500 text-xs font-medium rounded-full">
                    {d.tag}
                  </span>
                  <span className="text-xs text-stone-400 bg-stone-100 px-2.5 py-1 rounded-full font-mono">
                    {d.dataset}
                  </span>
                </div>
                <h3 className="font-serif text-2xl font-bold text-stone-800 mb-3">
                  {d.title}
                </h3>
                <p className="text-stone-500 text-sm leading-relaxed mb-8">
                  {d.description}
                </p>
                <div className="flex items-baseline gap-1.5">
                  <span className="font-serif text-3xl font-bold text-stone-800">
                    {d.stat}
                  </span>
                  <span className="text-stone-400 text-sm">{d.statLabel}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
