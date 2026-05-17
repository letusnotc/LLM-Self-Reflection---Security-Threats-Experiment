import Threads from "./Threads";

export default function Hero() {
  return (
    <section className="min-h-screen flex flex-col items-center px-6 text-center relative overflow-hidden bg-[#f5f4f0]">
      <div className="absolute inset-0 pointer-events-none">
        <Threads
          color={[0.976, 0.451, 0.086]}
          amplitude={2.6}
          distance={0.4}
          enableMouseInteraction={false}
        />
      </div>

      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 60% 55% at 50% 50%, transparent 10%, #f5f4f0 75%)",
        }}
      />

      {/* Spacer — guarantees content starts below the expanded nav (~292px) */}
      <div className="flex-shrink-0 h-[320px]" />

      <div className="relative z-10 flex flex-col items-center flex-1 justify-center pb-20">
        <span className="inline-block px-3 py-1 bg-stone-200/80 text-stone-500 text-xs font-medium rounded-full mb-10 tracking-widest uppercase ">
          AI Security Research
        </span>

        <h1 className="font-serif font-bold text-stone-800 leading-none text-[clamp(3.5rem,10vw,8rem)]">
          Threat Intelligence.
        </h1>
        <h1 className="font-serif font-bold text-stone-800 leading-none text-[clamp(3.5rem,10vw,8rem)] mt-1">
          Self-Reflection.
        </h1>

        <p className="mt-10 text-stone-500 text-lg leading-relaxed max-w-lg mx-auto">
          LLM agents that critique their own reasoning to detect cybersecurity
          threats with measurably higher accuracy — across four benchmark domains.
        </p>

        <div className="flex flex-wrap gap-4 mt-10 justify-center">
          <a
            href="#demo"
            className="px-8 py-3.5 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Try Live Detection
          </a>
          <a
            href="https://drive.google.com/file/d/1-TvGb-NGHRaN1qYc_ZIImxgWLEA6vqSb/view?usp=sharing"
            target="_blank"
            rel="noopener noreferrer"
            className="px-8 py-3.5 bg-white/80 border border-stone-300 hover:border-stone-400 text-stone-700 text-sm font-medium rounded-lg transition-colors "
          >
            Read the Paper
          </a>
        </div>

        <div className="flex flex-wrap gap-6 mt-16 justify-center">
          {["Network Intrusion", "Insider Threat", "Malware Detection", "Log Analysis"].map(
            (label, i, arr) => (
              <span key={label} className="flex items-center gap-6">
                <span className="text-xs text-stone-400 tracking-widest uppercase">
                  {label}
                </span>
                {i < arr.length - 1 && (
                  <span className="text-stone-300 text-xs">·</span>
                )}
              </span>
            )
          )}
        </div>
      </div>

      <div className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 opacity-30 z-10">
        <span className="text-xs text-stone-500 tracking-widest uppercase">Scroll</span>
        <div className="w-px h-10 bg-stone-400" />
      </div>
    </section>
  );
}
