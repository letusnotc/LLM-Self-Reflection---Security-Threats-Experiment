type Tier = {
  level: string;
  tag: string;
  title: string;
  image: string;
  description: string;
  metrics: { label: string; value: string }[];
  highlight: boolean;
};

const tiers: Tier[] = [
  {
    level: "L0",
    tag: "Baseline",
    title: "No Reflection",
    image: "/level 0.png",
    description:
      "Direct single-pass classification. Fast and cheap, but misses nuanced patterns. Establishes the performance floor for comparison.",
    metrics: [
      { label: "Avg accuracy", value: "~87%" },
      { label: "Cost per query", value: "$0.001" },
      { label: "Latency", value: "~0.8s" },
    ],
    highlight: false,
  },
  {
    level: "L1",
    tag: "Single Reflection",
    title: "Self-Critique",
    image: "/level 1.png",
    description:
      "Agent reviews its initial classification, reconsidering feature interpretations. Meaningful accuracy gains for mid-tier models.",
    metrics: [
      { label: "Avg accuracy", value: "~91%" },
      { label: "Cost per query", value: "$0.003" },
      { label: "Latency", value: "~2.1s" },
    ],
    highlight: true,
  },
  {
    level: "L2",
    tag: "Iterative Consensus",
    title: "Consensus Loop",
    image: "/level 2.png",
    description:
      "Multiple rounds until convergence. Highest accuracy — but also surfaces the Self-Reflection Paradox at capability extremes.",
    metrics: [
      { label: "Avg accuracy", value: "~93%" },
      { label: "Cost per query", value: "$0.008" },
      { label: "Latency", value: "~4.3s" },
    ],
    highlight: false,
  },
];

export default function ModelTiers() {
  return (
    <section id="models" className="py-28 px-6 bg-[#f5f4f0]">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-20">
          <span className="inline-block px-3 py-1 bg-stone-200 text-stone-500 text-xs font-medium rounded-full mb-4 tracking-widest uppercase">
            Architecture
          </span>
          <h2 className="font-serif text-5xl lg:text-6xl font-bold text-stone-800 mt-4">
            Self-Reflection.
          </h2>
          <h2 className="font-serif text-5xl lg:text-6xl font-bold text-stone-300 leading-none">
            Three Levels.
          </h2>
          <p className="mt-6 text-stone-500 max-w-xl mx-auto text-lg leading-relaxed">
            Each level adds reasoning depth — but also exposes the{" "}
            <span className="text-stone-700 font-medium italic">
              Self-Reflection Paradox
            </span>
            : weak models produce bad feedback, strong models hit the ceiling.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-5">
          {tiers.map((tier) => (
            <div
              key={tier.level}
              className={`relative card-lift h-full rounded-2xl p-8 border ${
                tier.highlight
                  ? "bg-white border-orange-200 shadow-lg"
                  : "bg-white border-stone-200"
              }`}
            >

              <div className="flex items-center justify-between mb-8">
                <span
                  className={`font-serif text-xs font-bold tracking-widest ${
                    tier.highlight ? "text-orange-500" : "text-stone-400"
                  }`}
                >
                  {tier.level}
                </span>
                <span className="inline-block px-2.5 py-1 bg-stone-100 text-stone-500 text-xs font-medium rounded-full">
                  {tier.tag}
                </span>
              </div>

              <div className="w-full mb-5 flex items-center justify-center">
                <img
                  src={tier.image}
                  alt={tier.title}
                  className="w-full h-auto object-contain"
                />
              </div>

              <h3 className="font-serif text-2xl font-bold text-stone-800 mb-3">
                {tier.title}
              </h3>
              <p className="text-stone-500 text-sm leading-relaxed mb-8">
                {tier.description}
              </p>

              <div className="space-y-3 pt-6 border-t border-stone-100">
                {tier.metrics.map((m) => (
                  <div key={m.label} className="flex items-center justify-between text-sm">
                    <span className="text-stone-400">{m.label}</span>
                    <span className="font-medium text-stone-700">{m.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
