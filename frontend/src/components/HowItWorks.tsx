const steps = [
  {
    num: "01",
    title: "Submit",
    description:
      "Provide raw log data, network captures, or behavioral sequences. The agent preprocesses and encodes features for LLM analysis.",
    tags: ["NSL-KDD", "CERT", "ClaMP", "HDFS"],
  },
  {
    num: "02",
    title: "Reflect",
    description:
      "The LLM critiques its own initial classification — reviewing feature weights and revising confidence scores through structured self-critique.",
    tags: ["L0 Baseline", "L1 Self-Critique", "JSON Schema"],
  },
  {
    num: "03",
    title: "Consensus",
    description:
      "Multiple reflection rounds converge to a high-confidence verdict. The iterative loop halts when the agent agrees with itself across rounds.",
    tags: ["L2 Consensus", "McNemar tested", "Explainable"],
  },
];

export default function HowItWorks() {
  return (
    <section id="process" className="py-28 px-6 bg-white">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-20">
          <span className="inline-block px-3 py-1 bg-stone-100 text-stone-500 text-xs font-medium rounded-full mb-4 tracking-widest uppercase">
            Process
          </span>
          <h2 className="font-serif text-5xl lg:text-6xl font-bold text-stone-800 mt-4">
            A Clear Path to Detection.
          </h2>
          <p className="mt-5 text-stone-500 max-w-md mx-auto text-lg leading-relaxed">
            Three stages that turn raw security data into a high-confidence
            threat verdict.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {steps.map((step) => (
            <div
              key={step.num}
              className="group card-lift bg-white rounded-2xl p-8 border border-stone-200 hover:border-orange-300"
            >
              {/* Number row with line */}
              <div className="flex items-center gap-4 mb-7">
                <span className="font-serif text-5xl font-bold text-orange-500 leading-none select-none">
                  {step.num}
                </span>
                <div className="flex-1 h-px bg-stone-200 group-hover:bg-orange-200 transition-colors duration-300" />
              </div>

              <h3 className="font-serif text-2xl font-bold text-stone-800 mb-3">
                {step.title}
              </h3>
              <p className="text-stone-500 text-sm leading-relaxed mb-6">
                {step.description}
              </p>
              <div className="flex flex-wrap gap-2">
                {step.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-2.5 py-1 bg-orange-50 text-orange-600 text-xs rounded-full font-medium border border-orange-100"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-14 text-center">
          <a
            href="#demo"
            className="inline-block px-8 py-3.5 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Analyze a Sample Log
          </a>
        </div>
      </div>
    </section>
  );
}
