export default function CTASection() {
  return (
    <section id="demo" className="py-20 px-6 bg-white">
      <div className="max-w-2xl mx-auto bg-stone-50 rounded-3xl p-12 text-center border border-stone-200">
        <h2 className="font-serif text-4xl font-bold text-stone-800 mb-2">
          Run Your Analysis
        </h2>
        <h2 className="font-serif text-4xl font-bold text-stone-400 mb-8">
          Today
        </h2>
        <p className="text-stone-500 leading-relaxed mb-8 max-w-md mx-auto">
          Explore the codebase, read the research paper, or clone the repo and
          run the self-reflection agent against your own log data.
        </p>
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="px-6 py-3 bg-orange-500 hover:bg-orange-600 text-white font-medium rounded-lg transition-colors"
          >
            View on GitHub
          </a>
          <a
            href="#domains"
            className="px-6 py-3 border border-stone-300 hover:border-stone-400 text-stone-700 font-medium rounded-lg transition-colors bg-white"
          >
            Explore Domains
          </a>
        </div>
        <p className="mt-8 text-xs text-stone-400">
          Open-source research · MIT licensed · Gemini + Ollama
        </p>
      </div>
    </section>
  );
}
