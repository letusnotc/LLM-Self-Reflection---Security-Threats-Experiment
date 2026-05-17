export default function Footer() {
  return (
    <footer className="bg-stone-900 text-stone-400 py-16 px-6">
      <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-12">
        <div className="md:col-span-1">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-7 h-7 rounded-lg bg-orange-500 flex items-center justify-center">
              <span className="text-white text-xs font-bold">CG</span>
            </div>
            <span className="font-serif text-lg font-semibold text-stone-200">
              ClarionGuard
            </span>
          </div>
          <p className="text-sm leading-relaxed">
            LLM self-reflection for cybersecurity threat detection. Open-source
            research project exploring the Self-Reflection Paradox.
          </p>
        </div>

        <div>
          <h4 className="text-stone-200 font-medium mb-4 text-sm">Navigate</h4>
          <ul className="space-y-3 text-sm">
            <li>
              <a href="#domains" className="hover:text-stone-200 transition-colors">
                Domains
              </a>
            </li>
            <li>
              <a href="#process" className="hover:text-stone-200 transition-colors">
                How It Works
              </a>
            </li>
            <li>
              <a href="#models" className="hover:text-stone-200 transition-colors">
                Architecture
              </a>
            </li>
            <li>
              <a href="#research" className="hover:text-stone-200 transition-colors">
                Research
              </a>
            </li>
          </ul>
        </div>

        <div>
          <h4 className="text-stone-200 font-medium mb-4 text-sm">Code</h4>
          <ul className="space-y-3 text-sm">
            <li>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-stone-200 transition-colors"
              >
                GitHub — main (Gemini)
              </a>
            </li>
            <li>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-stone-200 transition-colors"
              >
                GitHub — ollama branch
              </a>
            </li>
            <li>
              <a href="#" className="hover:text-stone-200 transition-colors">
                API Docs
              </a>
            </li>
          </ul>
        </div>

        <div>
          <h4 className="text-stone-200 font-medium mb-4 text-sm">Research</h4>
          <ul className="space-y-3 text-sm">
            <li>
              <a href="#" className="hover:text-stone-200 transition-colors">
                Paper (PDF)
              </a>
            </li>
            <li>
              <a
                href="https://www.unb.ca/cic/datasets/nsl.html"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-stone-200 transition-colors"
              >
                NSL-KDD Dataset
              </a>
            </li>
            <li>
              <a
                href="https://certs.cdc.gov"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-stone-200 transition-colors"
              >
                CERT Dataset
              </a>
            </li>
          </ul>
        </div>
      </div>

      <div className="max-w-6xl mx-auto mt-12 pt-8 border-t border-stone-800 text-xs text-stone-600 flex flex-col md:flex-row justify-between gap-4">
        <p>© 2025 ClarionGuard Research. Open source under MIT License.</p>
        <p>Built with Next.js + FastAPI · Powered by Gemini & Ollama</p>
      </div>
    </footer>
  );
}
