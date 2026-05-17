"use client";
import Link from "next/link";

export default function Navbar() {
  return (
    <nav className="fixed top-0 inset-x-0 z-50 bg-[#f5f4f0] border-b border-stone-200">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-orange-500 flex items-center justify-center">
            <span className="text-white text-xs font-bold">CG</span>
          </div>
          <span className="font-serif text-lg font-semibold text-stone-800">
            ClarionGuard
          </span>
        </Link>

        <div className="hidden md:flex items-center gap-8 text-sm text-stone-600">
          <Link href="#domains" className="hover:text-stone-900 transition-colors">
            Domains
          </Link>
          <Link href="#process" className="hover:text-stone-900 transition-colors">
            How It Works
          </Link>
          <Link href="#models" className="hover:text-stone-900 transition-colors">
            Architecture
          </Link>
          <Link href="#research" className="hover:text-stone-900 transition-colors">
            Research
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <a
            href="https://github.com/arnavpandey"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:block text-sm text-stone-600 hover:text-stone-900 transition-colors"
          >
            GitHub
          </a>
          <Link
            href="#demo"
            className="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Try Demo
          </Link>
        </div>
      </div>
    </nav>
  );
}
