import CardNav, { CardNavItem } from "@/components/CardNav";
import Hero from "@/components/Hero";
import Domains from "@/components/Domains";
import HowItWorks from "@/components/HowItWorks";
import ModelTiers from "@/components/ModelTiers";
import Stats from "@/components/Stats";
import DemoSection from "@/components/DemoSection";
import Footer from "@/components/Footer";

const navItems: CardNavItem[] = [
  {
    label: "Domains",
    bgColor: "#1c1917",
    textColor: "#fff",
    links: [
      { label: "Network Intrusion", href: "#domains", ariaLabel: "Network Intrusion detection" },
      { label: "Insider Threat", href: "#domains", ariaLabel: "Insider Threat detection" },
      { label: "Malware Detection", href: "#domains", ariaLabel: "Malware Detection" },
      { label: "Log Analysis", href: "#domains", ariaLabel: "Log Analysis" },
    ],
  },
  {
    label: "Architecture",
    bgColor: "#292524",
    textColor: "#fff",
    links: [
      { label: "How It Works", href: "#process", ariaLabel: "How It Works" },
      { label: "Model Tiers", href: "#models", ariaLabel: "Model Tiers" },
      { label: "Self-Reflection Paradox", href: "#models", ariaLabel: "Self-Reflection Paradox" },
    ],
  },
  {
    label: "Research",
    bgColor: "#c2410c",
    textColor: "#fff",
    links: [
      { label: "Read the Paper", href: "#research", ariaLabel: "Research paper" },
      { label: "GitHub — Gemini", href: "https://github.com", ariaLabel: "GitHub main branch" },
      { label: "GitHub — Ollama", href: "https://github.com", ariaLabel: "GitHub Ollama branch" },
    ],
  },
];

export default function Home() {
  return (
    <>
      {/* Relative wrapper so CardNav (absolute) positions against the hero area */}
      <div className="relative">
        <CardNav
          logo="/logo.svg"
          logoAlt="ClarionGuard"
          items={navItems}
          baseColor="#f5f4f0"
          menuColor="#1c1917"
          buttonBgColor="#f97316"
          buttonTextColor="#fff"
          buttonLabel="Try Demo"
          buttonHref="#demo"
          ease="power3.out"
        />
        <Hero />
      </div>
      <main>
        <Domains />
        <HowItWorks />
        <ModelTiers />
        <Stats />
        <DemoSection />
      </main>
      <Footer />
    </>
  );
}
