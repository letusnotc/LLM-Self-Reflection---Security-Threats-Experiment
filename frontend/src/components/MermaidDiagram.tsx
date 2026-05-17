"use client";

import { useEffect, useRef } from "react";

export default function MermaidDiagram({ chart }: { chart: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;

    async function render() {
      const mermaid = (await import("mermaid")).default;
      mermaid.initialize({
        startOnLoad: false,
        theme: "base",
        themeVariables: {
          fontFamily: "inherit",
          fontSize: "13px",
        },
      });

      if (!ref.current || cancelled) return;
      const id = `mermaid-${Math.random().toString(36).slice(2)}`;
      const { svg } = await mermaid.render(id, chart);
      if (ref.current && !cancelled) {
        ref.current.innerHTML = svg;
      }
    }

    render();
    return () => { cancelled = true; };
  }, [chart]);

  return <div ref={ref} className="w-full flex justify-center" />;
}
