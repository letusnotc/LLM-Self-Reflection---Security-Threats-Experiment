const stats = [
  { value: "4", label: "Threat Domains" },
  { value: "3", label: "Reflection Levels" },
  { value: "93%", label: "Peak Accuracy" },
  { value: "2", label: "Model Families" },
];

export default function Stats() {
  return (
    <section id="research" className="py-20 px-6 bg-stone-900">
      <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-10">
        {stats.map((s) => (
          <div key={s.label} className="text-center">
            <div className="font-serif text-5xl lg:text-6xl font-bold text-white mb-2">
              {s.value}
            </div>
            <div className="text-stone-400 text-sm tracking-wide">{s.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
