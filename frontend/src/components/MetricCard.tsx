import type { ReactNode } from "react";

type MetricCardProps = {
  label: string;
  value: number | string;
  tone?: "default" | "danger" | "warning" | "success";
  icon: ReactNode;
};

export function MetricCard({ label, value, tone = "default", icon }: MetricCardProps) {
  return (
    <section className={`metric metric-${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
      </div>
    </section>
  );
}
