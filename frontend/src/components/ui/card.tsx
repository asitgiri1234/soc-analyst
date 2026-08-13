/** Surfaces and headings shared by every panel on the dashboard. */

import type { ReactNode } from "react";

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-soc-border bg-soc-surface ${className}`}
    >
      {children}
    </section>
  );
}

export function CardHeader({
  title,
  subtitle,
  action,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-soc-border px-5 py-4">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold tracking-wide text-soc-text uppercase">
          {title}
        </h2>
        {subtitle && <p className="mt-1 text-xs text-soc-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function CardBody({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`px-5 py-4 ${className}`}>{children}</div>;
}

/** A single headline figure. */
export function StatCard({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "neutral" | "danger" | "warn" | "ok";
}) {
  const toneClass = {
    neutral: "text-soc-text",
    danger: "text-rose-400",
    warn: "text-amber-400",
    ok: "text-emerald-400",
  }[tone];

  return (
    <div className="rounded-xl border border-soc-border bg-soc-surface px-5 py-4">
      <p className="text-xs font-medium tracking-wide text-soc-muted uppercase">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${toneClass}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-soc-faint">{hint}</p>}
    </div>
  );
}
