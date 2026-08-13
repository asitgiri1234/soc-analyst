/**
 * Presentation helpers.
 *
 * Timestamps arrive as UTC ISO strings. A SOC works to absolute time, so they
 * are rendered in full rather than only as "3 hours ago" -- the relative form
 * is offered alongside, for scanning a list, never instead.
 */

const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
});

const DATE_ONLY = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : DATE_TIME.format(date);
}

export function formatDay(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : DATE_ONLY.format(date);
}

const UNITS: [limit: number, seconds: number, name: Intl.RelativeTimeFormatUnit][] = [
  [60, 1, "second"],
  [3600, 60, "minute"],
  [86400, 3600, "hour"],
  [2592000, 86400, "day"],
  [31536000, 2592000, "month"],
  [Infinity, 31536000, "year"],
];

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";

  const elapsed = (date.getTime() - Date.now()) / 1000;
  const magnitude = Math.abs(elapsed);
  for (const [limit, divisor, unit] of UNITS) {
    if (magnitude < limit) return RELATIVE.format(Math.round(elapsed / divisor), unit);
  }
  return DATE_ONLY.format(date);
}

/** `brute_force` -> `Brute force`. Enum values are snake_case on the wire. */
export function humanise(value: string | null | undefined): string {
  if (!value) return "—";
  const spaced = value.replace(/_/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Math.round(value * 100)}%`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return new Intl.NumberFormat().format(value);
}
