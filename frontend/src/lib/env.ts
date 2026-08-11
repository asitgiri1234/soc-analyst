/**
 * Public runtime configuration.
 *
 * Next.js inlines `NEXT_PUBLIC_*` at build time, so they must be referenced
 * as full literal expressions rather than via a dynamic index.
 */

export const env = {
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
  apiVersion: process.env.NEXT_PUBLIC_API_VERSION ?? "v1",
  appName: process.env.NEXT_PUBLIC_APP_NAME ?? "AI SOC Analyst",
} as const;

export const apiUrl = (path: string): string => {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return `${env.apiBaseUrl}/api/${env.apiVersion}${normalized}`;
};
