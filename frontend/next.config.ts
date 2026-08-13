import type { NextConfig } from "next";

/**
 * The API origin the browser is allowed to talk to.
 *
 * Read here so the CSP's `connect-src` names the real backend rather than
 * having to fall back on a wildcard.
 */
const apiOrigin = (() => {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  try {
    return new URL(configured).origin;
  } catch {
    return "http://localhost:8000";
  }
})();

/**
 * Content Security Policy.
 *
 * `script-src` includes `'unsafe-inline'` because the App Router serves its
 * hydration payload in inline `<script>` tags; a nonce-based policy would need
 * middleware to stamp every request and is not worth the machinery here, since
 * this policy is defence in depth rather than the primary XSS control. That
 * control is that nothing in this app renders untrusted content as HTML -- no
 * `dangerouslySetInnerHTML`, no `innerHTML`, no `eval` -- so LLM output and log
 * messages derived from attacker input are escaped by React.
 *
 * The directives that do real work here are the ones Next does not constrain:
 * `frame-ancestors` (clickjacking), `object-src` (plugin-based execution),
 * `base-uri` (base-tag hijacking) and `connect-src` (exfiltration to a
 * third-party host).
 */
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  // Tailwind is compiled to a stylesheet, but Next still injects inline styles.
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${apiOrigin}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  // The console's URLs carry incident ids; they should not travel to any
  // third-party host in a Referer header.
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Emits a minimal self-contained server bundle, consumed by the Dockerfile.
  output: "standalone",
  // Do not advertise the framework and version to anyone scanning.
  poweredByHeader: false,

  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
