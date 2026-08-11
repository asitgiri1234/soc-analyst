import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Emits a minimal self-contained server bundle, consumed by the Dockerfile.
  output: "standalone",
};

export default nextConfig;
