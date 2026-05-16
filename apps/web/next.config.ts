import type { NextConfig } from "next";

const apiHost = process.env.NEXT_PUBLIC_API_HOST;
const API_URL = apiHost
  ? (apiHost.startsWith("http") ? apiHost : `https://${apiHost}`)
  : "http://localhost:8000";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_URL}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
