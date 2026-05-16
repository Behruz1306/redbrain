import type { NextConfig } from "next";

const API_URL = process.env.NEXT_PUBLIC_API_HOST
  ? `https://${process.env.NEXT_PUBLIC_API_HOST}`
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
  output: "standalone",
};

export default nextConfig;
