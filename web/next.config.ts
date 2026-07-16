import type { NextConfig } from "next";

const rawBasePath = process.env.NEXT_PUBLIC_BASE_PATH?.trim();
const basePath = rawBasePath && rawBasePath !== "/" ? rawBasePath.replace(/\/+$/, "") : undefined;

const nextConfig: NextConfig = {
  basePath,
  poweredByHeader: false,
  typedRoutes: false,
  // Turbopack over-traces runtime-configurable portal state paths back to
  // compile-time TS inputs; the server runtime uses emitted .next chunks.
  outputFileTracingExcludes: {
    "/*": [
      "./next.config.ts",
      "./vite.config.ts",
      "./tsconfig.json",
      "./tsconfig.tsbuildinfo",
      "./src/**/*",
    ],
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
          {
            key: "Content-Security-Policy",
            value:
              "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
          },
        ],
      },
      {
        // The /intro cinematic splash (static, public/intro/) scrubs pre-rendered
        // video through blob: object URLs created from same-origin fetches, which
        // the site-wide policy's default-src fallback would block. This rule is
        // scoped to /intro only and differs from the global CSP solely by the
        // added `media-src 'self' blob:`; the other security headers still come
        // from the global rule above.
        source: "/intro/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value:
              "default-src 'self'; img-src 'self' data:; media-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
          },
        ],
      },
      {
        // The splash's big static assets (pre-rendered clips, self-hosted fonts,
        // poster stills) are content-stable — cache them hard so a reload or a
        // repeat viewer gets them from the browser/CDN instead of re-pulling
        // ~6MB of video from origin each time. Next serves public/ with
        // `max-age=0` by default, which is what forced a full re-download on
        // every view. If these assets are ever changed, bump the filename or
        // purge the CDN, since a returning browser will hold this for a week.
        source: "/intro/assets/frames/:path*",
        headers: [{ key: "Cache-Control", value: "public, max-age=604800, stale-while-revalidate=86400" }],
      },
      {
        source: "/intro/assets/fonts/:path*",
        headers: [{ key: "Cache-Control", value: "public, max-age=604800, stale-while-revalidate=86400" }],
      },
    ];
  },
  async rewrites() {
    return [
      // Serve the standalone splash at the bare URL (public route: /prizes/intro).
      // public/ files only resolve by exact path, so map the directory URL to its
      // index document; asset refs inside it are absolute (/prizes/intro/assets/…).
      { source: "/intro", destination: "/intro/index.html" },
    ];
  },
};

export default nextConfig;
