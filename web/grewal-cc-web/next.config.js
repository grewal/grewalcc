// web/grewal-cc-web/next.config.js

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  async headers() {
    return [
      {
        source: '/simulation/(.*).wasm',
        headers: [
          {
            key: 'Content-Type',
            value: 'application/wasm',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
