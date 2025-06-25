/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals.push('@grpc/grpc-js');
    }
    return config;
  },
};
module.exports = nextConfig;
