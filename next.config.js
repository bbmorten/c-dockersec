const withNextra = require('nextra')({
  theme: 'nextra-theme-docs',
  themeConfig: './theme.config.tsx',
  defaultShowCopyCode: true,
})

module.exports = withNextra({
  output: 'standalone',
  experimental: {
    outputFileTracingRoot: __dirname,
  },
})
