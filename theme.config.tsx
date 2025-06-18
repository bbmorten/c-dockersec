import React from 'react'
import { DocsThemeConfig } from 'nextra-theme-docs'

const config: DocsThemeConfig = {
  logo: <span>My Documentation</span>,
  project: {
    link: 'https://github.com/bbmorten/c-dockersec',
  },
  docsRepositoryBase: 'https://github.com/bbmorten/c-dockersec',
  footer: {
    text: 'Documentation built with Nextra',
  },
  search: {
    placeholder: 'Search documentation...'
  },
  sidebar: {
    titleComponent({ title, type }) {
      if (type === 'separator') {
        return <span className="cursor-default">{title}</span>
      }
      return <>{title}</>
    },
    defaultMenuCollapseLevel: 1,
    toggleButton: true
  },
  toc: {
    backToTop: true
  }
}

export default config
