import { lysConfig } from 'lys-docs-theme/config'

export default lysConfig({
  name: 'lys-secrets',
  description: "The lys desktop's freedesktop Secret Service.",
  nav: [{ text: 'Guide', link: '/guide/getting-started', activeMatch: '^/guide/' }],
  sidebar: [
    {
      text: 'Guide',
      items: [
        { text: 'Getting started', link: '/guide/getting-started' },
        { text: 'Install', link: '/guide/install' },
        { text: 'Configuration', link: '/guide/configuration' },
        { text: 'How it works', link: '/guide/how-it-works' },
        { text: 'How secrets are protected', link: '/guide/security' },
        { text: 'Development', link: '/guide/development' },
      ],
    },
  ],
})
