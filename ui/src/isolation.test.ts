import { describe, expect, it } from 'vitest'
import manifest from '../public/plugin.json'
import remoteConfig from '../vite.config.ts?raw'
import account from './account.tsx?raw'
import contract from './contract.ts?raw'
import pages from './pages.tsx?raw'
import userDetail from './userDetail.tsx?raw'
import users from './users.tsx?raw'

// This application renders inside the portal's tree and may not import the
// portal's source: the kit, the strings, the data client and the shell features
// all arrive through the page context. These checks pin that boundary, because an
// import that sneaks back in would build here and fail at runtime (the module does
// not exist in the shell's bundle).

const SOURCES = { 'users.tsx': users, 'account.tsx': account, 'userDetail.tsx': userDetail }

describe('the boundary', () => {
  for (const [name, source] of Object.entries(SOURCES)) {
    it(`${name} imports only its own modules, react and icons`, () => {
      const imports = [...source.matchAll(/from '([^']+)'/g)].map((match) => match[1])
      const external = imports.filter((spec) => !spec.startsWith('.'))
      const allowed = ['lucide-react', 'react']
      expect(external.filter((spec) => !allowed.includes(spec))).toEqual([])
    })

    it(`${name} takes everything from the context`, () => {
      expect(source).not.toContain("from '../components")
      expect(source).not.toContain("from '../lib")
    })
  }

  it('defines its section wrapper once, at module scope', () => {
    // A component created during render is a new type every render: React then
    // unmounts and remounts its subtree, and the widgets inside keep the page
    // re-rendering until React refuses ("maximum update depth exceeded").
    expect(userDetail).toContain('\nfunction SectionCard(')
    expect(userDetail).not.toContain('const SectionCard = (')
  })

  it('asks the shell for the agent editor instead of rebuilding it', () => {
    expect(account).toContain('features.openAgentForm(')
    expect(account).not.toContain('AgentFormDialog')
  })

  it('exposes every page the manifest declares', () => {
    for (const page of manifest.pages) {
      expect(pages, `${page.id} is not exported`).toContain(`export { ${page.mount.export} }`)
    }
    // The console's account screens and the three sign-in screens: the auth module
    // owns every page that talks about an account, including the unauthenticated
    // ones.
    expect(manifest.pages.map((page) => page.path)).toEqual([
      '/admin/users',
      '/me',
      '/admin/users/:id',
      '/login',
      '/register',
      '/change-password',
    ])
  })

  it('ships both pages from the remote build under /plugins/auth/', () => {
    expect(manifest.entry).toBe('/plugins/auth/remoteEntry.js')
    expect(remoteConfig).toContain("'./pages': './src/pages.tsx'")
    expect(remoteConfig).toContain("base: '/plugins/auth/'")
  })

  it('mirrors the portal contract fields the pages use', () => {
    for (const field of ['t:', 'ui:', 'api:', 'features:', 'toast:', 'navigate:', 'token:', 'locale:']) {
      expect(contract).toContain(field)
    }
  })
})
