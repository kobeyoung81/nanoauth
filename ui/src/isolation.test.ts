import { describe, expect, it } from 'vitest'
import manifest from '../public/plugin.json'
import remoteConfig from '../vite.config.ts?raw'
import contract from './contract.ts?raw'
import pages from './pages.tsx?raw'

// This application renders inside the portal's tree and may not import the
// portal's source: the kit, the strings and the data client all arrive through the
// page context. These checks pin that boundary, because an import that sneaks back
// in would build here and fail at runtime (the module does not exist in the shell's
// bundle).

describe('the boundary', () => {
  it('imports only its own modules, react and icons', () => {
    const imports = [...pages.matchAll(/from '([^']+)'/g)].map((match) => match[1])
    const external = imports.filter((spec) => !spec.startsWith('.'))
    expect(external.sort()).toEqual(['lucide-react', 'react'])
  })

  it('takes the kit, the strings and the client from the context', () => {
    expect(pages).toContain('const { t, ui, api, navigate } = ctx')
    expect(pages).not.toContain("from '../components")
    expect(pages).not.toContain("from '../lib")
  })

  it('declares the page in the manifest and exposes it from the remote build', () => {
    expect(manifest.pages.map((page) => page.path)).toEqual(['/admin/users'])
    expect(manifest.entry).toBe('/plugins/auth/remoteEntry.js')
    expect(remoteConfig).toContain("'./pages': './src/pages.tsx'")
    expect(remoteConfig).toContain("base: '/plugins/auth/'")
  })

  it('mirrors the portal contract fields the page uses', () => {
    // A field added on the portal side must be added here before a page may use it.
    for (const field of ['t:', 'ui:', 'api:', 'navigate:', 'token:', 'locale:']) {
      expect(contract).toContain(field)
    }
  })
})
