import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { federation } from '@module-federation/vite'
import { splitUtilityLayers } from './vite-plugins/splitUtilityLayers'

// The auth module's front end.
//
// It has no document of its own: the portal's shell loads it at runtime from
// /plugins/auth/ and renders it inside its own React tree. React therefore comes
// from the host (`import: false`). The palette and the base rules stay the
// shell's; this module builds the utilities its own screens use, into the
// `plugin` layer so they cannot outrank the shell's responsive variants.
export default defineConfig({
  base: '/plugins/auth/',
  plugins: [
    react(),
    // The module ships the utilities its own screens use: the shell's Tailwind
    // only scans the shell's sources, and the shell no longer carries a copy of
    // these screens. See src/styles.css for why they go into the `plugin` layer.
    tailwindcss(),
    // Base rules one layer below the shell, variants in the shell's own layer:
    // see vite-plugins/splitUtilityLayers.ts for why both are needed.
    splitUtilityLayers(),
    federation({
      name: 'auth',
      filename: 'remoteEntry.js',
      exposes: { './pages': './src/pages.tsx' },
      shared: {
        react: { singleton: true, import: false },
        'react-dom': { singleton: true, import: false },
      },
    }),
  ],
  publicDir: 'public',
  build: {
    target: 'chrome103',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: { input: 'plugin.html' },
  },
})
