// What this remote exposes: `auth/pages` → the named pages.
//
// One module, several pages: the manifest points each route at an export here, so
// adding a screen is a file plus one manifest entry.

export { UsersPage } from './users'
export { AccountPage } from './account'
