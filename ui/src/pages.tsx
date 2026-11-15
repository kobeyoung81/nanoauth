// What this remote exposes: `auth/pages` → the named pages.
//
// One module, several pages: the manifest points each route at an export here, so
// adding a screen is a file plus one manifest entry.

export { ChangePasswordPage } from './pages/change-password'
export { LoginPage } from './pages/login'
export { RegisterPage } from './pages/register'
export { UsersPage } from './users'
export { AccountPage } from './account'
export { UserDetailPage } from './userDetail'
