// The user row the console's account list shows.
//
// The portal serves it (`GET /api/admin/v1/users`); this application only renders
// it, so the type lives here rather than crossing the build boundary.

export type UserSummary = {
  user_id: string
  display_name: string
  role: string
  tier: string
  status: string
  agent_status: string
  channels: string[]
  last_activity_at: string
  auth_source?: 'local' | 'ldap'
}
