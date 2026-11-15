// The account endpoints, called directly rather than through the page client.
//
// They answer with a stable `code` (directory_unavailable, account_disabled, …) that
// the forms turn into a sentence; the generic client keeps only the message. The
// base comes from the host so no module spells a URL.

type AuthResponse = {
  access_token: string
  refresh_token?: string
  user_id: string
  display_name?: string
  role: string
  must_change_password?: boolean
}

type ErrorPayload = { error?: string; code?: string } | null

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return null
  }
}

export function authError(
  payload: ErrorPayload,
  status: number,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  switch (payload?.code) {
    case 'directory_unavailable':
      return t('errors.directoryUnavailable')
    case 'account_not_provisioned':
      return t('errors.accountNotProvisioned')
    case 'account_conflict':
      return t('errors.accountConflict')
    case 'account_disabled':
      return t('errors.accountDisabled')
  }
  return payload?.error ?? t('errors.loginFailed', { status })
}

/** signIn calls the token endpoint; the host's translator owns the wording. */
export async function signIn(
  base: string,
  email: string,
  password: string,
  t: (key: string, options?: Record<string, unknown>) => string,
): Promise<AuthResponse> {
  const response = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!response.ok) {
    throw new Error(authError((await readJson(response)) as ErrorPayload, response.status, t))
  }
  return (await response.json()) as AuthResponse
}

export async function registerAccount(
  base: string,
  input: { email: string; password: string; display_name?: string },
  t: (key: string, options?: Record<string, unknown>) => string,
): Promise<AuthResponse> {
  const response = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  if (!response.ok) {
    const payload = (await readJson(response)) as ErrorPayload
    throw new Error(payload?.error ?? t('errors.registerFailed', { status: response.status }))
  }
  return (await response.json()) as AuthResponse
}

export type { AuthResponse }
