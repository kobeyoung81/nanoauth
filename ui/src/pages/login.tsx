import { useState, type FormEvent } from 'react'

import type { PageContext } from '../contract'
import { signIn } from '../lib/authApi'
import { KeyRound } from 'lucide-react'

export function LoginPage({ ctx }: { ctx: PageContext }) {
  const { t, ui, api, features, navigate, query } = ctx
  const { Card, CardContent, CardDescription, CardHeader, CardTitle, Button, Input, FormField } = ui
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const auth = await signIn(api.bases.auth, email, password, t)
      features.signIn({
        user_id: auth.user_id,
        role: auth.role,
        display_name: auth.display_name,
        must_change_password: auth.must_change_password,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
      })
      if (auth.must_change_password) {
        navigate('/change-password')
        return
      }
      navigate(query.next ?? '/agent')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('auth.loginFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4" data-auth-page="login">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" />
            {t('auth.signInTitle')}
          </CardTitle>
          <CardDescription>{t('auth.signInDescription')}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="flex flex-col gap-4">
            {error ? (
              <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </p>
            ) : null}
            <FormField label={t('auth.email')}>
              <Input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                required
                autoComplete="email"
                autoFocus
              />
            </FormField>
            <p className="text-xs text-muted-foreground">{t('auth.ldapHint')}</p>
            <FormField label={t('auth.password')}>
              <Input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                autoComplete="current-password"
              />
            </FormField>
            <Button type="submit" disabled={busy}>
              {busy ? t('auth.signingIn') : t('auth.signIn')}
            </Button>
            <p className="text-center text-sm text-muted-foreground">
              {t('auth.noAccount')}{' '}
              <button
                type="button"
                onClick={() => navigate('/register')}
                className="font-medium text-primary hover:underline"
              >
                {t('auth.register')}
              </button>
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
