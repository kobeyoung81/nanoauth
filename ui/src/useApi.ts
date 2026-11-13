// The smallest data hook a page needs, built on the context's client.
//
// The shell has a richer one; a page cannot import it, and this is all the account
// list asks for: a value, a loading flag, an error and a way to refetch.

import { useCallback, useEffect, useRef, useState } from 'react'
import type { PageContext } from './contract'

export function useApi<T>(api: PageContext['api'], path: string | null): {
  data: T | null
  loading: boolean
  error: string | null
  refetch: () => void
} {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(path !== null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  // The path and the client are read at request time, so a re-render caused by a
  // language change does not throw away the rows on screen.
  const latest = useRef({ api, path })
  latest.current = { api, path }

  useEffect(() => {
    if (path === null) {
      return
    }
    let alive = true
    setLoading(true)
    latest.current
      .api.get<T>(path)
      .then((value) => {
        if (alive) {
          setData(value)
          setError(null)
        }
      })
      .catch((failure: unknown) => {
        if (alive) {
          setError(failure instanceof Error ? failure.message : String(failure))
        }
      })
      .finally(() => {
        if (alive) {
          setLoading(false)
        }
      })
    return () => {
      alive = false
    }
  }, [path, attempt])

  const refetch = useCallback(() => setAttempt((value) => value + 1), [])
  return { data, loading, error, refetch }
}

/** useDebounce delays a fast-changing value; the account list filters as you type. */
export function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}
