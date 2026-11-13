// The part of the portal's page contract this application uses.
//
// The portal's `portal/contract.ts` is the source of truth; this file is the same
// shape, written out so the two builds do not import each other. A field added
// there must be added here before a page may rely on it.

import type { ChangeEvent, ComponentType, ReactNode } from 'react'

type Children = { children?: ReactNode }

export type PortalUI = {
  Button: ComponentType<
    Children & {
      variant?: 'default' | 'outline' | 'ghost' | 'secondary' | 'destructive'
      size?: 'default' | 'sm' | 'lg' | 'icon'
      type?: 'button' | 'submit'
      className?: string
      disabled?: boolean
      title?: string
      onClick?: () => void
    }
  >
  Input: ComponentType<{
    type?: string
    value?: string
    placeholder?: string
    className?: string
    disabled?: boolean
    autoComplete?: string
    onChange?: (event: ChangeEvent<HTMLInputElement>) => void
  }>
  Card: ComponentType<Children & { className?: string }>
  CardHeader: ComponentType<Children & { className?: string }>
  CardTitle: ComponentType<Children & { className?: string }>
  CardDescription: ComponentType<Children & { className?: string }>
  CardContent: ComponentType<Children & { className?: string }>
  Badge: ComponentType<
    Children & {
      variant?: 'default' | 'secondary' | 'outline' | 'success' | 'warning' | 'danger' | 'info'
      className?: string
    }
  >
  Skeleton: ComponentType<{ className?: string }>
  EmptyState: ComponentType<{
    title: string
    description?: string
    icon?: ComponentType<{ className?: string }>
    action?: ReactNode
    className?: string
  }>
  Table: ComponentType<Children & { className?: string; stacked?: boolean }>
  TableHeader: ComponentType<Children & { className?: string }>
  TableBody: ComponentType<Children & { className?: string }>
  TableRow: ComponentType<
    Children & { className?: string; onClick?: () => void }
  >
  TableHead: ComponentType<Children & { className?: string }>
  TableCell: ComponentType<Children & { className?: string; label?: ReactNode }>
  Pagination: ComponentType<{
    page: number
    pageSize: number
    total: number
    onPageChange: (page: number) => void
    onPageSizeChange?: (size: number) => void
  }>
  StatusBadge: ComponentType<{ status: string; className?: string }>
  PageHeader: ComponentType<{
    title: ReactNode
    subtitle?: ReactNode
    actions?: ReactNode
    backTo?: string
    backLabel?: ReactNode
    className?: string
  }>
  FormField: ComponentType<Children & { label: string; hint?: string; error?: string; className?: string }>
  MetricCard: ComponentType<{
    icon: ComponentType<{ className?: string }>
    label: string
    value?: ReactNode
    sub?: ReactNode
    loading?: boolean
    className?: string
  }>
  Tooltip: ComponentType<Children & { delayDuration?: number }>
  TooltipTrigger: ComponentType<Children & { asChild?: boolean }>
  TooltipContent: ComponentType<Children & { className?: string; sideOffset?: number }>
  ConfirmDialog: ComponentType<{
    open: boolean
    onOpenChange: (open: boolean) => void
    title: string
    description?: string
    confirmLabel?: string
    onConfirm: () => Promise<void> | void
    busy?: boolean
  }>
  Select: ComponentType<{
    value: string
    onValueChange: (value: string) => void
    disabled?: boolean
    children?: ReactNode
  }>
  SelectTrigger: ComponentType<Children & { className?: string; disabled?: boolean }>
  SelectValue: ComponentType<{ placeholder?: string }>
  SelectContent: ComponentType<Children & { className?: string }>
  SelectItem: ComponentType<Children & { value: string; disabled?: boolean }>
}

export type PageContext = {
  token: string
  userId: string
  locale: string
  theme: 'light' | 'dark'
  navigate: (path: string) => void
  openPanel: (panelId: string) => void
  t: (key: string, options?: Record<string, unknown>) => string
  ui: PortalUI
  api: {
    get: <T>(path: string, base?: string) => Promise<T>
    post: <T>(path: string, body: unknown, base?: string) => Promise<T>
    patch: <T>(path: string, body: unknown, base?: string) => Promise<T>
    del: <T>(path: string, base?: string) => Promise<T>
    bases: { portalConsole: string; admin: string; user: string }
  }
  features: {
    openAgentForm: (request: { userId: string; agentId?: string; onSaved?: () => void }) => void
  }
  toast: {
    success: (message: string) => void
    error: (message: string) => void
  }
}

export type PageComponent = ComponentType<{ ctx: PageContext }>
