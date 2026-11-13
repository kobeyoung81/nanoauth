// Which row actions the account detail page offers for a container request.
//
// The queue's owner (the provisioner) owns the real rules: it only revives a
// disposed or failed request, and only restarts a running one. Asking the same
// question here keeps a button from showing next to a state the action would
// refuse with a 404. Statuses mirror `provisioner_container_requests.status`.

const LIVE_CONTAINER_STATUSES = new Set(['pending', 'creating', 'running', 'suspended'])
const REPROVISIONABLE_CONTAINER_STATUSES = new Set(['disposed', 'failed'])

/** Deprovision is offered while the container still occupies its slot. */
export function canDispose(status: string): boolean {
  return LIVE_CONTAINER_STATUSES.has(status)
}

/** In-place restart only makes sense for a running container. */
export function canRestart(status: string): boolean {
  return status === 'running'
}

/** Only a disposed or failed request can be revived. */
export function canReprovision(status: string): boolean {
  return REPROVISIONABLE_CONTAINER_STATUSES.has(status)
}
