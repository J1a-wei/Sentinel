export class ApiError extends Error { constructor(public status: number, public code: string) { super(code) } }
let credential = ''
export function setCredential(value: string) { credential = value }
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { ...options, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${credential}` }, signal: AbortSignal.timeout(20000), cache: 'no-store' })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: 'request_failed' }))
    throw new ApiError(response.status, body.error ?? 'request_failed')
  }
  return response.json() as Promise<T>
}
export interface Coverage { status: string; reason: string | null }
export interface Metrics {
  cpu_percent: number | null; memory_total_bytes: number | null; memory_available_bytes: number | null
  process_count: number | null; observed_at: string; received_at: string; quality: Record<string, Coverage>
  resource_summary: { interfaces?: Network[] }; scout_health?: { queue?: { pending_events: number; pending_bytes: number; overflow_count: number } }
}
export interface Asset { id: string; display_name: string; group_id: string; group_name: string; lifecycle: string; tags: Record<string, string>; metrics: Metrics | null; last_seen_at: string | null; scout_version: string | null; freshness: string; hostname: string | null; os_id: string | null; os_version: string | null }
export interface Group { id: string; name: string; description: string }
export interface Network { name: string; rx_bytes: number; tx_bytes: number; rx_bytes_per_second: number | null; tx_bytes_per_second: number | null }
export interface Collection { kind: string; latest_attempt: { id: string; status: string; coverage: Record<string, Coverage>; observed_at: string }; latest_complete: { id: string; observed_at: string } | null }
export interface Detail {
  asset: Asset; inventory: null | { hostname: string | null; os_id: string | null; os_version: string | null; kernel_version: string | null; architecture: string | null; cpu_model: string | null; logical_cpu_count: number | null; boot_id: string | null; interfaces: Network[] }
  collections: Collection[]; processes: { pid: number; start_ticks: number; name: string; state: string }[]
  ports: { protocol: string; address: string; port: number; network_namespace: string; loopback: boolean }[]
  packages: { name: string; version: string; architecture: string; source_name: string | null; source_version: string | null; origin: string }[]
  identity_conflicts?: { id: string; reason_code: string; detected_at: string; state: string }[]
}
