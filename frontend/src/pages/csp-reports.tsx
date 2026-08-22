import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Search, ShieldAlert } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import * as apiClient from "@/lib/api"
import type { CspReportEntry } from "@/lib/api"
import { cn } from "@/lib/utils"

const PAGE_SIZE = 50

function CspReportRow({ entry }: { entry: CspReportEntry }) {
  const [open, setOpen] = useState(false)
  
  const ts = new Date(entry.created_at)
  const timeStr = `${ts.getHours().toString().padStart(2, "0")}:${ts.getMinutes().toString().padStart(2, "0")}:${ts.getSeconds().toString().padStart(2, "0")}`
  const dateStr = `${ts.getFullYear()}-${(ts.getMonth() + 1).toString().padStart(2, "0")}-${ts.getDate().toString().padStart(2, "0")}`

  return (
    <li className={cn("group flex flex-col border-b border-hairline", open ? "bg-surface-elevated/30" : "")}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="grid grid-cols-1 gap-3 px-6 py-4 text-left hover:bg-surface-elevated/50 sm:grid-cols-[160px_220px_1fr_200px_32px] sm:items-center sm:gap-4 cursor-pointer transition-colors"
      >
        {/* Timestamp */}
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-body-sm text-ink">{timeStr}</span>
          <span className="font-mono text-[11px] text-mute">{dateStr}</span>
        </div>

        {/* Violated Directive */}
        <div className="flex items-center gap-2">
          <div className="flex size-6 shrink-0 items-center justify-center rounded-full bg-glow-orange border-glow-orange">
            <ShieldAlert className="size-3 text-accent-orange" />
          </div>
          <span className="truncate font-mono text-body-sm text-accent-orange" title={entry.violated_directive}>
            {entry.violated_directive}
          </span>
        </div>

        {/* Document URI & Blocked URI */}
        <div className="flex flex-col gap-1 min-w-0">
          <div className="truncate text-body-sm text-ink font-medium" title={entry.document_uri}>
            {entry.document_uri}
          </div>
          {entry.blocked_uri && (
            <div className="truncate font-mono text-caption text-charcoal flex items-center gap-1.5" title={entry.blocked_uri}>
              <span className="text-mute uppercase text-[9px] tracking-wider shrink-0">BLOCKED</span>
              <span>{entry.blocked_uri}</span>
            </div>
          )}
        </div>

        {/* Site Linkage */}
        <div className="flex flex-col gap-1 sm:items-end">
          {entry.site_name ? (
            <Badge variant="outline" className="w-fit text-cyan-400 border-cyan-400/30 bg-cyan-400/5">
              {entry.site_name}
            </Badge>
          ) : (
            <span className="text-caption text-mute italic">Unlinked origin</span>
          )}
        </div>

        {/* Expand toggle */}
        <div className="hidden items-center justify-end sm:flex">
          <div className={cn("flex size-6 items-center justify-center rounded-md transition-colors", open ? "bg-surface-deep text-ink" : "text-mute group-hover:text-charcoal")}>
            {open ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
          </div>
        </div>
      </button>

      {open && (
        <div className="border-t border-hairline/50 bg-surface-deep/30 px-6 py-5">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 max-w-[1200px]">
            {/* Raw JSON viewer */}
            <div className="lg:col-span-2">
              <h4 className="mb-3 font-mono text-[11px] uppercase tracking-wider text-mute">Full Report</h4>
              <div className="flex flex-col rounded-lg border border-hairline-strong bg-[#040407] overflow-hidden">
                <div className="flex h-9 items-center gap-1.5 border-b border-hairline bg-surface-deep px-4 select-none">
                  <span className="size-1.5 rounded-full bg-accent-red/80" />
                  <span className="size-1.5 rounded-full bg-accent-yellow/80" />
                  <span className="size-1.5 rounded-full bg-accent-green/80" />
                  <span className="ml-2 font-mono text-[9px] font-bold tracking-wider text-charcoal">
                    CSP_VIOLATION_PAYLOAD
                  </span>
                </div>
                <pre className="overflow-x-auto p-4 text-code-md text-body leading-relaxed font-mono scrollbar-thin">
                  <code className="font-mono text-code-md bg-surface-card px-1.5 py-0.5 rounded border border-hairline-strong">
                    {JSON.stringify(
                      {
                        document_uri: entry.document_uri,
                        violated_directive: entry.violated_directive,
                        effective_directive: entry.effective_directive,
                        blocked_uri: entry.blocked_uri,
                        source_file: entry.source_file,
                        line_number: entry.line_number,
                        column_number: entry.column_number,
                        status_code: entry.status_code,
                        user_agent: entry.user_agent,
                      },
                      null,
                      2
                    )}
                  </code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </li>
  )
}

export function CspReportsPage() {
  const [page, setPage] = useState(0)
  const [violatedDirective, setViolatedDirective] = useState("")

  const reports = useQuery({
    queryKey: ["csp_reports", { page, violatedDirective }],
    queryFn: () =>
      apiClient.listCspReports(
        page * PAGE_SIZE,
        PAGE_SIZE,
        undefined, // siteId not wired to a UI filter yet to keep it simple
        violatedDirective || undefined
      ),
  })

  const total = reports.data?.total ?? 0
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="relative">
      <div className="pointer-events-none absolute top-[-100px] left-1/2 h-[350px] w-full max-w-[800px] -translate-x-1/2 rounded-full opacity-5 blur-[140px] transition-all duration-1000 bg-glow-orange" />

      <div className="relative z-10 mb-8">
        <h1 className="text-display-lg text-ink">CSP Violations</h1>
        <p className="mt-2 text-body-md text-charcoal">
          Live Content-Security-Policy violation reports collected from browsers viewing monitored sites.
        </p>
      </div>

      <div className="relative z-20 mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-charcoal pointer-events-none" />
            <Input
              placeholder="Filter directive (e.g. script-src)"
              value={violatedDirective}
              onChange={(e) => {
                setViolatedDirective(e.target.value)
                setPage(0)
              }}
              className="pl-9 h-9 bg-surface-card border-hairline-strong text-ink placeholder:text-mute focus:border-ink rounded-md transition-colors font-mono"
            />
          </div>
        </div>
        
        <div className="text-body-sm text-charcoal font-mono bg-surface-deep px-3 py-1.5 rounded-full border border-hairline">
          Total logs: <span className="text-ink font-medium">{total}</span>
        </div>
      </div>

      <div className="relative z-10 rounded-lg border border-hairline-strong bg-surface-card shadow-sm overflow-hidden">
        {reports.data && reports.data.items.length > 0 && (
          <div className="hidden border-b border-hairline px-6 py-2.5 text-[10px] font-mono uppercase tracking-wider text-charcoal sm:grid sm:grid-cols-[160px_220px_1fr_200px_32px] sm:items-center sm:gap-4 bg-surface-deep/45">
            <span>Timestamp</span>
            <span>Directive</span>
            <span>Document & Blocked URI</span>
            <span className="text-right">Origin</span>
            <span></span>
          </div>
        )}

        {reports.isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <p className="font-mono text-body-sm text-mute animate-pulse">Loading reports...</p>
          </div>
        ) : reports.isError ? (
          <div className="flex h-40 items-center justify-center p-8 text-center">
            <p className="font-mono text-body-sm text-accent-red">
              Could not load CSP reports.
            </p>
          </div>
        ) : (reports.data?.items.length ?? 0) > 0 ? (
          <ul>
            {reports.data!.items.map((e) => (
              <CspReportRow key={e.id} entry={e} />
            ))}
          </ul>
        ) : (
          <div className="flex flex-col items-center gap-3 p-16 text-center">
            <div className="flex size-12 items-center justify-center rounded-full bg-surface-deep border border-hairline">
              <ShieldAlert className="size-5 text-charcoal" />
            </div>
            <p className="text-heading-sm text-ink mt-2">No violations recorded</p>
            <p className="max-w-sm text-body-sm text-charcoal">
              No CSP reports match the current filters.
            </p>
          </div>
        )}
      </div>

      {pageCount > 1 && (
        <div className="relative z-10 mt-4 flex items-center justify-end gap-3 font-mono">
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Newer entries"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="border border-hairline-strong bg-surface-card hover:bg-surface-elevated disabled:opacity-30 rounded-md"
          >
            <ChevronLeft className="size-4" />
          </Button>
          <span className="text-caption text-mute">
            {page + 1} / {pageCount}
          </span>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Older entries"
            disabled={page >= pageCount - 1}
            onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
            className="border border-hairline-strong bg-surface-card hover:bg-surface-elevated disabled:opacity-30 rounded-md"
          >
            <ChevronRight className="size-4" />
          </Button>
        </div>
      )}
    </div>
  )
}
