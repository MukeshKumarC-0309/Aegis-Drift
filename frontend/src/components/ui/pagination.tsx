import { Button } from '@/components/ui'
import type { PageMeta } from '@/types/api'

export function Pagination({ meta, onPage }: { meta: PageMeta; onPage: (page: number) => void }) {
  if (meta.total_pages <= 1) return null

  const from = (meta.page - 1) * meta.page_size + 1
  const to = Math.min(meta.page * meta.page_size, meta.total)

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[--color-border-subtle] px-5 py-3">
      <p className="numeric text-xs text-[--color-ink-muted]">
        {from}–{to} of {meta.total}
      </p>
      <div className="flex items-center gap-1.5">
        <Button size="sm" disabled={!meta.has_previous} onClick={() => onPage(meta.page - 1)}>
          Previous
        </Button>
        <span className="numeric px-2 text-xs text-[--color-ink-muted]">
          {meta.page} / {meta.total_pages}
        </span>
        <Button size="sm" disabled={!meta.has_next} onClick={() => onPage(meta.page + 1)}>
          Next
        </Button>
      </div>
    </div>
  )
}
