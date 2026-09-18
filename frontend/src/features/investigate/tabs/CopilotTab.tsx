import { useRef, useState, type FormEvent } from 'react'
import type { CopilotAnswer, Investigation } from '@/types/api'
import { useAskCopilot } from '@/lib/queries'
import { Badge, Button, Input, Spinner } from '@/components/ui'
import { IconSparkle } from '@/components/ui/icons'
import { absoluteTime, titleise } from '@/lib/format'
import { cn } from '@/lib/utils'

const STARTERS = [
  'Why was this identity flagged?',
  'Is this a real threat or a false positive?',
  'What data could they have reached?',
  'Show me the timeline of the drift.',
  'How does this compare to their peers?',
  'Which MITRE techniques does this map to?',
  'What should I do right now?',
  'Are there approved change tickets covering this?',
  'What regulatory obligations does this trigger?',
  'How confident is the engine in this verdict?',
]

interface Turn {
  question: string
  answer?: CopilotAnswer
  error?: string
}

export function CopilotTab({ data }: { data: Investigation }) {
  const [turns, setTurns] = useState<Turn[]>([])
  const [draft, setDraft] = useState('')
  const ask = useAskCopilot()
  const endRef = useRef<HTMLDivElement>(null)

  const submit = async (question: string) => {
    const trimmed = question.trim()
    if (!trimmed || ask.isPending) return
    setDraft('')
    setTurns((prev) => [...prev, { question: trimmed }])

    try {
      const answer = await ask.mutateAsync({ identityId: data.identity.id, question: trimmed })
      setTurns((prev) => prev.map((t, i) => (i === prev.length - 1 ? { ...t, answer } : t)))
    } catch (error) {
      setTurns((prev) =>
        prev.map((t, i) =>
          i === prev.length - 1
            ? { ...t, error: error instanceof Error ? error.message : 'Request failed' }
            : t,
        ),
      )
    } finally {
      requestAnimationFrame(() => endRef.current?.scrollIntoView({ behavior: 'smooth' }))
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-4">
      <div className="lg:col-span-3">
        <div className="mb-4 rounded-lg border border-indigo-500/20 bg-indigo-500/5 px-4 py-3">
          <div className="flex items-start gap-2.5">
            <IconSparkle className="mt-0.5 size-4 shrink-0 text-indigo-300" />
            <div>
              <p className="text-xs font-medium text-indigo-200">Grounded, not generative</p>
              <p className="mt-0.5 text-[11px] leading-relaxed text-indigo-200/70">
                The copilot answers only from values the detection pipeline actually computed for{' '}
                <span className="font-mono">{data.identity.username}</span>, and cites the events
                behind each claim. Ask something it cannot ground and it will say so rather than
                speculate.
              </p>
            </div>
          </div>
        </div>

        <div className="min-h-64 space-y-4">
          {turns.length === 0 && (
            <div className="rounded-lg border border-dashed border-[--color-border] px-4 py-10 text-center">
              <p className="text-sm text-[--color-ink-muted]">Ask a question to begin.</p>
              <p className="mt-1 text-xs text-[--color-ink-faint]">
                Try one of the suggestions on the right.
              </p>
            </div>
          )}

          {turns.map((turn, i) => (
            <div key={i} className="space-y-2.5">
              <div className="flex justify-end">
                <p className="max-w-lg rounded-2xl rounded-br-sm bg-cyan-500/12 px-3.5 py-2 text-sm text-cyan-100">
                  {turn.question}
                </p>
              </div>

              {turn.answer ? (
                <AnswerCard answer={turn.answer} onFollowUp={submit} />
              ) : turn.error ? (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/8 px-3.5 py-2.5 text-xs text-rose-200">
                  {turn.error}
                </div>
              ) : (
                <div className="flex items-center gap-2 px-1 text-xs text-[--color-ink-muted]">
                  <Spinner className="size-3.5" />
                  Reading the evidence…
                </div>
              )}
            </div>
          ))}
          <div ref={endRef} />
        </div>

        <form
          className="mt-4 flex gap-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault()
            void submit(draft)
          }}
        >
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={`Ask about ${data.identity.username}…`}
            disabled={ask.isPending}
          />
          <Button type="submit" variant="primary" loading={ask.isPending} disabled={!draft.trim()}>
            Ask
          </Button>
        </form>
      </div>

      <aside>
        <p className="mb-2 text-[10px] font-semibold tracking-wider text-[--color-ink-faint] uppercase">
          Suggested questions
        </p>
        <div className="space-y-1.5">
          {STARTERS.map((question) => (
            <button
              key={question}
              onClick={() => void submit(question)}
              disabled={ask.isPending}
              className="w-full rounded-lg border border-[--color-border-subtle] px-3 py-2 text-left text-[11px] leading-snug text-[--color-ink-muted] transition-colors hover:border-[--color-border-strong] hover:text-[--color-ink] disabled:opacity-50"
            >
              {question}
            </button>
          ))}
        </div>
      </aside>
    </div>
  )
}

function AnswerCard({
  answer,
  onFollowUp,
}: {
  answer: CopilotAnswer
  onFollowUp: (question: string) => void
}) {
  return (
    <div className="rounded-2xl rounded-bl-sm border border-[--color-border-subtle] bg-[--color-surface-raised] p-4">
      <div className="mb-2.5 flex items-center gap-2">
        <Badge className="border-indigo-500/30 bg-indigo-500/10 text-indigo-300">
          {titleise(answer.intent)}
        </Badge>
        <span className="numeric text-[10px] text-[--color-ink-faint]">
          {answer.confidence.toFixed(0)}% confidence
        </span>
      </div>

      <div className="space-y-2 text-sm leading-relaxed text-[--color-ink-muted]">
        {answer.answer.split('\n').map((line, i) => {
          if (!line.trim()) return null
          if (line.trim().startsWith('- ')) {
            return (
              <div key={i} className="flex gap-2 pl-1">
                <span className="mt-2 size-1 shrink-0 rounded-full bg-[--color-ink-faint]" />
                <span dangerouslySetInnerHTML={{ __html: renderInline(line.replace(/^-\s*/, '')) }} />
              </div>
            )
          }
          if (/^\d+\.\s/.test(line.trim())) {
            return (
              <div key={i} className="pl-1" dangerouslySetInnerHTML={{ __html: renderInline(line) }} />
            )
          }
          return <p key={i} dangerouslySetInnerHTML={{ __html: renderInline(line) }} />
        })}
      </div>

      {answer.citations.length > 0 && (
        <div className="mt-3 border-t border-[--color-border-subtle] pt-2.5">
          <p className="mb-1.5 text-[10px] tracking-wider text-[--color-ink-faint] uppercase">
            Cited evidence
          </p>
          <ul className="space-y-1">
            {answer.citations.map((citation) => (
              <li key={citation.ref} className="flex items-center gap-2 text-[11px]">
                <span className="font-mono text-[--color-ink-faint]">
                  {citation.timestamp ? absoluteTime(citation.timestamp, 'dd MMM HH:mm') : citation.type}
                </span>
                <span className="truncate text-[--color-ink-muted]">{citation.label}</span>
                {citation.score !== undefined && (
                  <span className="numeric ml-auto shrink-0 text-[--color-ink-faint]">
                    {citation.score.toFixed(0)}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {answer.follow_ups.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5 border-t border-[--color-border-subtle] pt-2.5">
          {answer.follow_ups.map((question) => (
            <button
              key={question}
              onClick={() => onFollowUp(question)}
              className={cn(
                'rounded-full border border-[--color-border] px-2.5 py-1 text-[11px] text-[--color-ink-muted]',
                'transition-colors hover:border-cyan-400/40 hover:text-cyan-200',
              )}
            >
              {question}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

/** Bold/code/italic only, on server-generated text. */
function renderInline(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="font-semibold text-[--color-ink]">$1</strong>')
    .replace(/`(.+?)`/g, '<code class="rounded bg-white/8 px-1 py-0.5 font-mono text-[11px]">$1</code>')
    .replace(/_(.+?)_/g, '<em>$1</em>')
}
