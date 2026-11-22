import { ListChecks } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { DetailsPanel } from '@/components/details-panel'
import { ResultsTree } from '@/components/results-tree'
import { Button } from '@/components/ui/button'
import { formatBytes } from '@/lib/format'
import { revealInExplorer, type NodeView, type ScanOverview } from '@/lib/scan'
import { recommended, tallyAll, toggle } from '@/lib/selection'
import { useResultsTree } from '@/lib/use-results-tree'

/**
 * The results of one scan: the tree, the details panel, and what's
 * selected. Mount it with `key={overview.scan_id}`.
 */
export function ResultsView({ overview }: { overview: ScanOverview }) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const tree = useResultsTree(overview)
  const [choices, setChoices] = useState<ReadonlyMap<number, boolean>>(() => new Map())
  const [focused, setFocused] = useState<NodeView | null>(null)

  const { byNode, total } = useMemo(
    () => tallyAll(overview.categories, choices, tree.loaded),
    [overview.categories, choices, tree.loaded],
  )
  const rules = useMemo(
    () => new Map(overview.rules.map((rule) => [rule.rule_id, rule])),
    [overview.rules],
  )
  const nothingFound = overview.rules.filter((rule) => rule.findings === 0).map((rule) => rule.name)

  return (
    <div className="flex flex-1 flex-col space-y-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Button variant="outline" onClick={() => setChoices(recommended(overview.categories))}>
          <ListChecks />
          {t('results.selectRecommended')}
        </Button>
        <Button variant="ghost" onClick={() => setChoices(new Map())} disabled={total.files === 0}>
          {t('results.clearSelection')}
        </Button>
        <p className="text-xs text-muted-foreground">{t('results.recommendedHint')}</p>
      </div>

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
        <ResultsTree
          rows={tree.rows}
          expanded={tree.expanded}
          tallies={byNode}
          focusedId={focused?.id ?? null}
          onToggleExpanded={tree.toggleExpanded}
          onToggleSelected={(node, current) =>
            setChoices(toggle(node, current, choices, tree.loaded))
          }
          onFocus={setFocused}
          onLoadMore={tree.loadMore}
        />
        <DetailsPanel
          className="lg:sticky lg:top-4"
          node={focused}
          rule={focused?.rule_id ? rules.get(focused.rule_id) : undefined}
          onReveal={(node) => revealInExplorer(overview.scan_id, node.id)}
        />
      </div>

      {nothingFound.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {t('results.alsoChecked', {
            rules: new Intl.ListFormat(locale, { type: 'conjunction' }).format(nothingFound),
          })}
        </p>
      )}

      {/* Pinned to the bottom of the window, whether the list is short or long. */}
      <div className="sticky bottom-0 -mx-6 mt-auto flex flex-wrap items-center gap-x-4 gap-y-1 border-t bg-background/95 px-6 py-3 backdrop-blur">
        <p className="text-sm font-medium tabular-nums" aria-live="polite">
          {total.files > 0
            ? t('results.selected', { count: total.files, size: formatBytes(total.size, locale) })
            : t('results.nothingSelected')}
        </p>
        <p className="ml-auto text-xs text-muted-foreground">{t('results.cleaningLater')}</p>
      </div>
    </div>
  )
}
