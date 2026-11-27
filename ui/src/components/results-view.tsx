import { BrushCleaning, ListChecks, Shield, ShieldAlert, TriangleAlert } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { CleanDialog } from '@/components/clean-dialog'
import { DetailsPanel } from '@/components/details-panel'
import { ResultsTree } from '@/components/results-tree'
import { ScanSummary } from '@/components/scan-summary'
import { Button } from '@/components/ui/button'
import { planClean, type CleanPlan } from '@/lib/clean'
import { formatBytes } from '@/lib/format'
import { useNodeLabel } from '@/lib/labels'
import { protectItem } from '@/lib/protected'
import {
  couldNotRead,
  openRecycleBin,
  revealInExplorer,
  type NodeView,
  type ScanOverview,
} from '@/lib/scan'
import { recommended, tallyAll, toggle } from '@/lib/selection'
import { useResultsTree } from '@/lib/use-results-tree'

interface ResultsViewProps {
  overview: ScanOverview
  /** The results changed (something was protected). Same scan, same node ids. */
  onOverviewChange: (overview: ScanOverview) => void
  /** The user confirmed this cleanup. */
  onClean: (plan: CleanPlan) => void
  onScanAgain: () => void
}

/**
 * The results of one scan: the tree, the details panel, what's selected,
 * and the Clean button. Mount it with `key={overview.scan_id}`; a new
 * overview for the same scan (after protecting something) keeps the
 * selection.
 */
export function ResultsView({ overview, onOverviewChange, onClean, onScanAgain }: ResultsViewProps) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const label = useNodeLabel()
  const tree = useResultsTree(overview)
  const [choices, setChoices] = useState<ReadonlyMap<number, boolean>>(() => new Map())
  const [focused, setFocused] = useState<NodeView | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [protectError, setProtectError] = useState<string | null>(null)
  const [plan, setPlan] = useState<CleanPlan | null>(null)
  const [planning, setPlanning] = useState(false)
  const [planError, setPlanError] = useState<string | null>(null)
  const treeArea = useRef<HTMLDivElement>(null)

  // The focused item may be gone once the results change.
  const [shown, setShown] = useState(overview)
  if (shown !== overview) {
    setShown(overview)
    setFocused(null)
  }

  const { byNode, total } = useMemo(
    () => tallyAll(overview.categories, choices, tree.loaded),
    [overview.categories, choices, tree.loaded],
  )
  const rules = useMemo(
    () => new Map(overview.rules.map((rule) => [rule.rule_id, rule])),
    [overview.rules],
  )
  // A rule that needs admin rights and couldn't read its folders found
  // nothing because it couldn't look, not because there's nothing there.
  const listFormat = new Intl.ListFormat(locale, { type: 'conjunction' })
  const protectedRules = overview.rules
    .filter((rule) => rule.status === 'protected')
    .map((rule) => rule.name)
  const elsewhere = overview.rules
    .filter((rule) => rule.status === 'not_selected')
    .map((rule) => rule.name)
  const empty = overview.rules.filter(
    (rule) => rule.findings === 0 && rule.status !== 'protected' && rule.status !== 'not_selected',
  )
  const notChecked = empty.filter(couldNotRead).map((rule) => rule.name)
  const nothingFound = empty.filter((rule) => !couldNotRead(rule)).map((rule) => rule.name)

  // A category picked in the chart: show its details and take the keyboard
  // to its row in the tree.
  function pickCategory(id: number) {
    const category = overview.categories.find((node) => node.id === id)
    if (!category) return
    setFocused(category)
    const row = treeArea.current?.querySelector<HTMLElement>(`[data-node-id="${id}"] [data-row-name]`)
    row?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    row?.focus({ preventScroll: true })
  }

  async function protect(node: NodeView) {
    setNotice(null)
    setProtectError(null)
    try {
      const update = await protectItem(overview.scan_id, node.id)
      setNotice(t('results.protectedNotice', { name: label(node) }))
      if (update.overview) onOverviewChange(update.overview)
    } catch (cause) {
      setProtectError(t('results.protectError', { error: String(cause) }))
    }
  }

  // The Rust side resolves the choices against the full results, and checks
  // which apps are open; the dialog shows its numbers, not the footer's.
  // "Check again" in the dialog calls this too.
  async function review() {
    setPlanError(null)
    setPlanning(true)
    try {
      setPlan(await planClean(overview.scan_id, choices))
    } catch (cause) {
      setPlan(null)
      setPlanError(t('clean.planError', { error: String(cause) }))
    } finally {
      setPlanning(false)
    }
  }

  return (
    <div className="flex flex-1 flex-col space-y-4">
      <ScanSummary overview={overview} onPickCategory={pickCategory} />

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

      {notice && (
        <p className="flex gap-2 text-sm text-muted-foreground" role="status">
          <Shield className="mt-0.5 size-4 shrink-0 text-primary" />
          {notice}
        </p>
      )}
      {protectError && (
        <p className="flex gap-2 text-sm text-destructive" role="alert">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          {protectError}
        </p>
      )}

      <div ref={treeArea} className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
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
          onOpenRecycleBin={openRecycleBin}
          onProtect={(node) => void protect(node)}
        />
      </div>

      {notChecked.length > 0 && (
        <p className="flex gap-2 text-sm text-amber-700 dark:text-amber-400">
          <ShieldAlert className="mt-0.5 size-4 shrink-0" />
          {t('results.notChecked', { rules: listFormat.format(notChecked) })}
        </p>
      )}
      {nothingFound.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {t('results.alsoChecked', { rules: listFormat.format(nothingFound) })}
        </p>
      )}
      {elsewhere.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {t('results.notSelected', { rules: listFormat.format(elsewhere) })}
        </p>
      )}
      {protectedRules.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {t('results.protectedRules', { rules: listFormat.format(protectedRules) })}
        </p>
      )}

      {/* Pinned to the bottom of the window, whether the list is short or long. */}
      <div className="sticky bottom-0 -mx-6 mt-auto flex flex-wrap items-center gap-x-4 gap-y-1 border-t bg-background/95 px-6 py-3 backdrop-blur">
        <p className="text-sm font-medium tabular-nums" aria-live="polite">
          {total.files > 0
            ? t('results.selected', { count: total.files, size: formatBytes(total.size, locale) })
            : t('results.nothingSelected')}
        </p>
        {planError && (
          <p className="text-sm text-destructive" role="alert">
            {planError}
          </p>
        )}
        <Button className="ml-auto" onClick={review} disabled={total.files === 0 || planning}>
          <BrushCleaning />
          {t('clean.button')}
        </Button>
      </div>

      <CleanDialog
        plan={plan}
        onCancel={() => setPlan(null)}
        onConfirm={onClean}
        onScanAgain={onScanAgain}
        onRecheck={() => void review()}
        rechecking={planning}
      />
    </div>
  )
}
