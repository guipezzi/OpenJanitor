import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { cssColor, formatShare, useThemeVersion, type Slice } from '@/lib/chart'
import type { ECharts } from '@/lib/echarts'
import { formatBytes } from '@/lib/format'
import { useCategoryName } from '@/lib/labels'

const SIZE = 120

interface CleanableChartProps {
  slices: Slice[]
  /** A category was picked, in the chart or its legend. */
  onPick: (id: number) => void
}

/**
 * The cleanable space by category (PLANNING.md section 7.8): a donut, and
 * beside it a legend that lists every slice with its size and share. The
 * legend is the readable, keyboard-reachable version; the chart adds the
 * picture and hover details.
 */
export function CleanableChart({ slices, onPick }: CleanableChartProps) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language
  const categoryName = useCategoryName()
  const element = useRef<HTMLDivElement>(null)
  const chart = useRef<ECharts | null>(null)
  const theme = useThemeVersion()
  const total = slices.reduce((sum, slice) => sum + slice.size, 0)
  const name = (slice: Slice) => (slice.category ? categoryName(slice.category) : t('chart.other'))
  // Kept in a ref so the chart's click handler always calls the latest one.
  const pick = useRef(onPick)
  useEffect(() => {
    pick.current = onPick
  }, [onPick])

  // ECharts loads on first use, so it doesn't slow the app's start.
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    let gone = false
    import('@/lib/echarts').then(
      ({ createChart }) => {
        if (gone || !element.current) return
        try {
          const created = createChart(element.current, SIZE)
          created.on('click', (event) => {
            const id = (event.data as { id?: number | null } | undefined)?.id
            if (typeof id === 'number') pick.current(id)
          })
          chart.current = created
          setLoaded(true)
        } catch {
          // Without a chart, the legend still says everything.
        }
      },
      () => {},
    )
    return () => {
      gone = true
      chart.current?.dispose()
      chart.current = null
    }
  }, [])

  useEffect(() => {
    chart.current?.setOption(
      {
        animationDuration: 300,
        tooltip: {
          trigger: 'item',
          confine: true,
          backgroundColor: cssColor('--chart-surface'),
          borderColor: cssColor('--chart-border'),
          textStyle: { color: cssColor('--chart-ink'), fontSize: 12, fontFamily: 'inherit' },
          formatter: (item: unknown) => {
            const { name: label, value, marker } = item as { name: string; value: number; marker: string }
            return `${marker}${escapeHtml(label)}<br/><b>${formatBytes(value, locale)}</b> · ${formatShare(value, total, locale)}`
          },
        },
        series: [
          {
            type: 'pie',
            radius: ['60%', '96%'],
            label: { show: false },
            labelLine: { show: false },
            // A 2px gap in the card's color between slices.
            itemStyle: { borderColor: cssColor('--chart-surface'), borderWidth: 2, borderRadius: 4 },
            emphasis: { scale: true, scaleSize: 3 },
            data: slices.map((slice) => ({
              id: slice.id,
              name: name(slice),
              value: slice.size,
              cursor: slice.id === null ? 'default' : 'pointer',
              itemStyle: { color: cssColor(slice.color) },
            })),
          },
        ],
      },
      { notMerge: true },
    )
    // `name` depends on the language, which `t` follows.
  }, [loaded, slices, total, locale, theme, t]) // eslint-disable-line react-hooks/exhaustive-deps

  // Pointing at a legend row lights up its slice.
  const highlight = (slice: Slice, on: boolean) =>
    chart.current?.dispatchAction({ type: on ? 'highlight' : 'downplay', seriesIndex: 0, name: name(slice) })

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
      {/* The legend below carries the same information for screen readers. */}
      <div ref={element} aria-hidden className="size-[120px] shrink-0" />
      <ul aria-label={t('chart.label')} className="grid min-w-60 flex-1 gap-0.5 text-sm">
        {slices.map((slice) => {
          const content = (
            <>
              <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: `var(${slice.color})` }} />
              <span className="min-w-0 flex-1 truncate">{name(slice)}</span>
              <span className="tabular-nums">{formatBytes(slice.size, locale)}</span>
              <span className="w-10 text-right text-muted-foreground tabular-nums">
                {formatShare(slice.size, total, locale)}
              </span>
            </>
          )
          const id = slice.id
          return (
            <li key={id ?? 'other'}>
              {id === null ? (
                <div className="flex items-center gap-2 px-1.5 py-0.5">{content}</div>
              ) : (
                <button
                  type="button"
                  title={t('chart.showInList')}
                  className="flex w-full items-center gap-2 rounded-md px-1.5 py-0.5 text-left outline-none hover:bg-muted/60 focus-visible:ring-2 focus-visible:ring-ring/50"
                  onClick={() => onPick(id)}
                  onMouseEnter={() => highlight(slice, true)}
                  onMouseLeave={() => highlight(slice, false)}
                  onFocus={() => highlight(slice, true)}
                  onBlur={() => highlight(slice, false)}
                >
                  {content}
                </button>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`)
}
