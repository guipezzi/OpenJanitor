// Apache ECharts (D14), with only the parts the app draws, so the rest of
// the library stays out of the bundle. SVG rendering keeps charts sharp at
// any zoom.
import { PieChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { SVGRenderer } from 'echarts/renderers'

echarts.use([PieChart, TooltipComponent, SVGRenderer])

export type ECharts = echarts.ECharts

/** A chart of a fixed size in `element`. */
export function createChart(element: HTMLElement, size: number): ECharts {
  return echarts.init(element, undefined, { renderer: 'svg', width: size, height: size })
}
