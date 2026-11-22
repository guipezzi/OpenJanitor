// Selection in the results tree (PLANNING.md section 7.1).
//
// The tree loads lazily, so selection can't be a list of files: most of
// them were never sent to the UI. Instead it's a set of explicit choices
// ("this node: selected", "that node: not selected"). A node without a
// choice of its own follows its closest ancestor that has one; nodes with
// no such ancestor are not selected. Nothing is selected by default.
//
// The Clean button (a later PR) sends these choices to the Rust side,
// which resolves them against the full results.
import type { NodeView } from './scan'

/** Explicit choices, by node id. */
export type Choices = ReadonlyMap<number, boolean>

/** The children of each expanded node, as far as they have been loaded. */
export type LoadedChildren = ReadonlyMap<number, readonly NodeView[]>

export interface Tally {
  files: number
  size: number
}

export type CheckState = boolean | 'indeterminate'

const NOTHING: Tally = { files: 0, size: 0 }

/**
 * What's selected inside every loaded node, plus the grand total. One pass
 * over the loaded tree.
 */
export function tallyAll(
  roots: readonly NodeView[],
  choices: Choices,
  children: LoadedChildren,
): { byNode: Map<number, Tally>; total: Tally } {
  const byNode = new Map<number, Tally>()

  const visit = (node: NodeView, inherited: boolean): Tally => {
    const selected = choices.get(node.id) ?? inherited
    const loaded = children.get(node.id)
    let tally: Tally
    if (!loaded || loaded.length === 0) {
      tally = selected ? { files: node.file_count, size: node.size_on_disk } : NOTHING
    } else {
      let files = 0
      let size = 0
      let loadedFiles = 0
      let loadedSize = 0
      for (const child of loaded) {
        const inner = visit(child, selected)
        files += inner.files
        size += inner.size
        loadedFiles += child.file_count
        loadedSize += child.size_on_disk
      }
      // Children not loaded yet follow this node.
      if (selected) {
        files += node.file_count - loadedFiles
        size += node.size_on_disk - loadedSize
      }
      tally = { files, size }
    }
    byNode.set(node.id, tally)
    return tally
  }

  const total = { files: 0, size: 0 }
  for (const root of roots) {
    const tally = visit(root, false)
    total.files += tally.files
    total.size += tally.size
  }
  return { byNode, total }
}

/** Checked, unchecked, or partly checked, from what's selected inside. */
export function checkState(node: NodeView, tally: Tally | undefined): CheckState {
  const files = tally?.files ?? 0
  if (files === 0) return false
  if (files >= node.file_count) return true
  return 'indeterminate'
}

/**
 * Flips a node: a fully selected node becomes unselected, anything else
 * becomes fully selected. Choices made inside it are dropped, so
 * everything inside follows it again.
 */
export function toggle(
  node: NodeView,
  current: CheckState,
  choices: Choices,
  children: LoadedChildren,
): Map<number, boolean> {
  const next = new Map(choices)
  const pending = [...(children.get(node.id) ?? [])]
  while (pending.length > 0) {
    const child = pending.pop()!
    next.delete(child.id)
    pending.push(...(children.get(child.id) ?? []))
  }
  next.set(node.id, current !== true)
  return next
}

/** Whether "Select recommended" picks this rule: low risk (D17) and not opted out (D24). */
export function isRecommended(rule: NodeView): boolean {
  return rule.risk === 'low' && rule.recommended !== false
}

/** "Select recommended": exactly the recommended rules. */
export function recommended(categories: readonly NodeView[]): Map<number, boolean> {
  const choices = new Map<number, boolean>()
  for (const category of categories) {
    for (const rule of category.children ?? []) {
      if (isRecommended(rule)) choices.set(rule.id, true)
    }
  }
  return choices
}
