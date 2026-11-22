import { describe, expect, it } from 'vitest'

import type { NodeView } from './scan'
import { checkState, recommended, tallyAll, toggle, type LoadedChildren } from './selection'

function node(id: number, files: number, size: number, extra: Partial<NodeView> = {}): NodeView {
  return {
    id,
    kind: 'folder',
    name: `node ${id}`,
    needs_admin: false,
    size_on_disk: size,
    file_count: files,
    last_modified: 0,
    has_children: files > 1,
    ...extra,
  }
}

// category 1 (10 files, 1000 B)
//   rule 2, low (6 files, 600 B)
//     folder 4 (4 files, 400 B)   <- its files are never loaded
//     file 5 (1 file, 150 B)
//     (one more file, 50 B, not loaded yet)
//   rule 3, medium (4 files, 400 B)
const rule2 = node(2, 6, 600, { kind: 'rule', risk: 'low' })
const rule3 = node(3, 4, 400, { kind: 'rule', risk: 'medium' })
const category = node(1, 10, 1000, { kind: 'category', children: [rule2, rule3] })
const folder4 = node(4, 4, 400)
const file5 = node(5, 1, 150, { kind: 'file' })

const children: LoadedChildren = new Map([
  [1, [rule2, rule3]],
  [2, [folder4, file5]],
])

describe('tallyAll', () => {
  it('selects nothing by default', () => {
    const { total } = tallyAll([category], new Map(), children)
    expect(total).toEqual({ files: 0, size: 0 })
  })

  it('counts children that were never loaded when their parent is selected', () => {
    const { byNode, total } = tallyAll([category], new Map([[2, true]]), children)
    expect(total).toEqual({ files: 6, size: 600 })
    expect(byNode.get(4)).toEqual({ files: 4, size: 400 })
    expect(byNode.get(3)).toEqual({ files: 0, size: 0 })
  })

  it('lets a choice inside override its parent', () => {
    const { byNode, total } = tallyAll(
      [category],
      new Map([
        [1, true],
        [4, false],
      ]),
      children,
    )
    expect(byNode.get(2)).toEqual({ files: 2, size: 200 })
    expect(total).toEqual({ files: 6, size: 600 })
  })
})

describe('checkState', () => {
  it('is partial when only some files inside are selected', () => {
    const choices = new Map([
      [2, true],
      [5, false],
    ])
    const { byNode } = tallyAll([category], choices, children)
    expect(checkState(rule2, byNode.get(2))).toBe('indeterminate')
    expect(checkState(category, byNode.get(1))).toBe('indeterminate')
    expect(checkState(folder4, byNode.get(4))).toBe(true)
    expect(checkState(rule3, byNode.get(3))).toBe(false)
  })
})

describe('toggle', () => {
  it('selects a partly selected node fully and drops the choices inside', () => {
    const choices = new Map([
      [2, true],
      [5, false],
    ])
    const next = toggle(category, 'indeterminate', choices, children)
    expect([...next]).toEqual([[1, true]])
    expect(tallyAll([category], next, children).total).toEqual({ files: 10, size: 1000 })
  })

  it('unselects a fully selected node', () => {
    const next = toggle(rule2, true, new Map([[2, true]]), children)
    expect(next.get(2)).toBe(false)
    expect(tallyAll([category], next, children).total.files).toBe(0)
  })

  it('leaves the original choices untouched', () => {
    const choices = new Map([[4, false]])
    toggle(category, false, choices, children)
    expect([...choices]).toEqual([[4, false]])
  })
})

describe('recommended', () => {
  it('selects the low-risk rules only', () => {
    const choices = recommended([category])
    expect([...choices]).toEqual([[2, true]])
    expect(tallyAll([category], choices, children).total).toEqual({ files: 6, size: 600 })
  })

  it('leaves out low-risk rules that opted out', () => {
    const bigCache = node(7, 5, 5000, { kind: 'rule', risk: 'low', recommended: false })
    const graphics = node(6, 5, 5000, { kind: 'category', children: [bigCache] })
    expect([...recommended([category, graphics])]).toEqual([[2, true]])
  })
})
