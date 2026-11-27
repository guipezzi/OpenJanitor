import '@testing-library/jest-dom/vitest'

import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

import '@/i18n'

// jsdom doesn't lay pages out, so it has no scrolling.
Element.prototype.scrollIntoView = () => {}

afterEach(() => {
  cleanup()
})
