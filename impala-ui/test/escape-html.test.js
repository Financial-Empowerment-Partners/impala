import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import vm from 'node:vm'

// Same IIFE-global loading pattern as validate.test.js: escape-html.js is
// string-replace based (no DOM), so it runs unmodified under node:vm.
const here = dirname(fileURLToPath(import.meta.url))
const code = readFileSync(resolve(here, '../html/js/escape-html.js'), 'utf8')
const ctx = {}
vm.createContext(ctx)
vm.runInContext(code, ctx)
const EscapeHtml = ctx.EscapeHtml

describe('EscapeHtml.escape', () => {
  it('escapes all five HTML metacharacters', () => {
    expect(EscapeHtml.escape('&<>"\'')).toBe('&amp;&lt;&gt;&quot;&#39;')
  })
  it('neutralizes a script tag', () => {
    expect(EscapeHtml.escape('<script>alert(1)</script>'))
      .toBe('&lt;script&gt;alert(1)&lt;/script&gt;')
  })
  it('neutralizes an img onerror payload', () => {
    const out = EscapeHtml.escape('<img src=x onerror=alert(1)>')
    expect(out).not.toContain('<')
    expect(out).not.toContain('>')
  })
  it('escapes ampersands first (no double-escaping artifacts)', () => {
    expect(EscapeHtml.escape('&lt;')).toBe('&amp;lt;')
  })
  it('is safe for double-quoted attribute values', () => {
    expect(EscapeHtml.escape('" onmouseover="alert(1)'))
      .toBe('&quot; onmouseover=&quot;alert(1)')
  })
  it('is safe for single-quoted attribute values', () => {
    expect(EscapeHtml.escape("' onclick='alert(1)"))
      .toBe('&#39; onclick=&#39;alert(1)')
  })
  it('passes plain text through unchanged', () => {
    expect(EscapeHtml.escape('plain text 123')).toBe('plain text 123')
  })
  it('returns empty string for null and undefined', () => {
    expect(EscapeHtml.escape(null)).toBe('')
    expect(EscapeHtml.escape(undefined)).toBe('')
  })
  it('stringifies non-string values', () => {
    expect(EscapeHtml.escape(42)).toBe('42')
    expect(EscapeHtml.escape(false)).toBe('false')
  })
})
