import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import vm from 'node:vm'

// The UI ships as browser IIFE globals (no module system). Load validate.js into
// a vm context; its top-level `var Validate = (function(){...})()` becomes a
// property of the contextified global.
const here = dirname(fileURLToPath(import.meta.url))
const code = readFileSync(resolve(here, '../html/js/validate.js'), 'utf8')
const ctx = {}
vm.createContext(ctx)
vm.runInContext(code, ctx)
const Validate = ctx.Validate

const G56 = 'G' + 'A'.repeat(55)

describe('Validate.stellarId', () => {
  it('accepts a 56-char id starting with G', () => {
    expect(Validate.stellarId(G56).valid).toBe(true)
  })
  it('rejects a missing value', () => {
    expect(Validate.stellarId('').valid).toBe(false)
  })
  it('rejects the wrong prefix', () => {
    expect(Validate.stellarId('A'.repeat(56)).valid).toBe(false)
  })
  it('rejects the wrong length', () => {
    expect(Validate.stellarId('GABC').valid).toBe(false)
  })
  it('rejects non-alphanumeric characters', () => {
    expect(Validate.stellarId('G' + '!'.repeat(55)).valid).toBe(false)
  })
})

describe('Validate.phone (E.164)', () => {
  it('accepts +1234567890', () => {
    expect(Validate.phone('+1234567890').valid).toBe(true)
  })
  it('rejects a number without +', () => {
    expect(Validate.phone('1234567890').valid).toBe(false)
  })
  it('rejects too-short numbers', () => {
    expect(Validate.phone('+12').valid).toBe(false)
  })
})

describe('Validate.email', () => {
  it('accepts a basic address', () => {
    expect(Validate.email('user@example.com').valid).toBe(true)
  })
  it('rejects a missing @', () => {
    expect(Validate.email('userexample.com').valid).toBe(false)
  })
  it('rejects a missing domain dot', () => {
    expect(Validate.email('user@example').valid).toBe(false)
  })
})

describe('Validate.hexString', () => {
  it('accepts even-length hex', () => {
    expect(Validate.hexString('deadbeef').valid).toBe(true)
  })
  it('rejects odd-length hex', () => {
    expect(Validate.hexString('abc').valid).toBe(false)
  })
  it('rejects non-hex characters', () => {
    expect(Validate.hexString('xyz0').valid).toBe(false)
  })
})

describe('Validate.required', () => {
  it('accepts a non-empty value', () => {
    expect(Validate.required('x').valid).toBe(true)
  })
  it('rejects whitespace-only', () => {
    expect(Validate.required('   ').valid).toBe(false)
  })
  it('rejects null', () => {
    expect(Validate.required(null).valid).toBe(false)
  })
})

describe('Validate.positiveNumber', () => {
  it('accepts a positive number', () => {
    expect(Validate.positiveNumber('5').valid).toBe(true)
  })
  it('rejects zero', () => {
    expect(Validate.positiveNumber('0').valid).toBe(false)
  })
  it('rejects non-numbers', () => {
    expect(Validate.positiveNumber('abc').valid).toBe(false)
  })
})

describe('Validate.totpCode', () => {
  it('accepts exactly 6 digits', () => {
    expect(Validate.totpCode('123456').valid).toBe(true)
  })
  it('rejects 5 digits', () => {
    expect(Validate.totpCode('12345').valid).toBe(false)
  })
  it('rejects non-digits', () => {
    expect(Validate.totpCode('12a456').valid).toBe(false)
  })
})

describe('Validate.firstError', () => {
  it('returns null when all valid', () => {
    expect(Validate.firstError([Validate.required('x'), Validate.email('a@b.co')])).toBeNull()
  })
  it('returns the first failure message', () => {
    const msg = Validate.firstError([Validate.required('x'), Validate.email('bad')])
    expect(msg).toBe('Invalid email address')
  })
})
