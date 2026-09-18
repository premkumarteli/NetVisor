import { describe, it, expect } from 'vitest'
import { formatUtcTimestampToLocal } from '../utils/time'

describe('formatUtcTimestampToLocal', () => {
  it('returns "Unknown" for null/undefined', () => {
    expect(formatUtcTimestampToLocal(null)).toBe('Unknown')
    expect(formatUtcTimestampToLocal(undefined)).toBe('Unknown')
  })

  it('returns "Unknown" for empty string', () => {
    expect(formatUtcTimestampToLocal('')).toBe('Unknown')
    expect(formatUtcTimestampToLocal('   ')).toBe('Unknown')
  })

  it('parses ISO timestamp with Z suffix', () => {
    const result = formatUtcTimestampToLocal('2026-01-15T10:30:00Z')
    expect(result).toContain('2026')
    expect(result).toContain('01')
    expect(result).toContain('15')
  })

  it('parses space-separated timestamp by appending Z', () => {
    const result = formatUtcTimestampToLocal('2026-06-13 12:00:00')
    expect(result).toContain('2026')
    expect(result).toContain('06')
    expect(result).toContain('13')
  })

  it('parses timestamp with timezone offset', () => {
    const result = formatUtcTimestampToLocal('2026-03-20T14:00:00+05:30')
    expect(result).not.toBe('Unknown')
  })

  it('returns raw string for invalid dates', () => {
    expect(formatUtcTimestampToLocal('not-a-date')).toBe('not-a-date')
  })
})
