import { describe, it, expect } from 'vitest'
import {
  formatByteCount, parseByteValue, formatPercent,
  getRiskTone, getStatusTone, formatBrowserLabel,
} from '../utils/presentation'

describe('formatByteCount', () => {
  it('formats bytes', () => expect(formatByteCount(512)).toBe('512 B'))
  it('formats KB', () => expect(formatByteCount(1536)).toBe('1.5 KB'))
  it('formats MB', () => expect(formatByteCount(5242880)).toBe('5.00 MB'))
  it('formats GB', () => expect(formatByteCount(2147483648)).toBe('2.00 GB'))
  it('handles zero', () => expect(formatByteCount(0)).toBe('0 B'))
  it('handles negative', () => expect(formatByteCount(-100)).toBe('0 B'))
  it('handles null', () => expect(formatByteCount(null)).toBe('0 B'))
})

describe('parseByteValue', () => {
  it('parses number directly', () => expect(parseByteValue(1024)).toBe(1024))
  it('parses "10 KB"', () => expect(parseByteValue('10 KB')).toBe(10240))
  it('parses "5 MB"', () => expect(parseByteValue('5 MB')).toBe(5242880))
  it('parses "1 GB"', () => expect(parseByteValue('1 GB')).toBe(1073741824))
  it('parses plain number string', () => expect(parseByteValue('2048')).toBe(2048))
  it('returns 0 for non-numeric', () => expect(parseByteValue('abc')).toBe(0))
  it('returns 0 for null', () => expect(parseByteValue(null)).toBe(0))
})

describe('formatPercent', () => {
  it('formats number', () => expect(formatPercent(75)).toBe('75%'))
  it('formats decimal', () => expect(formatPercent(33.7)).toBe('34%'))
  it('formats zero', () => expect(formatPercent(0)).toBe('0%'))
  it('handles null', () => expect(formatPercent(null)).toBe('0%'))
})

describe('getRiskTone', () => {
  it('returns danger for critical', () => expect(getRiskTone('critical')).toBe('danger'))
  it('returns danger for high', () => expect(getRiskTone('high')).toBe('danger'))
  it('returns warning for medium', () => expect(getRiskTone('medium')).toBe('warning'))
  it('returns success for low', () => expect(getRiskTone('low')).toBe('success'))
  it('returns success for null', () => expect(getRiskTone(null)).toBe('success'))
})

describe('getStatusTone', () => {
  it('returns success for online', () => expect(getStatusTone('online')).toBe('success'))
  it('returns success for running', () => expect(getStatusTone('running')).toBe('success'))
  it('returns warning for pending', () => expect(getStatusTone('pending')).toBe('warning'))
  it('returns warning for degraded', () => expect(getStatusTone('degraded')).toBe('warning'))
  it('returns danger for offline', () => expect(getStatusTone('offline')).toBe('danger'))
  it('returns danger for failed', () => expect(getStatusTone('failed')).toBe('danger'))
  it('returns neutral for unknown', () => expect(getStatusTone('something')).toBe('neutral'))
})

describe('formatBrowserLabel', () => {
  it('detects Edge from name', () => expect(formatBrowserLabel('Microsoft Edge')).toBe('Edge'))
  it('detects Chrome from name', () => expect(formatBrowserLabel('Google Chrome')).toBe('Chrome'))
  it('detects Firefox from name', () => expect(formatBrowserLabel('Firefox')).toBe('Firefox'))
  it('detects Safari from name', () => expect(formatBrowserLabel('Safari')).toBe('Safari'))
  it('returns raw name if unknown', () => expect(formatBrowserLabel('Brave')).toBe('Brave'))
  it('detects Chrome from process', () => expect(formatBrowserLabel('', 'chrome.exe')).toBe('Chrome'))
  it('detects Edge from process', () => expect(formatBrowserLabel('', 'msedge.exe')).toBe('Edge'))
  it('returns Browser for empty', () => expect(formatBrowserLabel('', '')).toBe('Browser'))
})
