import { describe, it, expect } from 'vitest'
import { ADMIN_ROLES, isAdminRole, OPERATOR_ROLES, isOperatorRole, isAllowedRole } from '../utils/roles'

describe('roles', () => {
  it('ADMIN_ROLES contains expected roles', () => {
    expect(ADMIN_ROLES).toContain('org_admin')
    expect(ADMIN_ROLES).toContain('super_admin')
    expect(ADMIN_ROLES).toHaveLength(2)
  })

  it('isAdminRole returns true for admin roles', () => {
    expect(isAdminRole('org_admin')).toBe(true)
    expect(isAdminRole('super_admin')).toBe(true)
  })

  it('isAdminRole returns false for non-admin roles', () => {
    expect(isAdminRole('operator')).toBe(false)
    expect(isAdminRole('viewer')).toBe(false)
    expect(isAdminRole('')).toBe(false)
    expect(isAdminRole(undefined)).toBe(false)
  })

  it('OPERATOR_ROLES contains admin and operator roles', () => {
    expect(OPERATOR_ROLES).toContain('org_admin')
    expect(OPERATOR_ROLES).toContain('super_admin')
    expect(OPERATOR_ROLES).toContain('operator')
    expect(OPERATOR_ROLES).not.toContain('viewer')
  })

  it('isOperatorRole validates operator and admin roles correctly', () => {
    expect(isOperatorRole('org_admin')).toBe(true)
    expect(isOperatorRole('super_admin')).toBe(true)
    expect(isOperatorRole('operator')).toBe(true)
    expect(isOperatorRole('viewer')).toBe(false)
    expect(isOperatorRole(null)).toBe(false)
  })

  it('isAllowedRole checks permissions with role list', () => {
    expect(isAllowedRole('operator', ['operator', 'org_admin'])).toBe(true)
    expect(isAllowedRole('viewer', ['operator', 'org_admin'])).toBe(false)
    expect(isAllowedRole('viewer', null)).toBe(true)
    expect(isAllowedRole('viewer', [])).toBe(true)
  })
})
