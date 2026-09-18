import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LoginPage from '../pages/LoginPage'

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ refreshUser: vi.fn(), user: null }),
}))

vi.mock('../services/api', () => ({
  authService: { login: vi.fn() },
}))

vi.mock('../components/V2/AuthSurface', () => ({
  default: ({ children }) => <div data-testid="auth-surface">{children}</div>,
}))

describe('LoginPage', () => {
  it('renders login form with username and password fields', () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    )
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('renders sign in button', () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    )
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('has default demo credentials pre-filled', () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    )
    expect(screen.getByLabelText(/username/i)).toHaveValue('admin')
    expect(screen.getByLabelText(/password/i)).toHaveValue('NetVisor!DemoAccess99')
  })
})
