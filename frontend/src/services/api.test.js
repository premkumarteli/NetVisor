import { describe, it, expect, beforeEach } from 'vitest';
import api from './api';

describe('api service and interceptors', () => {
  let eventFired = false;
  let eventDetail = null;

  beforeEach(() => {
    eventFired = false;
    eventDetail = null;
    const handler = (e) => {
      eventFired = true;
      eventDetail = e.detail;
    };
    window.addEventListener('netvisor:auth-expired', handler);
    return () => {
      window.removeEventListener('netvisor:auth-expired', handler);
    };
  });

  it('triggers netvisor:auth-expired event on HTTP 401 response', async () => {
    // Find the error handler in the response interceptors
    const errorHandler = api.interceptors.response.handlers[0].rejected;

    const mockError = {
      response: {
        status: 401,
        data: { detail: 'Token expired' },
      },
    };

    await expect(errorHandler(mockError)).rejects.toEqual(mockError);
    expect(eventFired).toBe(true);
    expect(eventDetail?.status).toBe(401);
  });

  it('does NOT trigger netvisor:auth-expired event on HTTP 403 response', async () => {
    const errorHandler = api.interceptors.response.handlers[0].rejected;

    const mockError = {
      response: {
        status: 403,
        data: { detail: 'Organization Admin access required' },
      },
    };

    await expect(errorHandler(mockError)).rejects.toEqual(mockError);
    expect(eventFired).toBe(false);
  });

  it('passes successful responses through untouched', async () => {
    const successHandler = api.interceptors.response.handlers[0].fulfilled;
    const mockResponse = { status: 200, data: { ok: true } };

    const result = successHandler(mockResponse);
    expect(result).toBe(mockResponse);
  });
});
