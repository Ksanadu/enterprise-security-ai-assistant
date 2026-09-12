import '@testing-library/jest-dom/vitest'

import { afterEach } from 'vitest'

import { clearAccessToken } from '../api/client'

// Ensure no test can leak an access token into another test.
afterEach(() => {
  clearAccessToken()
})
