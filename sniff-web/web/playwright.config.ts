import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  use: {
    baseURL: 'http://localhost:8000',
    headless: true,
  },
  webServer: {
    command: 'cd sniff-web && python3 -m uvicorn web_server:app --host 127.0.0.1 --port 8000',
    // Use /login (200) for readiness — /api/* requires auth so 401s before Playwright can sign in.
    url: 'http://localhost:8000/login',
    timeout: 30000,
    reuseExistingServer: !process.env.CI,
    env: {
      SNIFF_WEB_TEST: '1',
      SNIFF_WEB_TEST_USERNAME: 'admin',
      SNIFF_WEB_TEST_PASSWORD: 'sniff',
    },
  },
});