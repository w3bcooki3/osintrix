// Playwright test setup. Run: npm install && npx playwright install chromium && npm test
const { defineConfig, devices } = require('@playwright/test');
const exe = process.env.CHROMIUM_PATH; // optional: point at an existing Chromium
module.exports = defineConfig({
  testDir: './tests',
  timeout: 60_000,
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: { trace: 'retain-on-failure', ...(exe ? { launchOptions: { executablePath: exe } } : {}) },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'phone', use: { ...devices['Pixel 5'] }, grep: /@phone/ },
  ],
});
