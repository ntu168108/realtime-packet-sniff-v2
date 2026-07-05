import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/login');
  await page.fill('input[type="text"], input:not([type="password"]):not([type="checkbox"])', 'admin');
  await page.fill('input[type="password"]', 'sniff');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/);
});

test('capture page loads with interface dropdown', async ({ page }) => {
  await page.goto('/capture');
  await expect(page.locator('select')).toBeVisible();
  await expect(page.locator('button:has-text("Start")')).toBeVisible();
});