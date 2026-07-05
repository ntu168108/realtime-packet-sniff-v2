import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/login');
  await page.fill('input[type="text"], input:not([type="password"]):not([type="checkbox"])', 'admin');
  await page.fill('input[type="password"]', 'sniff');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/);
});

test('services page lists 6 services with status pills', async ({ page }) => {
  await page.goto('/services');
  const cards = page.locator('.card:has(h2)');
  await expect(cards).toHaveCount(6);  // 6 allowlisted services
  await expect(page.locator('.pill').first()).toBeVisible();
});