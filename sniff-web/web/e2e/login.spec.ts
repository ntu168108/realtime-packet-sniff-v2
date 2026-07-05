import { test, expect } from '@playwright/test';

test('login → dashboard', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login/);
  await page.fill('input[type="text"], input:not([type="password"]):not([type="checkbox"])', 'admin');
  await page.fill('input[type="password"]', 'sniff');
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL(/\/dashboard/);
});

test('wrong password shows error', async ({ page }) => {
  await page.goto('/login');
  await page.fill('input[type="text"], input:not([type="password"]):not([type="checkbox"])', 'admin');
  await page.fill('input[type="password"]', 'WRONG');
  await page.click('button[type="submit"]');
  await expect(page.locator('.error')).toBeVisible();
});