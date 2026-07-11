import { expect, test } from '@playwright/test'

// Motion ON (the default context has no reduced-motion): the scroll-triggered section reveals must
// end fully opaque and STAY there. This guards against the scrubbed-opacity regression where
// content that must be read got left mid-fade in the reading zone. (The a11y spec separately scans
// the reduced-motion path.)

test('landing sections reveal to full opacity on scroll (motion on)', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 })
  await page.goto('/')
  const sections = page.locator('.lp-section')
  const n = await sections.count()
  expect(n).toBeGreaterThan(0)
  for (let i = 0; i < n; i++) {
    await sections.nth(i).scrollIntoViewIfNeeded()
    const title = sections.nth(i).locator('.lp-section__title, .cta').first()
    // The triggered reveal runs ~0.6s; poll until it settles at full opacity.
    await expect
      .poll(() => title.evaluate((el) => Number(getComputedStyle(el).opacity)), { timeout: 4000 })
      .toBeGreaterThan(0.95)
  }
})
