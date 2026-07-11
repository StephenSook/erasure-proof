import { expect, test } from '@playwright/test'

// getClient() is a module singleton in mock mode, so an erasure done on /demo is still verifiable
// after client-side navigation to /proof. Full page reloads reset the singleton, so each test drives
// the loop then follows an in-app link rather than reloading.

test('the full erasure loop runs in the browser and the proof verifies', async ({ page }) => {
  await page.goto('/demo')

  // Autopilot drives all six stages: store -> leak -> envelope -> erase -> durability -> audit.
  await page.getByRole('button', { name: 'Autopilot' }).click()

  // The leak beat reconstructs the name from the embedding alone.
  await expect(page.getByText(/Stephen Sookra/).first()).toBeVisible({ timeout: 30_000 })

  // The retrieval beat: the similarity search finds the stored memory (stage 1), and the SAME
  // search after erasure finds nothing because the vector itself was destroyed.
  await expect(page.getByText(/found aaaaaaaa-/).first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(/0 rows: the vector no longer exists/)).toBeVisible({ timeout: 30_000 })

  // The audit beat: the agent role is denied the forbidden write (SQLSTATE 42501) and the
  // hash chain is intact.
  await expect(page.getByText('42501', { exact: true })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('intact').first()).toBeVisible()

  // The live decision-log timeline is present (mock: snapshot then the erasure row).
  await expect(page.getByText(/decision log, streamed as it grows/)).toBeVisible()

  // The console links straight to the erased subject's proof; follow it (client-side nav keeps the
  // mock singleton, so the proof exists).
  await page.getByRole('link', { name: /Verify this proof/ }).click()

  // WebCrypto verifies the ECDSA signature and the subject binding in the browser.
  await expect(page.getByText('SIGNATURE VERIFIED')).toBeVisible({ timeout: 15_000 })

  // The transparency panel: the erasure is a leaf of the signed tree, and the log is append-only.
  await expect(page.getByText(/leaf of tree size/)).toBeVisible({ timeout: 15_000 })
})

test('a wrong subject on the proof page is caught (replay guard)', async ({ page }) => {
  // Erase the mock subject first so a signed proof exists, then verify a DIFFERENT subject: the
  // signature is valid but the subject binding must fail.
  await page.goto('/demo')
  await page.getByRole('button', { name: 'Autopilot' }).click()
  await expect(page.getByText('42501', { exact: true })).toBeVisible({ timeout: 30_000 })

  await page.getByRole('link', { name: 'Verify', exact: true }).click()
  await page.getByPlaceholder(/subject id/i).fill('99999999-8888-4777-8666-555555555555')
  await page.getByRole('button', { name: 'Verify', exact: true }).click()

  // Valid signature, wrong subject: the page must NOT show a clean verified verdict.
  await expect(page.getByText(/WRONG SUBJECT|not found|no memory/i)).toBeVisible({ timeout: 15_000 })
})
