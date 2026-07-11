import { expect, test } from '@playwright/test'

// Real-stack E2E: no mocks anywhere in the path. The browser talks to the vite dev proxy, which
// forwards to the Go api, which talks to cryptod (real KMS envelope + ECDSA sign + S3 Object Lock,
// all against moto-server) and to CockroachDB. Every assertion below is backed by a real HTTP
// round trip, real SQL, and real crypto. The Modal GPU and Bedrock paths are not wired in CI, so
// the inversion beat serves its honest recorded golden run; everything else is live.

test('the whole loop runs against a live backend with zero mocks', async ({ page }) => {
  await page.goto('/demo')

  await page.getByRole('button', { name: 'Autopilot' }).click()

  // Store: the memory is ingested through the real /memories -> cryptod /prepare (real KMS
  // GenerateDataKey) path, and the C-SPANN similarity search finds it (distance ~0). Whether the
  // planner uses the vector index for a one-row table is cost-based (the controlled unit test
  // asserts index usage); here we assert the retrieval SEMANTICS, which are robust.
  await expect(page.getByText(/found [0-9a-f]{8}/).first()).toBeVisible({ timeout: 45_000 })

  // AS OF SYSTEM TIME: the panel inserts a throwaway wrapped-key row, DELETEs it, and reads it back
  // from the recent past, all live against the database. The leak stage (rendered by Autopilot)
  // hosts the panel.
  await page.getByRole('button', { name: /DELETE a row, then read it back/ }).click()
  await expect(page.getByText(/0 rows \("gone"\)/)).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText(/1 row, still fully readable/)).toBeVisible({ timeout: 20_000 })

  // Erase: the SERIALIZABLE destroy-and-retain transaction ran, the live vector was purged, and
  // the same similarity search now returns nothing.
  await expect(page.getByText(/0 rows: the vector no longer exists/)).toBeVisible({ timeout: 45_000 })

  // Audit: the agent role is denied the forbidden write with a real SQLSTATE 42501, and the
  // hash chain verifies intact over the real decision_log. Exact match: a random S3 proof-key hash
  // can contain "42501" as a substring, so only the sqlstate cell (=="42501") must match.
  await expect(page.getByText('42501', { exact: true })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('intact').first()).toBeVisible()

  // The proof was ECDSA-signed and anchored to the real (moto) S3 Object Lock bucket; the browser
  // verifies the signature and subject binding over the exact stored canonical bytes. A full
  // navigation works because the state lives in the database, not a client singleton.
  const proofLink = page.getByRole('link', { name: /Verify this proof/ })
  const href = await proofLink.getAttribute('href')
  expect(href).toBeTruthy()
  await page.goto(href!)
  await expect(page.getByText('SIGNATURE VERIFIED')).toBeVisible({ timeout: 20_000 })
})
