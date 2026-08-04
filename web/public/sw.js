// Installability-only service worker: a pure network passthrough. Deliberately NO caching: the
// console shows live evidence (proofs, chain heads, agent verdicts), and a stale cached response
// on a trust surface would be worse than no PWA at all.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request))
})
