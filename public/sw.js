/* The whole reason this file exists: Samsung's gallery does not answer the
 * intent a file input sends, so on those phones "מהגלריה" can never reach the
 * gallery. This inverts the direction — the soldier starts in the gallery,
 * taps שיתוף, picks מסייעת 951, and Android POSTs the photo here.
 *
 * It handles that one POST and nothing else. No offline cache, no asset
 * interception, no routing: a service worker that caches the app is a service
 * worker that can serve last week's app.js after a deploy, and this app changes
 * often enough for that to be a real hazard. Every request other than the share
 * POST falls through to the network untouched, exactly as if this file were not
 * installed.
 */
const SHARE_CACHE = 'tzayad-share-v1';
const SHARE_KEY = '/__shared-photo';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'POST' || url.pathname !== '/share-target') return;

  event.respondWith((async () => {
    const cache = await caches.open(SHARE_CACHE);
    /* Whatever was shared before has already been handed to the page or
       abandoned. Either way it is stale, and it is somebody's photograph. */
    await cache.delete(SHARE_KEY);

    try {
      const form = await event.request.formData();
      const file = form.get('photo');
      if (file && typeof file === 'object' && file.size > 0) {
        await cache.put(SHARE_KEY, new Response(file, {
          headers: {
            'content-type': file.type || 'application/octet-stream',
            'x-shared-name': encodeURIComponent(file.name || 'photo'),
          },
        }));
      }
    } catch {
      /* A share that cannot be read is a share the page will simply not find.
         Redirecting anyway is better than an error screen with no way back. */
    }

    return Response.redirect('/?shared=1#sign', 303);
  })());
});

/* The page asks for the photo and, once it has it, says so — the copy here is
   deleted the moment it is claimed rather than left sitting in a cache. */
self.addEventListener('message', (event) => {
  if (event.data === 'shared-photo-taken') {
    event.waitUntil(caches.open(SHARE_CACHE).then((c) => c.delete(SHARE_KEY)));
  }
});
