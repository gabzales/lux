// Service worker minimal: hanya agar situs bisa dipasang sebagai aplikasi. Tidak menyimpan cache apa pun.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
