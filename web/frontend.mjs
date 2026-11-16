// Build-time settings for static hosting. Nothing here is supplied by the
// storage server. Keep the same baseline headers as internal/server.
export function parseAPIOrigin(value = '') {
  return parseOrigin(value, 'NULLBIN_API_ORIGIN', 'https://api.example.com');
}

// The website's own address, for link previews (Open Graph), which need an
// absolute image URL. Optional; without it the page has no preview image.
export function parseSiteOrigin(value = '') {
  return parseOrigin(value, 'NULLBIN_SITE_ORIGIN', 'https://paste.example.com');
}

function parseOrigin(value, name, example) {
  if (value === '') return '';
  let url;
  try { url = new URL(value); } catch { throw new Error(`${name} must be an HTTPS origin, such as ${example}`); }
  // Plain HTTP to this computer is for the browser tests only, and only when
  // they ask for it: a bundle built that way would send every visitor's
  // tokens to whatever listens on that port on their own computer.
  const local = process.env.NULLBIN_LOCAL_TEST_HTTP === '1' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      ![url.origin, `${url.origin}/`].includes(value) ||
      // Host names of letters, digits, dots and hyphens (and a port) only:
      // the origin goes into HTML attributes and headers, and characters
      // such as $ or ' could change what a replacement writes.
      !/^https?:\/\/(\[::1\]|[a-z0-9.-]+)(:[0-9]{1,5})?$/.test(url.origin)) {
    throw new Error(`${name} must be a canonical HTTPS origin without a path, credentials, query or fragment (HTTP to localhost is for the browser tests only, with NULLBIN_LOCAL_TEST_HTTP=1)`);
  }
  return url.origin;
}

export function contentSecurityPolicy(apiOrigin = '') {
  apiOrigin = parseAPIOrigin(apiOrigin);
  return "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
    `connect-src 'self'${apiOrigin ? ` ${apiOrigin}` : ''}; ` +
    "img-src 'self' blob: data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " +
    "require-trusted-types-for 'script'; trusted-types 'none'";
}

export function frontendHeaders(apiOrigin = '') {
  return {
    'Content-Security-Policy': contentSecurityPolicy(apiOrigin),
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'accelerometer=(), autoplay=(), browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()',
    'Strict-Transport-Security': 'max-age=31536000',
  };
}
