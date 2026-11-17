/** Cancel page-owned work on departure and reload a cached, cleared page. */
export function pageLifetime(clear: () => void): { active: () => boolean; finish: () => void } {
  let active = true;
  let left = false;
  const leave = () => {
    if (!active) return;
    active = false;
    left = true;
    clear();
  };
  const restore = (event: PageTransitionEvent) => {
    if (left && event.persisted) window.location.reload();
  };
  window.addEventListener('pagehide', leave);
  window.addEventListener('pageshow', restore);
  return {
    active: () => active,
    finish: () => {
      active = false;
      window.removeEventListener('pagehide', leave);
      window.removeEventListener('pageshow', restore);
    },
  };
}
