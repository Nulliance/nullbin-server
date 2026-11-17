// Light/dark mode via Bootstrap's data-bs-theme attribute. The page always
// follows the system setting, and changes with it. The toggle switches the
// current page only: nothing is remembered, so the next page load follows
// the system again. (The stylesheet also follows the system on its own, so
// the first paint already matches before this script runs.)

import { setIcon } from './dom.ts';

type Theme = 'light' | 'dark';

/** Earlier versions remembered a manual choice here. It is no longer used. */
const LEGACY_STORAGE_KEY = 'nullbin-theme';

export function initTheme(): void {
  try {
    localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    // Storage blocked: there is nothing to clear.
  }
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const buttons = document.querySelectorAll<HTMLButtonElement>('#theme-toggle, #room-theme-toggle');
  const apply = (t: Theme) => {
    document.documentElement.setAttribute('data-bs-theme', t);
    // A toggle button: pressed means the dark theme is on.
    for (const button of buttons) {
      button.setAttribute('aria-pressed', String(t === 'dark'));
      button.title = t === 'dark' ? 'Dark theme is on' : 'Dark theme is off';
      setIcon(button, t === 'dark' ? 'sun' : 'moon');
    }
  };
  const system = (): Theme => (media.matches ? 'dark' : 'light');
  apply(system());
  // A change of the system setting wins over a toggle on this page.
  media.addEventListener('change', () => apply(system()));
  for (const button of buttons) button.addEventListener('click', () => {
    apply(document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark');
  });
}
