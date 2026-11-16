// The site's navigation: one link per service in the top bar (a full-page
// menu on phones), the current service marked with a pill. On the home
// page the links also switch between creating a paste and a chat in place,
// with the address and the back button following.

import { el } from './dom.ts';

export type Service = 'paste' | 'chat';

/** The address that starts each service. */
const HOME: Record<Service, string> = { paste: '/', chat: '/chat' };

/** Which service a path belongs to, if any. */
export function serviceOf(path: string): Service | null {
  if (path === '/' || /^\/[pd]\//.test(path)) return 'paste';
  if (path === '/chat' || path.startsWith('/r/')) return 'chat';
  return null;
}

/**
 * Marks the current service in every menu. On its own start page the link
 * is the current page; on a paste or chat it marks the section.
 */
function mark(current: Service | null, path: string): void {
  for (const a of document.querySelectorAll<HTMLAnchorElement>('[data-nav]')) {
    const on = a.dataset['nav'] === current;
    if (!on) a.removeAttribute('aria-current');
    else a.setAttribute('aria-current', path === HOME[current] ? 'page' : 'true');
  }
}

/**
 * Sets up the menus. `switchTo`, given on the home page, shows a service's
 * form without loading a page.
 */
export function initNav(switchTo?: (service: Service) => void): void {
  const path = window.location.pathname;
  mark(serviceOf(path), path);

  // Phones: the links live in a full-page menu, a modal dialog (focus stays
  // in it, Escape closes it, the page behind is inert).
  const menu = el<HTMLDialogElement>('nav-overlay');
  const open = el<HTMLButtonElement>('nav-menu');
  open.addEventListener('click', () => {
    menu.showModal();
    open.setAttribute('aria-expanded', 'true');
    (menu.querySelector<HTMLElement>('[aria-current]') ?? menu.querySelector<HTMLElement>('[data-nav]'))?.focus();
  });
  menu.addEventListener('close', () => open.setAttribute('aria-expanded', 'false'));
  el('nav-close').addEventListener('click', () => menu.close());
  // Leaving phone width with the menu open closes it.
  window.matchMedia('(min-width: 768px)').addEventListener('change', (e) => { if (e.matches && menu.open) menu.close(); });

  for (const a of document.querySelectorAll<HTMLAnchorElement>('[data-nav]')) {
    a.addEventListener('click', (ev) => {
      const service = a.dataset['nav'] as Service;
      if (menu.open) menu.close();
      // On the home page, switch in place; elsewhere, follow the link.
      if (!switchTo || serviceOf(window.location.pathname) === null || ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button !== 0) return;
      if (window.location.pathname !== '/' && window.location.pathname !== '/chat') return;
      ev.preventDefault();
      if (window.location.pathname !== HOME[service]) history.pushState(null, '', HOME[service]);
      mark(service, HOME[service]);
      switchTo(service);
    });
  }
  if (switchTo) {
    window.addEventListener('popstate', () => {
      const service = serviceOf(window.location.pathname);
      if (!service || (window.location.pathname !== '/' && window.location.pathname !== '/chat')) return;
      mark(service, window.location.pathname);
      switchTo(service);
    });
  }
}
