/**
 * Blob URLs stay local to the browser and never contain a server URL or key.
 * The URL lives a minute, long enough for the browser to start the download;
 * `revoke` ends it sooner (calling it again does nothing).
 */
function localLink(blob: Blob): { link: HTMLAnchorElement; revoke: () => void } {
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.rel = 'noopener noreferrer';
  let timer = 0;
  const revoke = () => {
    clearTimeout(timer);
    URL.revokeObjectURL(url);
  };
  timer = window.setTimeout(revoke, 60_000);
  return { link, revoke };
}

/** Offers the blob as a download; returns a function that frees it at once (e.g. when a chat ends). */
export function downloadBlob(blob: Blob, name: string): () => void {
  const { link, revoke } = localLink(blob);
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  return revoke;
}

/** A text/plain document cannot interpret paste content as HTML or script. */
export function openRawText(text: string): void {
  const { link } = localLink(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  link.target = '_blank';
  document.body.append(link);
  link.click();
  link.remove();
}
