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

/**
 * File types an operating system runs or opens as a program when they are
 * double-clicked. Saved through the browser's own downloads, they get its
 * protections, whatever the browser does for files written through the
 * save dialog: the downloaded-from-the-internet mark (Windows'
 * Mark-of-the-Web, macOS quarantine), and the checks that warn before
 * running one.
 */
const PROGRAM = /\.(?:exe|msi|msix|msixbundle|appx|appxbundle|com|scr|pif|cpl|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|url|scf|reg|msc|jar|app|dmg|pkg|mpkg|command|sh|bash|zsh|csh|run|bin|appimage|deb|rpm|apk|iso|img|vhd|vhdx|xll|docm|xlsm|pptm|application|gadget|inf|settingcontent-ms)$/i;

/** Whether a file of this name should go through the browser's downloads rather than straight to disk. */
export function isProgramFile(name: string): boolean {
  return PROGRAM.test(name);
}

/** A text/plain document cannot interpret paste content as HTML or script. */
export function openRawText(text: string): void {
  const { link } = localLink(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  link.target = '_blank';
  document.body.append(link);
  link.click();
  link.remove();
}
