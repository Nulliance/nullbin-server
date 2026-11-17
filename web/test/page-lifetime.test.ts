import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { pageLifetime } from '../src/page-lifetime.ts';

function page(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const events = new EventTarget();
  let reloads = 0;
  Object.assign(events, { location: { reload: () => reloads++ } });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: events });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, 'window', previous);
    else Reflect.deleteProperty(globalThis, 'window');
  });
  return {
    transition: (type: string, persisted = false) => {
      const event = new Event(type);
      Object.defineProperty(event, 'persisted', { value: persisted });
      events.dispatchEvent(event);
    },
    reloads: () => reloads,
  };
}

test('page departure cancels pending work and clears secrets exactly once', (t) => {
  const p = page(t);
  const secret = new Uint8Array([1, 2, 3]);
  let clears = 0;
  const life = pageLifetime(() => { clears++; secret.fill(0); });
  assert.equal(life.active(), true);
  p.transition('pagehide', true);
  assert.equal(life.active(), false);
  assert.deepEqual(secret, new Uint8Array(3));
  p.transition('pagehide');
  assert.equal(clears, 1);
});

test('a cleared cached page reloads only after a persisted restoration', (t) => {
  const p = page(t);
  const life = pageLifetime(() => {});
  p.transition('pageshow', true);
  assert.equal(p.reloads(), 0, 'initial pageshow does not reload');
  p.transition('pagehide', true);
  p.transition('pageshow');
  assert.equal(p.reloads(), 0, 'ordinary pageshow does not reload');
  p.transition('pageshow', true);
  assert.equal(p.reloads(), 1);
  assert.equal(life.active(), false, 'restoring never revives cancelled work');
});

test('handoff removes old cleanup and restoration handlers', (t) => {
  const p = page(t);
  let clears = 0;
  const life = pageLifetime(() => clears++);
  life.finish();
  life.finish();
  assert.equal(life.active(), false);
  p.transition('pagehide', true);
  p.transition('pageshow', true);
  assert.equal(clears, 0, 'the new page owner alone handles departure');
  assert.equal(p.reloads(), 0);
});

test('finishing a departed lifetime removes its restoration handler', (t) => {
  const p = page(t);
  let clears = 0;
  const life = pageLifetime(() => clears++);
  p.transition('pagehide', true);
  life.finish();
  p.transition('pageshow', true);
  assert.equal(clears, 1);
  assert.equal(p.reloads(), 0);
});
