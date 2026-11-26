const test = require('node:test');
const assert = require('node:assert');
const { generateInvisibleId, hashInvisibleId, fingerprint, hashesEqual } = require('../src/invisible-id');

test('generated IDs are unique and high-entropy', () => {
  const ids = new Set(Array.from({ length: 1000 }, generateInvisibleId));
  assert.equal(ids.size, 1000);
  assert.ok([...ids][0].length > 80);
});
test('hash is deterministic, raw ID is never stored', () => {
  const id = generateInvisibleId();
  assert.equal(hashInvisibleId(id), hashInvisibleId(id));
  assert.notEqual(hashInvisibleId(id), id);
  assert.ok(!hashInvisibleId(id).includes(id.slice(0, 8)));
});
test('fingerprint reveals only 4 chars', () => {
  const fp = fingerprint(hashInvisibleId(generateInvisibleId()));
  assert.match(fp, /^••••-[0-9a-f]{4}$/);
});
test('constant-time compare', () => {
  const h = hashInvisibleId(generateInvisibleId());
  assert.ok(hashesEqual(h, h));
  assert.ok(!hashesEqual(h, hashInvisibleId(generateInvisibleId())));
});
