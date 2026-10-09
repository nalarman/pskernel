import assert from 'node:assert/strict';
import { test } from 'node:test';
import { freezeCompilerDataGraph } from './compiler-data-boundary.mjs';

const errors = {
  nonDataObject: 'NON_DATA_OBJECT',
  accessorForbidden: 'ACCESSOR_FORBIDDEN',
  functionForbidden: 'FUNCTION_FORBIDDEN',
};

test('freezes nested arrays, symbols, null-prototype data and shared cyclic graphs', () => {
  const inner = Object.assign(Object.create(null), { value: 1 });
  const symbol = Symbol('secret');
  const root = { child: [inner], [symbol]: inner };
  root.self = root;
  assert.equal(freezeCompilerDataGraph(root, errors), root);
  for (const value of [root, root.child, inner]) {
    assert.equal(Object.isFrozen(value), true);
  }
  assert.throws(() => { inner.value = 2; }, TypeError);
});

test('refuses unsupported prototypes without running conversion hooks', () => {
  class Foreign { constructor() { this.value = 1; } }
  assert.throws(() => freezeCompilerDataGraph(new Foreign(), errors), /NON_DATA_OBJECT/);
  assert.throws(() => freezeCompilerDataGraph(new Date(), errors), /NON_DATA_OBJECT/);
});

test('rejects own accessors without evaluating them', () => {
  let invoked = false;
  const value = {};
  Object.defineProperty(value, 'secret', {
    enumerable: true,
    get() { invoked = true; throw new Error('must not run'); },
  });
  assert.throws(() => freezeCompilerDataGraph(value, errors), /ACCESSOR_FORBIDDEN/);
  assert.equal(invoked, false);
});

test('rejects function-valued own fields, including symbol properties', () => {
  const key = Symbol('callable');
  assert.throws(() => freezeCompilerDataGraph({ [key]: () => 42 }, errors), /FUNCTION_FORBIDDEN/);
});

test('accepts primitives and null without wrapping or changing them', () => {
  for (const value of [null, undefined, 0, 1n, 'text', true]) {
    assert.equal(freezeCompilerDataGraph(value, errors), value);
  }
});
