/**
 * Deep-freeze the plain compiler-data graphs that may cross host boundaries.
 *
 * This deliberately accepts only arrays, ordinary objects and null-prototype
 * records. Inspect own property descriptors without reading getters, including
 * symbol-keyed properties. Shared references and cycles are handled without
 * recursion. Callers supply their established diagnostic codes so migrating to
 * this shared implementation does not change their public failure contracts.
 *
 * This is an ownership/immutability check, not a trust boundary against
 * malicious JavaScript in the same process.
 */
export function freezeCompilerDataGraph(root, errors) {
  const pending = [root];
  const seen = new WeakSet();
  while (pending.length > 0) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype && prototype !== Array.prototype) {
      throw new Error(errors.nonDataObject);
    }

    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!Object.hasOwn(descriptor, "value")) {
        throw new Error(errors.accessorForbidden);
      }
      if (typeof descriptor.value === "function") {
        throw new Error(errors.functionForbidden);
      }
      pending.push(descriptor.value);
    }
    Object.freeze(value);
  }
  return root;
}
