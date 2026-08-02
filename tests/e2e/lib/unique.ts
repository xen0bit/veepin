// uniqueName returns a listener/profile name that cannot collide with the seed
// or with another test's entity. Listener names match ^[a-z0-9][a-z0-9-]{0,31}$,
// so the result is strictly lowercase hex/digits plus hyphens.
let counter = 0;

export function uniqueName(prefix: string): string {
  counter += 1;
  const suffix = Date.now().toString(36).slice(-4);
  return `${prefix}-${suffix}${counter}`;
}
