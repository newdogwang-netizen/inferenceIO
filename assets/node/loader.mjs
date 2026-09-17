/* ESM companion for the iorec Node.js preload. */
'use strict';

const OPENAI_WRAPPER_PREFIX = 'iorec-openai:';

export async function resolve(specifier, context, nextResolve) {
  if (specifier !== 'openai') return nextResolve(specifier, context);
  const resolved = await nextResolve(specifier, context);
  return {
    shortCircuit: true,
    url: `${OPENAI_WRAPPER_PREFIX}${encodeURIComponent(resolved.url)}`,
  };
}

export async function load(url, context, nextLoad) {
  if (!url.startsWith(OPENAI_WRAPPER_PREFIX)) return nextLoad(url, context);
  const original = decodeURIComponent(url.slice(OPENAI_WRAPPER_PREFIX.length));
  const specifier = JSON.stringify(original);
  return {
    format: 'module',
    shortCircuit: true,
    source: `
      import OriginalDefault, { OpenAI as OriginalOpenAI } from ${specifier};
      export * from ${specifier};
      const runtime = globalThis[Symbol.for('iorec.node.runtime.v1')];
      const wrap = runtime?.wrapOpenAIConstructor ?? ((value) => value);
      const WrappedDefault = wrap(OriginalDefault);
      const WrappedOpenAI = wrap(OriginalOpenAI);
      export { WrappedDefault as default, WrappedOpenAI as OpenAI };
    `,
  };
}
