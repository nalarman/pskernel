import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { freezeCompilerDataGraph } from "./compiler-data-boundary.mjs";

const hash = (text) => createHash("sha256").update(text, "utf8").digest("hex");

const freezeCompilerData = root => freezeCompilerDataGraph(root, {
  nonDataObject: "PSC0_PREPARATION_NON_DATA_OBJECT",
  accessorForbidden: "PSC0_PREPARATION_ACCESSOR_FORBIDDEN",
  functionForbidden: "PSC0_PREPARATION_FUNCTION_FORBIDDEN",
});

function diagnosticJson(value) {
  return JSON.stringify(value, (_key, item) => {
    if (typeof item === "bigint") return item.toString();
    if (item !== null && typeof item === "object" && !Array.isArray(item)) {
      const tags = Object.getOwnPropertySymbols(item)
        .map((symbol) => item[symbol])
        .filter((tag) => typeof tag === "string");
      if (tags.length) return { ...item, $constructors: tags };
    }
    return item;
  });
}

function unwrapExcept(value, stage, sourcePath, timingsMs) {
  if (value !== null && typeof value === "object") {
    for (const symbol of Object.getOwnPropertySymbols(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, symbol);
      if (!Object.hasOwn(descriptor, "value")) {
        throw new Error("PSC0_PREPARATION_ACCESSOR_FORBIDDEN");
      }
      if (descriptor.value === "ok") return value.value;
      if (descriptor.value === "error") {
        // Cached parse failures cross the same ownership boundary as successes.
        // Freeze before diagnostics inspect the graph or a caller can mutate it.
        const freezeStarted = performance.now();
        try { freezeCompilerData(value); }
        finally { timingsMs.freeze += performance.now() - freezeStarted; }
        const error = new Error(
          "PSC0_PREPARATION_" + stage.toUpperCase() + "_FAILED" +
          (sourcePath ? ": " + sourcePath : "") + ": " + diagnosticJson(value.error),
        );
        error.stage = stage;
        error.sourcePath = sourcePath;
        error.compilerError = value.error;
        throw error;
      }
    }
  }
  throw new Error("PSC0_PREPARATION_" + stage.toUpperCase() + "_RESULT_SHAPE");
}

/**
 * Retain preparation values only inside the exact supplied compiler instance.
 * The caller must associate compilerSha256 with the bytes actually executed,
 * resolve/read the current ordered closure on every request. Returned prepared
 * data is deeply frozen before it can share cached declarations with a caller.
 * This helper does not load a compiler, persist
 * compiler objects, reuse provider acceptance, or certify generated artifacts.
 *
 * Reuse is deliberately conservative: a changed module invalidates the entire
 * following preparation suffix. Both the environment and accumulated ordered
 * declarations live in each opaque compiler checkpoint. Parsing may be reused
 * independently because the source kind, path and exact source text agree.
 *
 * The parsed LRU bounds entries and the UTF-8 bytes of their source texts. This
 * is not a hard AST-heap bound. Prefix checkpoints retain one current closure's
 * environment/declarations and source texts, with persistent graph sharing;
 * their heap size depends on the compiler and input and must be measured.
 */
export function createGeneratedPreparationSession(
  compiler,
  { compilerSha256, maxParsedEntries = 128, maxParsedSourceBytes = 8 * 1024 * 1024 } = {},
) {
  if (!/^[a-f0-9]{64}$/u.test(compilerSha256 ?? "")) {
    throw new Error("PSC0_PREPARATION_COMPILER_IDENTITY_REQUIRED");
  }
  if (!Number.isSafeInteger(maxParsedEntries) || maxParsedEntries < 1 ||
      !Number.isSafeInteger(maxParsedSourceBytes) || maxParsedSourceBytes < 1) {
    throw new Error("PSC0_PREPARATION_CACHE_BOUND");
  }
  for (const name of [
    "psCompilerParseSource",
    "psCompilerPreparationStart",
    "psCompilerPreparationStepParsed",
    "psCompilerPreparationFinish",
  ]) {
    if (typeof compiler?.[name] !== "function") {
      throw new Error("PSC0_PREPARATION_COMPILER_EXPORT_MISSING: " + name);
    }
  }
  if (!compiler.PsCompilerSourceKind ||
      !("lean" in compiler.PsCompilerSourceKind) ||
      !("proofScript" in compiler.PsCompilerSourceKind)) {
    throw new Error("PSC0_PREPARATION_SOURCE_KINDS_MISSING");
  }

  // Bounded LRU. Cached parse errors are context-independent just as successes
  // are; elaboration errors are never reused across preparation checkpoints.
  const parsed = new Map();
  let parsedSourceBytes = 0;
  let previous;

  function reset() {
    parsed.clear();
    parsedSourceBytes = 0;
    previous = undefined;
  }

  function prepare(kind, orderedSources) {
    const started = performance.now();
    if (kind !== "lean" && kind !== "proofScript") {
      throw new Error("PSC0_PREPARATION_SOURCE_KIND: " + kind);
    }
    if (!Array.isArray(orderedSources)) {
      throw new Error("PSC0_PREPARATION_ORDERED_SOURCES_REQUIRED");
    }
    const inputs = orderedSources.map((item) => {
      if (typeof item?.path !== "string" || !item.path ||
          typeof item.source !== "string") {
        throw new Error("PSC0_PREPARATION_SOURCE_INPUT");
      }
      return Object.freeze({
        path: item.path,
        source: item.source,
        sha256: hash(item.source),
        sourceBytes: Buffer.byteLength(item.source, "utf8"),
      });
    });
    const closureSha256 = hash(JSON.stringify({
      sourceKind: kind,
      modules: inputs.map(({ path, sha256 }) => ({ path, sha256 })),
    }));
    const sourceKind = compiler.PsCompilerSourceKind[kind];
    const stats = {
      prefixModules: 0,
      parseHits: 0,
      parseMisses: 0,
      parseEvictions: 0,
      parseUncachedModules: 0,
      preparedModules: 0,
      finishHit: false,
    };
    const timingsMs = {
      input: performance.now() - started,
      parse: 0,
      prepare: 0,
      finish: 0,
      freeze: 0,
      total: 0,
    };
    const receipt = () => Object.freeze({
      schemaVersion: 1,
      kind: "psc0-preparation-session",
      evidence: "admission-ready",
      compilerSha256,
      sourceKind: kind,
      closureSha256,
      moduleCount: inputs.length,
      cache: Object.freeze({
        ...stats,
        retainedParsedEntries: parsed.size,
        retainedParsedSourceBytes: parsedSourceBytes,
        retainedPrefixModules: previous?.inputs.length ?? 0,
        retainedPrefixSourceBytes: previous?.inputs.reduce((sum, item) => sum + item.sourceBytes, 0) ?? 0,
        maxParsedEntries,
        maxParsedSourceBytes,
      }),
      timingsMs: Object.freeze({ ...timingsMs, total: performance.now() - started }),
    });

    let prefix = 0;
    if (previous?.kind === kind) {
      while (prefix < inputs.length && prefix < previous.inputs.length &&
          inputs[prefix].path === previous.inputs[prefix].path &&
          inputs[prefix].source === previous.inputs[prefix].source) {
        prefix += 1;
      }
    }
    stats.prefixModules = prefix;

    if (previous?.kind === kind && previous.prepared !== undefined &&
        prefix === inputs.length && prefix === previous.inputs.length) {
      stats.finishHit = true;
      return Object.freeze({ prepared: previous.prepared, receipt: receipt() });
    }

    const states = previous?.kind === kind
      ? previous.states.slice(0, prefix + 1)
      : [compiler.psCompilerPreparationStart(sourceKind)];
    let completed = prefix;
    try {
      for (let index = prefix; index < inputs.length; index += 1) {
        const item = inputs[index];
        const key = JSON.stringify([kind, item.path, item.sha256]);
        let parsedSource = parsed.get(key);
        const parseStarted = performance.now();
        // Exact text comparison makes even a hash collision a recomputation.
        if (parsedSource && parsedSource.source === item.source) {
          stats.parseHits += 1;
          parsed.delete(key);
          parsed.set(key, parsedSource);
        } else {
          stats.parseMisses += 1;
          if (parsedSource) {
            parsed.delete(key);
            parsedSourceBytes -= parsedSource.sourceBytes;
          }
          parsedSource = {
            source: item.source,
            sourceBytes: item.sourceBytes,
            result: compiler.psCompilerParseSource(sourceKind, item.source),
          };
          if (item.sourceBytes <= maxParsedSourceBytes) {
            parsed.set(key, parsedSource);
            parsedSourceBytes += item.sourceBytes;
            while (parsed.size > maxParsedEntries || parsedSourceBytes > maxParsedSourceBytes) {
              const oldest = parsed.keys().next().value;
              parsedSourceBytes -= parsed.get(oldest).sourceBytes;
              parsed.delete(oldest);
              stats.parseEvictions += 1;
            }
          } else {
            stats.parseUncachedModules += 1;
          }
        }
        timingsMs.parse += performance.now() - parseStarted;
        const syntaxModule = unwrapExcept(parsedSource.result, "parse", item.path, timingsMs);
        const prepareStarted = performance.now();
        const result = compiler.psCompilerPreparationStepParsed(states[index], syntaxModule);
        timingsMs.prepare += performance.now() - prepareStarted;
        states.push(unwrapExcept(result, "elaborate", item.path, timingsMs));
        completed = index + 1;
        stats.preparedModules += 1;
      }
      const finishStarted = performance.now();
      const result = compiler.psCompilerPreparationFinish(states[inputs.length]);
      timingsMs.finish += performance.now() - finishStarted;
      const prepared = unwrapExcept(result, "finish", undefined, timingsMs);
      const freezeStarted = performance.now();
      freezeCompilerData(prepared);
      timingsMs.freeze += performance.now() - freezeStarted;
      previous = { kind, inputs, states, prepared };
      return Object.freeze({ prepared, receipt: receipt() });
    } catch (error) {
      // A failed new suffix must not leave a previous successful suffix reusable.
      previous = {
        kind,
        inputs: inputs.slice(0, completed),
        states: states.slice(0, completed + 1),
        prepared: undefined,
      };
      error.preparationReceipt = receipt();
      throw error;
    }
  }

  return Object.freeze({ compilerSha256, prepare, reset });
}
