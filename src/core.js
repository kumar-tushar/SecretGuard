(() => {
  'use strict';
  const MAX_CHARACTERS = 100_000;
  const MAX_CUSTOM_FIELDS = 50;
  const MAX_DECODE_DEPTH = 3;
  const MAX_DECODE_CHARACTERS = 1_000_000;
  const MAX_COMPOSITE_CHECKS = 1_000_000;
  const ENCODING_TAGS = ['decoded:percent', 'decoded:hex', 'decoded:base64'];
  const MASK = 'xxxxxxxxxx';
  const CLIENT_ID_NAMES = ['client_id', 'client-id', 'client id', 'clientId'];
  const defaults = Object.freeze({ mode: 'redact', protectClientIds: true, sensitiveNames: [] });
  class ScanError extends Error {
    constructor() { super('This text could not be scanned. Keep it local and shorten it before retrying.'); }
  }
  let detector;

  function compileAllowlists(values = [], ruleIds) {
    return values.map(value => {
      const condition = value.condition ?? 'OR', target = value.regexTarget ?? 'secret';
      const targetRules = value.targetRules === undefined ? [] : value.targetRules;
      if (!['AND', 'OR'].includes(condition) || !['secret', 'match', 'line'].includes(target) ||
          !Array.isArray(targetRules) || targetRules.some(id => typeof id !== 'string' || !ruleIds?.has(id)) ||
          !Array.isArray(value.regexes) || !Array.isArray(value.stopwords) || !Array.isArray(value.paths) ||
          [...value.regexes, ...value.stopwords, ...value.paths].some(item => typeof item !== 'string') ||
          !value.regexes.length && !value.stopwords.length && !value.paths.length) throw new ScanError();
      return { condition, target, regexes: value.regexes.map(pattern => new RegExp(pattern)),
        stopwords: value.stopwords.map(word => word.toLowerCase()), hasPaths: value.paths.length > 0,
        targetRules: [...new Set(targetRules)] };
    });
  }

  function detectionRules() {
    if (detector) return detector;
    try {
      const source = globalThis.SecretShieldRules;
      if (!source || !Array.isArray(source.rules) || !source.rules.length) throw new ScanError();
      const ids = new Set();
      const rules = source.rules.map(rule => {
        const required = rule.required === undefined ? [] : rule.required;
        if (typeof rule.id !== 'string' || !rule.id || ids.has(rule.id) || typeof rule.regex !== 'string' ||
            rule.description !== undefined && (typeof rule.description !== 'string' || rule.description.length > 2048) ||
            rule.tags !== undefined && (!Array.isArray(rule.tags) || rule.tags.length > 64 ||
              rule.tags.some(tag => typeof tag !== 'string' || !tag || tag.length > 256)) ||
            !Number.isInteger(rule.secretGroup) || rule.secretGroup < 0 || !Number.isFinite(rule.entropy) || rule.entropy < 0 ||
            !Array.isArray(rule.keywords) || rule.keywords.some(word => typeof word !== 'string' || !word) ||
            rule.reuseBoundary !== undefined && typeof rule.reuseBoundary !== 'boolean' ||
            rule.skipReport !== undefined && typeof rule.skipReport !== 'boolean' || !Array.isArray(required) ||
            required.some(item => !item || typeof item !== 'object' || Array.isArray(item) || typeof item.id !== 'string' || !item.id ||
              ['withinLines', 'withinColumns'].some(key => item[key] !== undefined && (!Number.isSafeInteger(item[key]) || item[key] < 0)))) throw new ScanError();
        ids.add(rule.id);
        // Match Go's code-point quantifiers while retaining UTF-16 editor offsets.
        const regex = new RegExp(rule.regex, 'gdu');
        // Gitleaks group zero selects the first populated capture or the whole match.
        // Count captures without requiring a credential to match.
        const groupCount = new RegExp(`(?:${rule.regex})|`, 'u').exec('').length;
        if (groupCount <= rule.secretGroup || rule.maskGroup !== undefined &&
            (!Number.isInteger(rule.maskGroup) || rule.maskGroup < 0 || rule.maskGroup >= groupCount)) throw new ScanError();
        let command;
        if (rule.command !== undefined) {
          const { start, prefix, lineBreakGroups } = rule.command;
          if (typeof start !== 'string' || !start || typeof prefix !== 'string' || !prefix.startsWith(start) ||
              !rule.regex.startsWith(prefix) || prefix.length >= rule.regex.length ||
              !Number.isSafeInteger(lineBreakGroups) || lineBreakGroups < 0) throw new ScanError();
          // Dot already consumes CR in Go. Counting LF groups preserves the
          // accepted prefix without ambiguous CR/dot backtracking in JavaScript.
          const normalizedPrefix = `${start}[^\\n]*(?:\\n{1,2}[^\\n]*){0,${lineBreakGroups}}`;
          command = { start: new RegExp(start, 'gu'), tail: new RegExp(rule.regex.slice(prefix.length), 'gdu'),
            complete: new RegExp(`^(?:${normalizedPrefix}${rule.regex.slice(prefix.length)})(?![\\s\\S])`, 'du') };
        }
        return { ...rule, regex, command, tags: [...(rule.tags ?? [])], required: required.map(item => ({ ...item })),
          keywords: rule.keywords.map(word => word.toLowerCase()), allowlists: compileAllowlists(rule.allowlists) };
      });
      const byId = new Map(rules.map(rule => [rule.id, rule])), allowlists = [], auxiliaryIds = new Set();
      for (const rule of rules) for (const item of rule.required) {
        if (!ids.has(item.id)) throw new ScanError();
        auxiliaryIds.add(item.id);
      }
      for (const list of compileAllowlists(source.globalAllowlists, ids)) {
        // Shared targeted exclusions are local to their named rules, never global.
        if (list.targetRules.length) for (const id of list.targetRules) byId.get(id).allowlists.push(list);
        else allowlists.push(list);
      }
      detector = { rules, byId, allowlists, auxiliaryIds };
      return detector;
    } catch { throw new ScanError(); }
  }

  function* ruleMatches(rule, text) {
    if (!rule.command) {
      rule.regex.lastIndex = 0;
      let match;
      while ((match = rule.regex.exec(text)) !== null) {
        if (!match[0]) throw new ScanError();
        yield match;
        // A consumed trailing delimiter may also introduce the next value.
        // Reuse it only after the current secret, never inside that secret.
        if (rule.reuseBoundary) {
          const group = rule.secretGroup || Math.max(0, match.findIndex((value, index) => index > 0 && value));
          rule.regex.lastIndex = Math.max(match.index + 1, match.indices[group][1]);
        }
      }
      return;
    }
    const { start, tail, complete } = rule.command;
    start.lastIndex = tail.lastIndex = 0;
    let previous, next = start.exec(text), candidate;
    while ((candidate = tail.exec(text)) !== null) {
      if (!candidate[0]) throw new ScanError();
      // A delimiter can terminate one option and introduce the following one.
      tail.lastIndex = Math.max(candidate.index + 1, tail.lastIndex - 1);
      while (next && next.index < candidate.index) {
        if (!next[0]) throw new ScanError();
        previous = next; next = start.exec(text);
      }
      if (!previous) continue;
      // Anchor each option to the nearest command to avoid quadratic rescanning
      // and prevent a greedy prefix from hiding earlier authentication options.
      const match = complete.exec(text.slice(previous.index, candidate.index + candidate[0].length));
      if (!match) continue;
      match.index += previous.index;
      for (const bounds of match.indices) if (bounds) { bounds[0] += previous.index; bounds[1] += previous.index; }
      yield match;
    }
  }

  function entropy(value) {
    const counts = new Map();
    let length = 0;
    for (const char of value) {
      counts.set(char, (counts.get(char) ?? 0) + 1);
      const point = char.codePointAt(0);
      length += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
    }
    // Gitleaks counts runes but divides by UTF-8 byte length, including case folds.
    let result = 0;
    for (const count of counts.values()) { const frequency = count / length; result -= frequency * Math.log2(frequency); }
    return result;
  }

  function allowed(allowlists, secret, match, line) {
    const lower = secret.toLowerCase();
    return allowlists.some(list => {
      const checks = [];
      // A prompt has no path, so an AND exclusion requiring one cannot match.
      if (list.hasPaths && list.condition === 'AND') checks.push(false);
      if (list.regexes.length) checks.push(list.regexes.some(regex => regex.test(list.target === 'line' ? line : list.target === 'match' ? match : secret)));
      if (list.stopwords.length) checks.push(list.stopwords.some(word => lower.includes(word)));
      return checks.length > 0 && (list.condition === 'AND' ? checks.every(Boolean) : checks.some(Boolean));
    });
  }

  function normalizePolicy(value = {}) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ScanError();
    const mode = value.mode ?? defaults.mode;
    if (!['redact', 'block'].includes(mode)) throw new ScanError();
    if (value.protectClientIds !== undefined && typeof value.protectClientIds !== 'boolean') throw new ScanError();
    const sensitiveNames = value.sensitiveNames ?? [];
    if (!Array.isArray(sensitiveNames) || sensitiveNames.length > MAX_CUSTOM_FIELDS ||
        sensitiveNames.some(name => typeof name !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_ -]{1,63}$/.test(name))) {
      throw new ScanError();
    }
    return { mode, protectClientIds: value.protectClientIds ?? true, sensitiveNames: [...new Set(sensitiveNames)] };
  }

  function assignmentFindings(text, names, type) {
    if (!names.length) return [];
    const labels = [...names].sort((a, b) => b.length - a.length)
      .map(name => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    const assignments = new RegExp(`(?<![\\p{L}\\p{N}\\p{M}_$-])(?:(['"\x60])(?:${labels})\\1|(?:${labels}))[\\t \\u00a0]*(?:=(?!=|>)|:(?![:=]))[\\t \\u00a0]*`, 'giu');
    const findings = [];
    while (assignments.exec(text) !== null) {
      let start = assignments.lastIndex;
      // Only an explicit assignment can continue onto the immediately next line.
      if (text[start] === '\r' || text[start] === '\n') {
        start += text[start] === '\r' && text[start + 1] === '\n' ? 2 : 1;
        while (/[\t \u00a0]/.test(text[start] ?? '')) start++;
        if (/^(?:(['"`])[a-zA-Z][a-zA-Z0-9_ .-]*\1[\t ]*|[a-zA-Z][a-zA-Z0-9_ .\t-]*)[:=]/.test(text.slice(start))) continue;
      }
      if (start >= text.length || /[\r\n\u2028\u2029]/.test(text[start]) ||
          '{}[](),;=<>#'.includes(text[start]) || text.startsWith('//', start) || text.startsWith('${', start)) continue;
      const quote = text[start], quoted = ['"', "'", '`'].includes(quote);
      let end = start;
      if (quoted) {
        start++;
        end = start;
        while (end < text.length && text[end] !== quote) {
          end += text[end] === '\\' ? 2 : 1;
        }
        // Block incomplete quoted values rather than masking only a prefix.
        if (end >= text.length) throw new ScanError();
        assignments.lastIndex = end + 1;
      } else {
        while (end < text.length && !/[\s,;\]}>"'`]/u.test(text[end])) end++;
        assignments.lastIndex = end;
      }
      const value = text.slice(start, end);
      if (!value.trim() || /^x{5,}$/i.test(value) || /^(?:\[REDACTED\]|<[^<>\r\n]+>|\$\{[\w.]+\}|\{\{[\w. ]+\}\})$/i.test(value) ||
          quote === '`' && value.includes('${') ||
          !quoted && /^(?:null|undefined|true|false|\$[a-zA-Z_][\w]*)$/.test(value)) continue;
      findings.push({ start, end, type });
    }
    return findings;
  }

  function decodeBase64(value, budget) {
    const length = value.replace(/=+$/, '').length, padding = value.length - length;
    if (length % 4 === 1 || padding && (value.length % 4 || padding !== (4 - length % 4) % 4) ||
        /[+/]/.test(value) && /[-_]/.test(value)) return null;
    let bits = 0, pending = 0, decoded = '';
    for (let i = 0; i < length; i++) {
      const code = value.charCodeAt(i);
      const digit = code >= 65 && code <= 90 ? code - 65 : code >= 97 && code <= 122 ? code - 71 :
        code >= 48 && code <= 57 ? code + 4 : code === 43 || code === 45 ? 62 : 63;
      pending = pending << 6 | digit;
      bits += 6;
      if (bits < 8) continue;
      bits -= 8;
      const byte = pending >> bits;
      // Match upstream's ASCII scope; arbitrary binary/UTF-8 is not text.
      if (byte < 9 || byte > 126) return null;
      if (budget.remaining-- <= 0) throw new ScanError();
      decoded += String.fromCharCode(byte);
      pending &= (1 << bits) - 1;
    }
    // Reject noncanonical unused bits instead of accepting a partial value.
    return pending ? null : decoded;
  }

  function decodePercent(value, budget) {
    const escapes = /%[0-9A-Fa-f]{2}/g;
    let output = '', cursor = 0, match;
    while ((match = escapes.exec(value)) !== null) {
      const byte = Number.parseInt(match[0].slice(1), 16);
      if (byte < 9 || byte > 126) return null;
      if (budget.remaining-- <= 0) throw new ScanError();
      output += value.slice(cursor, match.index) + String.fromCharCode(byte);
      cursor = escapes.lastIndex;
    }
    return output + value.slice(cursor);
  }

  function decodeHex(value, budget) {
    if (value.length % 2) return null;
    let output = '';
    for (let i = 0; i < value.length; i += 2) {
      const byte = Number.parseInt(value.slice(i, i + 2), 16);
      if (byte < 9 || byte > 126) return null;
      if (budget.remaining-- <= 0) throw new ScanError();
      output += String.fromCharCode(byte);
    }
    return output;
  }

  function decodePass(text, budget) {
    // Percent candidates span the first through last valid escape on a line,
    // as upstream does. Precedence is percent, hex, then Base64.
    const candidates = /(%[0-9A-Fa-f]{2}(?:[^\n]*%[0-9A-Fa-f]{2})?)|([0-9A-Fa-f]{32,})|[A-Za-z0-9+/_-]{16,}={0,2}/g, segments = [];
    let output = '', cursor = 0, match;
    while ((match = candidates.exec(text)) !== null) {
      const percent = match[1] !== undefined, hex = match[2] !== undefined;
      if (!percent && !hex && text[candidates.lastIndex] === '=') continue;
      const decoded = percent ? decodePercent(match[0], budget) : hex ? decodeHex(match[0], budget) : decodeBase64(match[0], budget);
      if (decoded === null) continue;
      output += text.slice(cursor, match.index);
      segments.push({ start: output.length, end: output.length + decoded.length,
        originalStart: match.index, originalEnd: candidates.lastIndex,
        tag: percent ? 'decoded:percent' : hex ? 'decoded:hex' : 'decoded:base64' });
      output += decoded;
      cursor = candidates.lastIndex;
    }
    return { text: output + text.slice(cursor), segments };
  }

  function originalOffset(offset, segments, end) {
    // Locate the endpoint's segment in logarithmic time, then expand its bounds.
    let low = 0, high = segments.length;
    while (low < high) {
      const middle = low + high >> 1;
      if (segments[middle].start < offset || !end && segments[middle].start === offset) low = middle + 1;
      else high = middle;
    }
    const segment = segments[low - 1];
    if (!segment) return offset;
    if (offset < segment.end || end && offset === segment.end) return end ? segment.originalEnd : segment.originalStart;
    return offset + segment.originalEnd - segment.end;
  }

  function findingTags(tags) {
    const encodings = ENCODING_TAGS.filter(tag => tags.includes(tag));
    const depth = Math.max(0, ...tags.filter(tag => tag.startsWith('decode-depth:')).map(tag => Number(tag.slice(13))));
    return [...encodings, `decode-depth:${depth}`];
  }

  function matchLocations(text, starts) {
    const locations = new Map();
    let index = 0, bytes = 0, line = 0, lastNewline = 0;
    for (const start of [...new Set(starts)].sort((a, b) => a - b)) {
      while (index < start) {
        const point = text.codePointAt(index);
        if (point === 10) { line++; lastNewline = bytes; }
        bytes += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
        index += point > 0xffff ? 2 : 1;
      }
      // Gitleaks measures byte columns from the preceding LF itself, and a
      // match starting on LF belongs to the following line at column one.
      locations.set(start, text[start] === '\n' ? { line: line + 1, column: 1 } : { line, column: bytes - lastNewline + 1 });
    }
    return locations;
  }

  function findingLocations(text, findings) {
    let index = 0, line = 1, column = 1, lastLine = 1, lastColumn = 1;
    const advance = end => {
      while (index < end) {
        const point = text.codePointAt(index), width = point > 0xffff ? 2 : 1;
        if (index + width > end) throw new ScanError();
        lastLine = line;
        if (point === 10) { lastColumn = column; line++; column = 1; }
        else {
          column += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
          lastColumn = column - 1;
        }
        index += width;
      }
    };
    return findings.map(({ start, end }) => {
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < index || end <= start || end > text.length) throw new ScanError();
      advance(start);
      const startLine = line, startColumn = column;
      advance(end);
      return { startLine, startColumn, endLine: lastLine, endColumn: lastColumn };
    });
  }

  function proximityWindow(items, key, center, distance) {
    const bound = value => {
      let low = 0, high = items.length;
      while (low < high) {
        const middle = low + high >> 1;
        if (items[middle][key] < value) low = middle + 1;
        else high = middle;
      }
      return low;
    };
    return [bound(center - distance), bound(center + distance + 1)];
  }

  function compositeFindings(pending, matches, original, budget) {
    const located = pending.some(item => item.rule.required.some(required => required.withinLines !== undefined || required.withinColumns !== undefined));
    const locations = located ? matchLocations(original, [...pending.map(item => item.point), ...[...matches.values()].flat()]) : null;
    const indexes = new Map();
    for (const [id, points] of matches) {
      const items = locations ? points.map(point => locations.get(point)) : points;
      indexes.set(id, locations ? { items, line: [...items].sort((a, b) => a.line - b.line),
        column: [...items].sort((a, b) => a.column - b.column) } : { items });
    }
    const supports = (required, point) => {
      if (budget.remaining-- <= 0) throw new ScanError();
      const index = indexes.get(required.id);
      if (!index?.items.length) return false;
      const { withinLines, withinColumns } = required;
      if (withinLines === undefined && withinColumns === undefined) return true;
      const position = locations.get(point);
      const lines = withinLines === undefined ? [0, index.items.length] : proximityWindow(index.line, 'line', position.line, withinLines);
      const columns = withinColumns === undefined ? [0, index.items.length] : proximityWindow(index.column, 'column', position.column, withinColumns);
      if (withinLines === undefined) return columns[0] < columns[1];
      if (withinColumns === undefined) return lines[0] < lines[1];
      const [items, range] = lines[1] - lines[0] <= columns[1] - columns[0] ? [index.line, lines] : [index.column, columns];
      for (let i = range[0]; i < range[1]; i++) {
        if (budget.remaining-- <= 0) throw new ScanError();
        if (Math.abs(items[i].line - position.line) <= withinLines && Math.abs(items[i].column - position.column) <= withinColumns) return true;
      }
      return false;
    };
    return pending.filter(item => {
      // Upstream collects all qualifying supports by ID before checking that
      // every required ID is present. Repeated IDs provide alternative bounds.
      const satisfied = new Set();
      for (const required of item.rule.required) if (supports(required, item.point)) satisfied.add(required.id);
      return item.rule.required.every(required => satisfied.has(required.id));
    }).map(item => item.finding);
  }

  function normalizeRuleIds(value) {
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.length > 1000) throw new ScanError();
    if (!value.length) return undefined;
    const rules = globalThis.SecretShieldRules?.rules;
    if (!Array.isArray(rules)) throw new ScanError();
    const known = new Set(rules.map(rule => rule.id)), selected = new Set();
    for (const id of value) {
      if (typeof id !== 'string' || !known.has(id)) throw new ScanError();
      selected.add(id);
    }
    // Copy caller input and retain catalog order, including for overlapping rules.
    return rules.filter(rule => selected.has(rule.id)).map(rule => rule.id);
  }

  function plainFindings(text, normalized, original = text, passes = [], compositeBudget = { remaining: MAX_COMPOSITE_CHECKS }, ruleIds) {
    const { rules, allowlists, auxiliaryIds } = detectionRules(), lower = text.toLowerCase();
    const findings = [...assignmentFindings(text, normalized.sensitiveNames, 'custom-field'),
      ...(normalized.protectClientIds ? assignmentFindings(text, CLIENT_ID_NAMES, 'client-id') : [])];
    const matches = new Map(), pending = [];
    for (const rule of rules) {
      if (ruleIds && !ruleIds.has(rule.id)) continue;
      const active = !rule.keywords.length || rule.keywords.some(word => lower.includes(word));
      if ((!active || rule.skipReport) && !auxiliaryIds.has(rule.id)) continue;
      for (const match of ruleMatches(rule, text)) {
        const group = rule.secretGroup || Math.max(0, match.findIndex((value, index) => index > 0 && value));
        const selectedBounds = match.indices[rule.maskGroup ?? group];
        let secret = match[group];
        if (!selectedBounds || !secret) throw new ScanError();
        const bounds = [...selectedBounds];
        // Gitleaks trims LF delimiters from whole-match extraction.
        if (group === 0) {
          bounds[0] += secret.length - secret.replace(/^\n+/, '').length;
          bounds[1] -= secret.length - secret.replace(/\n+$/, '').length;
          secret = secret.replace(/^\n+|\n+$/g, '');
        }
        if (!secret) throw new ScanError();
        if (rule.entropy && entropy(secret) <= rule.entropy) continue;
        const matched = match[0].replace(/^\n+|\n+$/g, '');
        const lineStart = text.lastIndexOf('\n', match.index - 1) + 1;
        const lineEnd = text.indexOf('\n', match.index + matched.length);
        const line = text.slice(lineStart, lineEnd < 0 ? text.length : lineEnd);
        if (allowed(allowlists, secret, matched, line) || allowed(rule.allowlists, secret, matched, line)) continue;
        const [start, end] = bounds;
        const finding = { start, end, type: rule.id };
        let point = match.index;
        if (auxiliaryIds.has(rule.id) || rule.required.length) {
          for (let i = passes.length - 1; i >= 0; i--) point = originalOffset(point, passes[i], false);
        }
        if (auxiliaryIds.has(rule.id)) {
          if (!matches.has(rule.id)) matches.set(rule.id, []);
          matches.get(rule.id).push(point);
        }
        if (active && !rule.skipReport) {
          if (rule.required.length) pending.push({ rule, finding, point });
          else findings.push(finding);
        }
      }
    }
    if (pending.length) for (const finding of compositeFindings(pending, matches, original, compositeBudget)) findings.push(finding);
    return findings;
  }

  function scan(text, policy = defaults, maxCharacters = MAX_CHARACTERS, options = {}) {
    const maxDecodeDepth = options?.maxDecodeDepth === undefined ? MAX_DECODE_DEPTH : options.maxDecodeDepth;
    if (typeof text !== 'string' || !Number.isSafeInteger(maxCharacters) || maxCharacters < 0 || text.length > maxCharacters ||
        !options || typeof options !== 'object' || Array.isArray(options) || !Number.isSafeInteger(maxDecodeDepth) ||
        maxDecodeDepth < 0 || maxDecodeDepth > MAX_DECODE_DEPTH) throw new ScanError();
    const selected = normalizeRuleIds(options.ruleIds), ruleIds = selected && new Set(selected);
    const normalized = normalizePolicy(policy), compositeBudget = { remaining: MAX_COMPOSITE_CHECKS };
    const findings = plainFindings(text, normalized, text, [], compositeBudget, ruleIds);
    const passes = [], budget = { remaining: MAX_DECODE_CHARACTERS };
    let decoded = text;
    for (let depth = 0; depth < maxDecodeDepth; depth++) {
      const next = decodePass(decoded, budget);
      if (!next.segments.length) break;
      passes.push(next.segments);
      decoded = next.text;
      for (const item of plainFindings(decoded, normalized, text, passes, compositeBudget, ruleIds)) {
        let { start, end } = item;
        const tags = new Set();
        for (let i = passes.length - 1; i >= 0; i--) {
          const segments = passes[i];
          // Only overlapping decoded segments contribute tags to this finding.
          let low = 0, high = segments.length;
          while (low < high) {
            const middle = low + high >> 1;
            if (segments[middle].end <= start) low = middle + 1;
            else high = middle;
          }
          for (let j = low; j < segments.length && segments[j].start < end; j++) {
            tags.add(segments[j].tag); tags.add(`decode-depth:${i + 1}`);
          }
          start = originalOffset(start, segments, false);
          end = originalOffset(end, segments, true);
        }
        findings.push({ start, end, type: item.type, ...(tags.size ? { tags: findingTags([...tags]) } : {}) });
      }
    }
    // Provider, generic and custom rules can describe the same value. Keep
    // one review item per overlapping occurrence and mask its complete span.
    const distinct = [];
    for (const item of findings.sort((a, b) => a.start - b.start || b.end - a.end)) {
      const previous = distinct.at(-1);
      if (previous && item.start < previous.end) {
        previous.end = Math.max(previous.end, item.end);
        if (item.tags) previous.tags = findingTags([...(previous.tags ?? []), ...item.tags]);
        if (previous.type === 'generic-api-key' ||
            ['custom-field', 'client-id'].includes(previous.type) && !['generic-api-key', 'custom-field', 'client-id'].includes(item.type)) previous.type = item.type;
      } else distinct.push(item);
    }
    // Attach metadata after overlap selection so descriptions and rule tags
    // always belong to the retained rule, separate from combined decode tags.
    const { byId } = detectionRules(), locations = findingLocations(text, distinct);
    return distinct.map((item, index) => {
      const rule = byId.get(item.type);
      return { ...item, ...locations[index], ...(rule?.description !== undefined ? { description: rule.description } : {}),
        ...(rule?.tags.length ? { tags: [...rule.tags, ...(item.tags ?? [])] } : {}) };
    });
  }

  function redact(text, policy, maxCharacters, options) {
    const findings = scan(text, policy, maxCharacters, options);
    let output = '', cursor = 0;
    for (const item of findings) {
      output += text.slice(cursor, item.start) + MASK;
      cursor = item.end;
    }
    return { text: output + text.slice(cursor), count: findings.length, findings };
  }
  globalThis.SecretShieldCore = Object.freeze({ scan, redact, findingLocations, normalizePolicy, normalizeRuleIds, defaults, ScanError, MASK, MAX_CHARACTERS, MAX_CUSTOM_FIELDS });
})();
