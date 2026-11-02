// Independent UTF-8 byte-buffer oracle for public finding coordinates.
export function withLocations(text, findings) {
  const bytes = Buffer.from(text);
  const position = offset => {
    const before = bytes.subarray(0, offset);
    return { line: 1 + before.filter(byte => byte === 10).length, column: offset - before.lastIndexOf(10) };
  };
  return findings.map(item => {
    const start = position(Buffer.byteLength(text.slice(0, item.start)));
    const end = position(Buffer.byteLength(text.slice(0, item.end)) - 1);
    return { ...item, startLine: start.line, startColumn: start.column, endLine: end.line, endColumn: end.column };
  });
}
