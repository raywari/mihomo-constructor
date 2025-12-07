self.onmessage = async (event) => {
  const { type, url, chunkSize = 5000 } = event.data || {};
  if (type !== "start" || !url) return;

  let received = 0;
  let total = null;
  let totalLines = 0;
  const batch = [];

  const flushBatch = () => {
    if (!batch.length) return;
    totalLines += batch.length;
    self.postMessage({
      type: "chunk",
      lines: batch.splice(0, batch.length),
      received,
      total,
    });
  };

  const pushLines = (lines) => {
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      batch.push(trimmed);
      if (batch.length >= chunkSize) flushBatch();
    }
  };

  const parseAndSend = (text) => {
    const lines = text.split(/\r?\n/);
    pushLines(lines);
  };

  try {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Could not load ${url} (HTTP ${res.status})`);
    }

    total = Number(res.headers.get("content-length")) || null;

    if (!res.body || !res.body.getReader) {
      const text = await res.text();
      received = text.length;
      parseAndSend(text);
      flushBatch();
      self.postMessage({ type: "done", received, total, totalLines });
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.byteLength;
      buffer += decoder.decode(value, { stream: true });

      const lastNewline = buffer.lastIndexOf("\n");
      if (lastNewline !== -1) {
        const chunk = buffer.slice(0, lastNewline);
        buffer = buffer.slice(lastNewline + 1);
        parseAndSend(chunk);
        flushBatch();
      }

      self.postMessage({ type: "progress", received, total });
    }

    buffer += decoder.decode();
    if (buffer.length) {
      parseAndSend(buffer);
    }

    flushBatch();
    self.postMessage({ type: "done", received, total, totalLines });
  } catch (e) {
    const message = e?.message || String(e);
    self.postMessage({ type: "error", message });
  }
};
