// Injected only into the verifier's isolated browser. Never stored in platform
// data or counted as a real benchmark/capture. Keep this function self-contained.
export function installProgressFixture(run) {
  const originalFetch = globalThis.fetch.bind(globalThis);
  const base = '/v1/recordings/' + encodeURIComponent(run + '#0000');
  const state = globalThis.__iorecProgressFixture = { revision: 1, served: [], conflicts: 0, timelineRequests: 0 };
  const calls = Array.from({ length: 53 }, (_, i) => ({
    ordinal: i + 1,
    evidence: { attempt_id: `fixture-call-${i + 1}`, recording_id: run + '#0000', first_seq: i * 2 + 1, last_seq: i * 2 + 2 },
    model: 'browser-only-fixture', api_mode: 'responses', terminal_state: 'success',
    started_at: '2026-09-20T00:00:00Z', ended_at: '2026-09-20T00:00:01Z',
    input_preview: 'Synthetic browser pagination test; not a real agent task.',
    response_preview: `Fixture response ${i + 1}`, response_characters: 20,
    tools: [], predecessors: [], body_unavailable: false, unmatched_tool_results: 0,
  }));
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  globalThis.fetch = async (input, init) => {
    const u = new URL(typeof input === 'string' ? input : input.url, location.origin);
    if (u.pathname === base) return json({ id: run + '#0000', capture_run_id: run, agent_kind: 'browser-only-fixture', state: 'sealed', ui_state: 'ready', durable_seq: 106, parsed_seq: 106, final_seq: 106, batches: [], failed_jobs: 0, active_jobs: 0 });
    if (u.pathname === base + '/timeline') {
      state.timelineRequests++;
      return json({ error: { code: 'fixture_unexpected_eager_timeline', message: 'Unexpected legacy query' } }, 500);
    }
    if (u.pathname !== base + '/progress') return originalFetch(input, init);
    const snapshot = 'fixture-' + state.revision;
    const requested = u.searchParams.get('snapshot');
    if (requested && requested !== snapshot) {
      state.conflicts++;
      return json({ error: { code: 'progress_snapshot_changed', message: 'Synthetic snapshot change' } }, 409);
    }
    const offset = Number(u.searchParams.get('offset') ?? 0), limit = Number(u.searchParams.get('limit') ?? 25);
    state.served.push({ offset, snapshot });
    return json({ schema_version: 1, capture_run_id: run, snapshot, total: calls.length,
      items: calls.slice(offset, offset + limit), offset, limit,
      next_offset: offset + limit < calls.length ? offset + limit : null,
      summary: { model_calls: 53, websocket_connections: 0, hook_observations: 0, hook_events: 0,
        other_http_requests: 0, all_attempt_rows: 53, raw_events: 106, sse_events: 0, websocket_messages: 0,
        stream_events: 0, normalization_pending: 0,
        tools: { requested: 0, results_observed: 0, awaiting_result_evidence: 0, ambiguous: 0, conflicting: 0, unmatched_result_observations: 0 } },
      benchmark_result: null,
    });
  };
}
