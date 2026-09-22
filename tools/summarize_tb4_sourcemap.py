#!/usr/bin/env python3
"""Regenerate a payload-free ledger from the three local TB4 trial artifacts.

Reads a local platform API; never launches agents or changes recordings. The
output intentionally excludes prompts, responses, solutions and credentials.
Prices are the operator-supplied snapshot, not provider billing evidence.
"""
import argparse
from collections import Counter
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import quote
from urllib.request import urlopen


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def usage_metrics(usage):
    i, o = usage['input_tokens'], usage['output_tokens']
    details = usage.get('input_tokens_details') or {}
    read, write = details.get('cached_tokens', 0), details.get('cache_write_tokens', 0)
    ordinary = i - read - write
    if any(type(v) is not int or v < 0 for v in (i, o, read, write, ordinary)):
        raise ValueError('Invalid or overlapping input buckets')
    rates = (8, Decimal('0.8'), 10, 30) if i > 272000 else (4, Decimal('0.4'), 5, 20)
    cost = sum(Decimal(v) * r for v, r in zip((ordinary, read, write, o), rates)) / 1000000
    return dict(input_tokens=i, output_tokens=o, cache_read_tokens=read,
                cache_write_tokens=write, ordinary_input_tokens=ordinary,
                reasoning_tokens=(usage.get('output_tokens_details') or {}).get('reasoning_tokens', 0),
                usage_covered_requests=1, long_context_requests=int(i > 272000)), cost


def summary(base, api, agent):
    def get(path):
        with urlopen(api.rstrip('/') + path, timeout=30) as response:
            return json.load(response)

    state = json.loads((base / agent / 'state.json').read_text())
    paths = list((base / agent / 'jobs/audit').glob('*/result.json'))
    assert len(paths) == 1, 'Expected exactly one trial, not retries'
    path = paths[0]
    result = json.loads(path.read_text())
    assert result.get('finished_at') and not result.get('exception_info')
    report_path = base / agent / 'report.json'
    report = json.loads(report_path.read_text())
    diagnostic_path = base / agent / 'diagnostic-platform-import.json'
    diagnostic = json.loads(diagnostic_path.read_text()) if diagnostic_path.exists() else None
    if diagnostic is None:
        assert report['workflow_status'] == 'completed'
    else:
        assert report['workflow_status'] == 'incomplete' and diagnostic['capture_qualified'] is False
    run = state['source_identity']['run_id']
    recording_id = run + '#0000'
    recording = get('/v1/recordings/' + quote(recording_id, safe=''))
    assert recording.get('final_seq') is not None
    assert recording['final_seq'] == recording['durable_seq'] == recording['parsed_seq']
    rows = get('/v1/attempts?recording_id=' + quote(recording_id, safe='') + '&limit=500')['items']
    assert len(rows) < 500, 'Pagination required; refusing truncated accounting'
    calls = sorted([r for r in rows if r.get('source', '').startswith('proxy')
                    and r.get('entity_kind') != 'websocket_connection'
                    and r.get('api_mode') == 'responses'], key=lambda r: r['first_seq'])
    totals, generating = Counter(), Counter()
    price, generation_price = Decimal(0), Decimal(0)
    per_call = []
    for n, row in enumerate(calls, 1):
        detail = get('/v1/attempts/' + quote(row['id'], safe=''))
        body = detail.get('request_body')
        if isinstance(body, str):
            body = json.loads(body)
        parameter_source = 'request_body'
        if body is None:
            # Chunked HTTP requests live in body parts; the platform's completed
            # normalized projection reconstructs them, including generate/reasoning.
            normalized = detail.get('normalized') or {}
            assert isinstance(normalized.get('params'), dict), 'Request parameters unavailable'
            body = dict(normalized['params'], model=normalized.get('model'))
            parameter_source = 'normalized_request_body_parts'
        assert isinstance(body, dict), 'Request parameters unavailable'
        reason = body.get('reasoning') or {}
        assert body.get('model') == 'gpt-5.6-sol' and reason.get('effort') == 'high'
        generates = body.get('generate') is not False
        purpose = 'task' if generates else 'warmup'
        messages = (detail.get('normalized') or {}).get('messages') or []
        if (agent == 'hermes' and n == len(calls) and messages and messages[-1].get('role') == 'user'
                and messages[-1].get('text', '').startswith('Review the conversation above and update the skill library.')):
            purpose = 'post_task_skill_review'
        item = dict(ordinal=n, id=row['id'], terminal_state=row.get('terminal_state'),
                    status_code=row.get('status_code'), generates=generates,
                    requested_model=body['model'], reasoning_effort=reason['effort'],
                    parameter_source=parameter_source,
                    purpose=purpose, started_at=row.get('started_at'),
                    usage_available=row.get('usage') is not None)
        if row.get('usage') is not None:
            values, cost = usage_metrics(row['usage'])
            totals.update(values)
            price += cost
            if generates:
                generating.update(values)
                generation_price += cost
            item.update(usage=values, estimated_cost_usd=str(cost))
        per_call.append(item)
    ctrf = json.loads((path.parent / 'verifier/ctrf.json').read_text())['results']
    measured = report['stages']['record']['result']['measurement']
    audit = report['stages']['transport_audit']
    if diagnostic is not None:
        raw = json.loads((base / agent / 'transport-diagnostic.json').read_text())
        audit = dict(status='failed', result={k: raw.get(k) for k in
                     ['schema_version', 'complete', 'payload_diff_passed', 'completeness_boundary',
                      'matched_attempts', 'missing_from_wire', 'extra_on_wire', 'websocket_rows',
                      'manifest_capture_drops', 'gaps', 'proxy_attempts_eligible']})
    # These two projections contain only transport counters and verdicts.
    proof = recording.get('transport_proof')
    recovery_path = base / agent / 'qualification-recovery.json'
    recovery = json.loads(recovery_path.read_text()) if recovery_path.exists() else None
    native_session = None
    session_path = path.parent / 'agent/hermes-session.jsonl'
    if agent == 'hermes' and session_path.exists():
        sessions = [json.loads(line) for line in session_path.read_text().splitlines() if line.strip()]
        assert len(sessions) == 1
        native_session = {k: sessions[0].get(k) for k in
                          ['model', 'api_call_count', 'tool_call_count', 'input_tokens', 'output_tokens',
                           'cache_read_tokens', 'cache_write_tokens', 'reasoning_tokens', 'cost_status']}
        native_session['sha256'] = sha(session_path)
        final = sessions[0]['messages'][-1]
        assert final['role'] == 'assistant' and final['finish_reason'] == 'stop'
        for call in per_call:
            if call['purpose'] == 'post_task_skill_review':
                assert datetime.fromisoformat(call['started_at'].replace('Z', '+00:00')).timestamp() > final['timestamp']
    return dict(agent=agent, agent_version=result['agent_info']['version'],
                model='openai/gpt-5.6-sol', trial=path.parent.name,
                reward=result['verifier_result']['rewards']['reward'],
                verifier=dict(summary=ctrf['summary'], checks=[dict(name=t['name'], status=t['status']) for t in ctrf['tests']]),
                model_requests=len(calls), usage=dict(totals),
                generation_requests=sum(c['generates'] for c in per_call),
                task_requests=sum(c['purpose'] == 'task' for c in per_call),
                auxiliary_requests=sum(c['purpose'] == 'post_task_skill_review' for c in per_call),
                generation_usage=dict(generating),
                estimated_cost_usd_generation=str(generation_price), estimated_cost_usd_observed=str(price),
                cost_coverage_complete=totals['usage_covered_requests'] == len(calls),
                native_agent_result={k: result.get('agent_result', {}).get(k) for k in
                                     ['n_input_tokens', 'n_cache_tokens', 'n_output_tokens', 'cost_usd']},
                wall_seconds=measured['wall_seconds'], wall_scope=measured['wall_scope'],
                run_id=run, recording_id=recording_id, final_seq=recording['final_seq'],
                transport_proof=proof, independent_audit=audit, qualification_recovery=recovery,
                capture_qualified=diagnostic is None, workflow_status=report['workflow_status'],
                native_session_usage=native_session,
                hashes=dict(trial_result=sha(path), verifier_ctrf=sha(path.parent / 'verifier/ctrf.json'),
                            capture_manifest=state['source_identity']['manifest_sha256'], workflow_report=sha(report_path)),
                calls=per_call)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--api', default='http://127.0.0.1:18080')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    declaration = json.loads((args.root / 'declaration.json').read_text())
    trials = [summary(args.root, args.api, a) for a in ['codex', 'pi', 'hermes']]
    original_task = args.root / 'tasks/bun-sourcemap-leak'
    runtime_task = args.root / 'runtime-tasks/bun-sourcemap-leak'
    original_files = [p for p in original_task.rglob('*') if p.is_file()]
    assert all(p.read_bytes() == (runtime_task / p.relative_to(original_task)).read_bytes() for p in original_files)
    extra_files = sorted(str(p.relative_to(runtime_task)) for p in runtime_task.rglob('*')
                         if p.is_file() and not (original_task / p.relative_to(runtime_task)).exists())
    assert extra_files == ['environment/docker-compose.yaml', 'tests/docker-compose.yaml']
    oracle_paths = list((args.root / 'preflight-jobs/oracle-preflight').glob('*/result.json'))
    assert len(oracle_paths) == 1
    oracle = json.loads(oracle_paths[0].read_text())
    assert not oracle.get('exception_info') and oracle['verifier_result']['rewards']['reward'] == 1
    report = dict(
        schema_version=1, experiment='tb4-bun-sourcemap-same-model', date='2026-09-22',
        declaration=declaration,
        task_inputs={p: sha(args.root / 'tasks/bun-sourcemap-leak' / p) for p in ['instruction.md', 'task.toml']},
        recorder_sha256=sha(args.root / 'bin/iorec'),
        generator_sha256=sha(Path(__file__)),
        oracle_preflight=dict(reward=1, trial=oracle_paths[0].parent.name, result_sha256=sha(oracle_paths[0])),
        runtime_overlay=dict(original_files_identical=len(original_files),
                             added_files={p: sha(runtime_task / p) for p in extra_files}),
        methodology=dict(
            model_calls='Proxy Responses requests only; exclude hook duplicates and parent WebSocket connections; separate generate=false warmup.',
            input='Disjoint ordinary input + cache read + cache write; repeated context is counted on each request.',
            native_input='Pi native input excludes cache writes; use the normalized disjoint bucket sum consistently for all three agents.',
            missing_usage='Requests without usage remain in the request count. Cost and token sums are lower bounds when coverage is incomplete.',
            hermes_native='Harbor reports zero tokens for this Hermes export; that is not zero consumption. The separate native session counters and observed proxy usage are retained.',
            hermes_auxiliary='The final request asks to review the conversation and update the skill library, after the native final stop reply. It has no captured usage and is not a task-solving round.',
            reasoning='Subset of output; never added twice.',
            time='Command launch through reap including recorder startup and flush; excludes installation, verifier and import.',
            verification='Official verifier reward is separate from recording integrity and independent transport audit.',
            local_overlay='Original task files byte-identical; only explicit agent and verifier Docker bridge subnets added.',
            control='Isolated official oracle reward=1 before trials; no solution or verifier hints supplied to agents.',
            scope='One independent attempt per agent; no automatic retries. Not a leaderboard submission or causal agent ranking.'),
        price_snapshot=dict(source='User supplied; estimates, not invoices', currency='USD', unit='per million tokens',
                            short_context=dict(ordinary_input=4, cache_read=0.4, cache_write=5, output=20),
                            long_context=dict(ordinary_input=8, cache_read=0.8, cache_write=10, output=30),
                            long_context_input_threshold=272000),
        trials=trials,
        privacy='Aggregates, identifiers and hashes only. No captured payloads, solutions, prompts or credentials.')
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(output=str(args.output), trials=len(trials), rewards=[t['reward'] for t in trials])))


if __name__ == '__main__':
    main()
