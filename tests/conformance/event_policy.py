"""Reproducible PR seeds and per-run weekly seeds; counts are actual requests."""
import datetime
import hashlib


def policy(env, now=None):
    extended=env.get('GITHUB_EVENT_NAME') in ('schedule','workflow_dispatch')
    seed=20261109
    if extended:
        stamp=env.get('GITHUB_RUN_ID') or (now or datetime.datetime.now(datetime.timezone.utc)).isoformat()
        identity=stamp+':'+env.get('GITHUB_RUN_ATTEMPT','1')
        seed=int.from_bytes(hashlib.sha256(identity.encode()).digest()[:8],'big')
        if seed==20261109: seed+=2
    count=2000000 if extended else 200000
    return {'extended':extended,'redactor_seed':seed,'line_seed':seed+1,
            'redactor_random_inputs':count//2,'redactor_fuzz_requests':count,'line_random_inputs':count}
