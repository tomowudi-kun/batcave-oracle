from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
edge=(ROOT/'src/existing_change_gate_additive_STAGED.ts').read_text()
sql=(ROOT/'sql/lab_only_enrollment_additive_STAGED.sql').read_text()
core=(ROOT/'src/owner_gate_core.mjs').read_text()


def test_existing_get_stays_shadow_only():
    for bit in ["mode:'shadow'", "deployment_authorized:false", "permits_mutations:false", "passkey_enrollment_enabled:false", "owner_authenticated:true"]:
        assert bit in edge
    for route in ['change_gate_rules','change_gate_intents','maintenance_release_candidates']:
        assert route in edge


def test_only_three_owner_authenticated_post_actions():
    for action in ['oracle_lab_enroll_challenge_v2','oracle_lab_enroll_reviewer_v2','oracle_lab_record_review_v2']:
        assert f"body.action==='{action}'" in core
    assert 'owner_authenticated:true' in edge
    assert "withSupabase({auth:'user'}" in edge
    assert "getUserById(ctx.userClaims.id)" in edge
    assert 'execution_authorized:false' in core
    assert 'deployment_authorized:false' in core


def test_db_immutable_lab_scope_and_private_permissions():
    assert sql.count('ENABLE ROW LEVEL SECURITY') == 3
    assert sql.count('FROM PUBLIC,anon,authenticated;')>=5
    assert 'production_release_authorized=false' in sql
    assert "scope='disposable_lab_only'" in sql
    assert "fixture='fixed_clamp_score_v1'" in sql
    assert 'REFERENCES batcave.commands(id)' in sql
    assert 'ON CONFLICT DO NOTHING' in sql
    assert 'FOR UPDATE OF c' in sql
    assert 'GRANT EXECUTE ON FUNCTION' in sql
    for unsafe in ['DROP TABLE','TRUNCATE TABLE','ALTER TABLE batcave.change_gate_rules','UPDATE batcave.change_gate_intents','CREATE EXTENSION']:
        assert unsafe not in sql


def test_exact_release_archive_pin_differentiated_from_fixed_fixture_pin():
    release='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2'
    fixture='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'
    assert release != fixture
    for text in [sql,(ROOT/'src/verify_owner_enrollment_v2.mjs').read_text()]:
        assert release in text and fixture in text


def test_db_writer_is_service_role_only_without_self_signature():
    assert sql.count('LANGUAGE plpgsql SECURITY INVOKER')==2
    assert sql.count('TO service_role;') >= 8
    assert "INSERT INTO batcave.oracle_lab_review_grants_v1" in sql
    assert "INSERT INTO batcave.oracle_lab_reviewer_keys_v1" in sql
    assert 'extensions.digest' in sql
    assert 'p_raw_request_json' in sql and 'p_request_sha256' in sql
    assert 'public_record' in core


def test_no_signed_receipt_promotion_to_production():
    for field in ['execution_authorized','deployment_authorized','production_release_authorized']:
        assert f"p_signed_receipt->'payload'->>'{field}'" in sql
        assert f"(p_signed_receipt->'payload'->>'{field}') IS DISTINCT FROM 'false'" in sql
    assert "respond({error:'lab_gate_unavailable',execution_authorized:false,deployment_authorized:false}" in edge


def test_no_arbitrary_code_or_command_datum_in_post_allowlist():
    assert "body.action==='oracle_lab_record_review_v2'" in core
    assert 'verifyReview({' in core
    assert "return deny('UNSUPPORTED_ACTION',400)" in core
    assert not re.search(r'\beval\s*\(',edge+core)
    assert not re.search(r'\bexec\s*\(',edge+core)

def test_cors_allows_only_existing_owner_portal_and_cloud_control():
    assert "'https://batcave-linux-approval.vercel.app'" in edge
    assert "'https://batcave-cloud-control.vercel.app'" in edge
    assert 'access-control-allow-origin' in edge
    assert "allowedOrigins.has(origin)" in edge
    assert 'access-control-allow-origin\':\'*\'' not in edge
