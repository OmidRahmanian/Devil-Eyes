"""Add the optional AI security review: sources, analyses, feedback and project memory.

Every table is project-scoped under the ``project_isolation`` policy. History
(sources, candidates, feedback, memory revisions and events, example usage and
the chunk cache) is append-only; the current state of analyses, memory
examples and per-project AI switches is kept separately and updated.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

TABLES = ("ai_project_settings", "ai_sources", "ai_analyses", "ai_candidates", "ai_chunk_cache", "ai_feedback",
          "ai_memory_examples", "ai_memory_revisions", "ai_memory_events", "ai_memory_usage")
APPEND_ONLY = ("ai_sources", "ai_candidates", "ai_chunk_cache", "ai_feedback", "ai_memory_revisions",
               "ai_memory_events", "ai_memory_usage")


def _ts(name, *, nullable=False, now=False):
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable, server_default=sa.text("now()") if now else None)


def _json(name, default="'{}'::jsonb"):
    return sa.Column(name, JSONB(), nullable=False, server_default=sa.text(default))


def _flag(name):
    return sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.text("false"))


def _uuid(name, nullable=False):
    return sa.Column(name, sa.UUID(), nullable=nullable)


def _table(name, *columns, pk, unique=(), fks=(), checks=()):
    constraints = [sa.PrimaryKeyConstraint(*pk, name=op.f(f"pk_{name}"))]
    constraints += [sa.UniqueConstraint(*cols, name=op.f(f"uq_{name}_{'_'.join(cols)}")) for cols in unique]
    constraints += [sa.ForeignKeyConstraint(list(cols), [f"{ref}.{c}" for c in ref_cols],
                                            name=op.f(f"fk_{name}_{'_'.join(cols)}_{ref}")) for cols, ref, ref_cols in fks]
    constraints += [sa.CheckConstraint(sql, name=op.f(f"ck_{name}_{label}")) for label, sql in checks]
    op.create_table(name, *columns, *constraints)


def _index(table, *columns):
    op.create_index(op.f(f"ix_{table}_{'_'.join(columns)}"), table, list(columns), unique=False)


PROJECT = (("project_id",), "projects", ("id",))


def upgrade():
    _table("ai_project_settings", _uuid("project_id"),
           _flag("retain_response_bodies"), _flag("allow_source_maps"), _flag("memory_require_second_reviewer"),
           _flag("review_changed_scripts"), _ts("updated_at", now=True), _uuid("updated_by", True),
           pk=("project_id",), fks=[PROJECT, (("updated_by",), "principals", ("id",))])
    _table("ai_sources", _uuid("id"), _uuid("project_id"), _uuid("run_id", True),
           sa.Column("origin", sa.Text(), nullable=False), sa.Column("kind", sa.Text(), nullable=False),
           sa.Column("url", sa.Text(), nullable=False), sa.Column("final_url", sa.Text(), nullable=True),
           sa.Column("status_code", sa.Integer(), nullable=True),
           sa.Column("content_type", sa.Text(), server_default="", nullable=False),
           sa.Column("size_bytes", sa.BigInteger(), server_default="0", nullable=False),
           sa.Column("sha256", sa.Text(), nullable=True), sa.Column("redacted_sha256", sa.Text(), nullable=True),
           sa.Column("storage_uri", sa.Text(), nullable=True), _flag("truncated"),
           sa.Column("redactions", sa.Integer(), server_default="0", nullable=False),
           _json("details"), _json("preanalysis"), _ts("created_at", now=True), _ts("expires_at", nullable=True),
           pk=("id",), unique=[("project_id", "id")], fks=[PROJECT],
           checks=[("origin", "origin IN ('scan_evidence', 'retained_body', 'collected', 'reference', 'source_map')"),
                   ("kind", "kind IN ('scan_summary', 'html', 'script', 'inline_script', 'source_map_source', 'reference')"),
                   ("sha256_hex", "sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'")])
    _index("ai_sources", "project_id", "run_id")
    _table("ai_analyses", _uuid("id"), _uuid("project_id"), _uuid("run_id", True), _uuid("requested_by", True),
           sa.Column("status", sa.Text(), server_default="queued", nullable=False),
           sa.Column("mode", sa.Text(), server_default="model", nullable=False),
           _json("source_ids", "'[]'::jsonb"),
           sa.Column("model", sa.Text(), server_default="", nullable=False),
           sa.Column("prompt_version", sa.Text(), server_default="", nullable=False),
           sa.Column("config_hash", sa.Text(), server_default="", nullable=False),
           _uuid("reanalysis_of", True), _json("preanalysis"), _json("coverage"),
           sa.Column("error", sa.Text(), nullable=True), _ts("outdated_at", nullable=True),
           sa.Column("outdated_reason", sa.Text(), nullable=True),
           _ts("created_at", now=True), _ts("started_at", nullable=True), _ts("finished_at", nullable=True),
           pk=("id",), unique=[("project_id", "id")], fks=[PROJECT, (("requested_by",), "principals", ("id",))],
           checks=[("status", "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')"),
                   ("mode", "mode IN ('model', 'preanalysis_only')")])
    _index("ai_analyses", "project_id", "created_at")
    _table("ai_candidates", _uuid("id"), _uuid("project_id"), _uuid("analysis_id"),
           sa.Column("ordinal", sa.Integer(), nullable=False), sa.Column("category", sa.Text(), nullable=False),
           sa.Column("title", sa.Text(), nullable=False), sa.Column("supported", sa.Boolean(), nullable=False),
           sa.Column("citation_status", sa.Text(), nullable=False), sa.Column("confidence", sa.Text(), nullable=False),
           _json("data"), _uuid("matched_finding_id", True), _ts("created_at", now=True),
           pk=("id",), unique=[("project_id", "id"), ("analysis_id", "ordinal")],
           fks=[PROJECT, (("project_id", "analysis_id"), "ai_analyses", ("project_id", "id")),
                (("project_id", "matched_finding_id"), "findings", ("project_id", "id"))],
           checks=[("citation_status", "citation_status IN ('verified', 'partial', 'not_verified')"),
                   ("confidence", "confidence IN ('low', 'medium', 'high')")])
    _table("ai_chunk_cache", _uuid("project_id"), sa.Column("cache_key", sa.Text(), nullable=False),
           sa.Column("model", sa.Text(), nullable=False), sa.Column("prompt_version", sa.Text(), nullable=False),
           _json("result"), _ts("created_at", now=True), pk=("project_id", "cache_key"), fks=[PROJECT])
    _table("ai_feedback", _uuid("id"), _uuid("project_id"), _uuid("analysis_id"), _uuid("candidate_id"),
           sa.Column("kind", sa.Text(), nullable=False), sa.Column("reason", sa.Text(), server_default="", nullable=False),
           _json("corrected"), _json("evidence", "'[]'::jsonb"), _flag("submitted_for_memory"),
           _uuid("author", True), _ts("created_at", now=True),
           pk=("id",), unique=[("project_id", "id")],
           fks=[PROJECT, (("project_id", "analysis_id"), "ai_analyses", ("project_id", "id")),
                (("project_id", "candidate_id"), "ai_candidates", ("project_id", "id")),
                (("author",), "principals", ("id",))],
           checks=[("kind", "kind IN ('looks_correct', 'false_positive', 'edit')"),
                   ("reason_present", "kind <> 'false_positive' OR length(trim(reason)) > 0")])
    _index("ai_feedback", "project_id", "candidate_id")
    _table("ai_memory_examples", _uuid("id"), _uuid("project_id"),
           sa.Column("status", sa.Text(), server_default="submitted", nullable=False), _flag("eligible"),
           sa.Column("current_revision", sa.Integer(), server_default="1", nullable=False),
           sa.Column("approved_revision", sa.Integer(), nullable=True), _uuid("feedback_id", True),
           _uuid("submitted_by", True), _uuid("reviewed_by", True), _ts("reviewed_at", nullable=True),
           _flag("self_approved"), _uuid("superseded_by", True), _ts("created_at", now=True), _ts("updated_at", now=True),
           pk=("id",), unique=[("project_id", "id")],
           fks=[PROJECT, (("project_id", "feedback_id"), "ai_feedback", ("project_id", "id")),
                (("submitted_by",), "principals", ("id",)), (("reviewed_by",), "principals", ("id",))],
           checks=[("status", "status IN ('submitted', 'approved', 'rejected', 'superseded', 'disabled')"),
                   ("eligible_when_approved", "NOT eligible OR (status = 'approved' AND approved_revision IS NOT NULL)")])
    _table("ai_memory_revisions", _uuid("project_id"), _uuid("example_id"),
           sa.Column("revision", sa.Integer(), nullable=False), _json("content"), _json("conditions"),
           _uuid("author", True), sa.Column("note", sa.Text(), server_default="", nullable=False), _ts("created_at", now=True),
           pk=("example_id", "revision"),
           fks=[PROJECT, (("project_id", "example_id"), "ai_memory_examples", ("project_id", "id")),
                (("author",), "principals", ("id",))],
           checks=[("revision_positive", "revision > 0")])
    _table("ai_memory_events", sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
           _uuid("project_id"), _uuid("example_id"), sa.Column("action", sa.Text(), nullable=False),
           sa.Column("revision", sa.Integer(), nullable=True), _uuid("actor", True),
           sa.Column("reason", sa.Text(), server_default="", nullable=False), _ts("created_at", now=True),
           pk=("id",), fks=[PROJECT, (("project_id", "example_id"), "ai_memory_examples", ("project_id", "id")),
                            (("actor",), "principals", ("id",))],
           checks=[("action", "action IN ('submitted', 'approved', 'self_approved', 'rejected', 'edited', 'disabled', "
                              "'re_enabled', 'superseded')")])
    _index("ai_memory_events", "project_id", "example_id")
    _table("ai_memory_usage", _uuid("project_id"), _uuid("analysis_id"), _uuid("example_id"),
           sa.Column("revision", sa.Integer(), nullable=False), _json("score"),
           sa.Column("reason", sa.Text(), server_default="", nullable=False), _ts("created_at", now=True),
           pk=("analysis_id", "example_id", "revision"),
           fks=[PROJECT, (("project_id", "analysis_id"), "ai_analyses", ("project_id", "id")),
                (("project_id", "example_id"), "ai_memory_examples", ("project_id", "id"))])
    _index("ai_memory_usage", "project_id", "example_id")
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY project_isolation ON {table} USING (watchtower_is_system() OR project_id = "
                   "watchtower_current_project()) WITH CHECK (watchtower_is_system() OR project_id = "
                   "watchtower_current_project())")
    for table in APPEND_ONLY:
        op.execute(f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
                   "FOR EACH ROW EXECUTE FUNCTION watchtower_reject_change()")
        op.execute(f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
                   "FOR EACH STATEMENT EXECUTE FUNCTION watchtower_reject_change()")


def downgrade():
    for table in reversed(TABLES):
        op.drop_table(table)
