# =============================================================================
# webapp/app.py — AgentGuard Web UI
# =============================================================================
# A thin web front end over the exact same scanning engine used by the CLI
# (agentguard.project_scanner.scan_target). No detection logic lives here —
# this file only handles upload, dispatch, and rendering, so the web UI and
# the CLI can never disagree about what counts as a finding.
#
# Accepts three upload shapes:
#   - a single .py file
#   - a .zip archive
#   - a whole folder, via the browser's native folder picker
#     (<input type="file" webkitdirectory>), which submits every file in the
#     folder with its relative path preserved in the filename.
#
# Run:
#   cd webapp
#   python3 app.py
#   open http://localhost:5000
#
# SECURITY NOTE — read this before exposing it beyond localhost.
# This app accepts arbitrary uploaded code and scans it, which includes
# generating and executing proof-of-concept exploits in a sandbox as part of
# the normal AgentGuard pipeline. That sandbox is hardened (see
# docker_sandbox.py / sandbox_runner.py) but "hardened" is not the same claim
# as "safe to expose to the public internet." Run this on localhost or behind
# your own authentication — it is a local analyst tool, not a public service.
# =============================================================================

import os
import sys
import shutil
import tempfile
import uuid
from pathlib import Path

from flask import (
    Flask, request, render_template, send_from_directory,
    redirect, url_for, flash,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentguard.project_scanner import (
    scan_target, write_project_json_report, write_project_markdown_report,
)

app = Flask(__name__)
app.secret_key = os.environ.get("AGENTGUARD_WEB_SECRET", os.urandom(24).hex())
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # 50 MB upload cap

UPLOAD_ROOT = Path(tempfile.gettempdir()) / "agentguard_web_uploads"
REPORT_ROOT = Path(__file__).resolve().parent / "reports"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
REPORT_ROOT.mkdir(parents=True, exist_ok=True)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    use_llm = request.form.get("use_llm") == "on"
    mode = request.form.get("mode", "file")

    job_id = uuid.uuid4().hex[:12]
    job_dir = UPLOAD_ROOT / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    # ── Collect the upload into job_dir, whichever shape it came in ────────
    if mode == "folder":
        files = request.files.getlist("folder_files")
        files = [f for f in files if f and f.filename]
        if not files:
            flash("No folder was selected, or the folder was empty.")
            shutil.rmtree(job_dir, ignore_errors=True)
            return redirect(url_for("index"))

        for f in files:
            # webkitdirectory submits each file's filename as a path relative
            # to the chosen folder, e.g. "myproject/tools/accounts.py".
            rel_path = Path(f.filename)
            if ".." in rel_path.parts:
                continue   # refuse anything trying to escape job_dir
            dest = job_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            f.save(dest)

        target = str(job_dir)

    else:
        upload = request.files.get("single_upload")
        if not upload or upload.filename == "":
            flash("No file was selected.")
            shutil.rmtree(job_dir, ignore_errors=True)
            return redirect(url_for("index"))

        suffix = Path(upload.filename).suffix.lower()
        if suffix not in (".py", ".zip"):
            flash("Only a .py file or a .zip archive is accepted here — "
                  "use 'Upload a folder' for anything else.")
            shutil.rmtree(job_dir, ignore_errors=True)
            return redirect(url_for("index"))

        dest = job_dir / Path(upload.filename).name
        upload.save(dest)
        target = str(dest)

    # ── Run the same scan engine the CLI uses ───────────────────────────────
    try:
        result, tmp_handle = scan_target(target, use_llm=use_llm, verbose=False)
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(job_dir, ignore_errors=True)
        flash(f"Scan failed: {exc}")
        return redirect(url_for("index"))

    try:
        report_dir = REPORT_ROOT / job_id
        report_dir.mkdir(parents=True, exist_ok=True)
        write_project_json_report(result, str(report_dir / "report.json"))
        write_project_markdown_report(result, str(report_dir / "report.md"))
    finally:
        if tmp_handle is not None:
            tmp_handle.cleanup()
        # The uploaded source has been fully read into `result` by this
        # point; the code itself does not need to remain on disk.
        shutil.rmtree(job_dir, ignore_errors=True)

    findings = sorted(
        result.all_findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence),
    )
    static_findings = [f for f in findings if f.source == "static"]
    gemini_findings = [f for f in findings if f.source == "gemini"]
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return render_template(
        "results.html",
        job_id            = job_id,
        target_kind       = result.target_kind,
        files_scanned     = len(result.files),
        agent_files       = len(result.agent_files),
        tools_found       = result.total_tools,
        frameworks        = sorted(result.frameworks),
        findings          = findings,
        static_findings   = static_findings,
        gemini_findings   = gemini_findings,
        cross_file        = result.cross_file_findings,
        severity_counts   = severity_counts,
        total_findings    = len(findings),
        skipped           = result.skipped,
        parse_errors      = [f for f in result.files if f.parse_error],
    )


@app.route("/download/<job_id>/<fmt>")
def download(job_id, fmt):
    report_dir = REPORT_ROOT / job_id
    if not report_dir.is_dir():
        flash("That report has expired or was already cleaned up.")
        return redirect(url_for("index"))
    filename = "report.json" if fmt == "json" else "report.md"
    return send_from_directory(report_dir, filename, as_attachment=True,
                                download_name=f"agentguard_{filename}")


if __name__ == "__main__":
    print("\n  AgentGuard Web UI")
    print("  Open http://localhost:5000 in your browser")
    print("  Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
