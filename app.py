import os
import tempfile
import shutil
from pathlib import Path
from flask import Flask, render_template, request, redirect, send_file, flash, url_for
from werkzeug.utils import secure_filename

# Import existing processing functions
from consolidation import consolidated_process, summary_process


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")


ALLOWED_EXTENSIONS = {"csv", "zip"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET"]) 
def index():
    return render_template("index.html")


@app.route("/run", methods=["POST"]) 
def run_operation():
    operation = request.form.get("operation")
    custom_name = (request.form.get("download_name") or "").strip()

    if operation not in {"consolidate", "summary"}:
        flash("Invalid operation.")
        return redirect(url_for("index"))

    # Create temp working directory
    temp_dir = tempfile.mkdtemp(prefix="va_report_")
    try:
        if operation == "summary":
            files = request.files.getlist("files")
            if not files or len([f for f in files if f and f.filename]) != 1:
                flash("Please upload exactly one CSV file for 'Summary'.")
                return redirect(url_for("index"))
            uploaded_file = [f for f in files if f and f.filename][0]
            if not uploaded_file.filename.lower().endswith(".csv"):
                flash("Only .csv is allowed for 'Summary'.")
                return redirect(url_for("index"))

            filename = secure_filename(uploaded_file.filename)
            input_csv_path = os.path.join(temp_dir, filename)
            uploaded_file.save(input_csv_path)

            summary_process(input_csv_path)

            output_path = os.path.join(os.path.dirname(input_csv_path), "vulnerability_summary.csv")
            if not os.path.exists(output_path):
                flash("Summary generation failed: output not found.")
                return redirect(url_for("index"))

            download_name = custom_name or "vulnerability_summary.csv"
            if not download_name.lower().endswith(".csv"):
                download_name += ".csv"
            return send_file(output_path, as_attachment=True, download_name=download_name)

        # consolidate using unified files input
        files = [f for f in request.files.getlist("files") if f and f.filename]
        if not files:
            flash("Select one or more .csv files for 'Consolidate'.")
            return redirect(url_for("index"))

        target_dir = os.path.join(temp_dir, "input")
        os.makedirs(target_dir, exist_ok=True)

        for f in files:
            if not f.filename.lower().endswith(".csv"):
                flash("All uploaded files must be .csv for 'Consolidate'.")
                return redirect(url_for("index"))
            f.save(os.path.join(target_dir, secure_filename(f.filename)))

        consolidated_process(target_dir)

        output_path = os.path.join(os.getcwd(), "consolidated_vulnerability_report.csv")
        if not os.path.exists(output_path):
            alt_output_path = os.path.join(target_dir, "consolidated_vulnerability_report.csv")
            output_path = alt_output_path if os.path.exists(alt_output_path) else output_path
        if not os.path.exists(output_path):
            project_output = Path(__file__).resolve().parent / "consolidated_vulnerability_report.csv"
            if project_output.exists():
                output_path = str(project_output)
        if not os.path.exists(output_path):
            flash("Consolidation failed: output not found.")
            return redirect(url_for("index"))

        download_name = custom_name or "consolidated_vulnerability_report.csv"
        if not download_name.lower().endswith(".csv"):
            download_name += ".csv"

        return send_file(output_path, as_attachment=True, download_name=download_name)

    finally:
        # Clean up temp dir (not removing potential output in CWD)
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)


