import os
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from .crypto_helpers import encrypt_file, decrypt_file, save_metadata, load_meta

# Flask setup
base_dir = os.path.dirname(__file__)
template_dir = os.path.join(base_dir, "templates")
app = Flask(__name__, template_folder=template_dir)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = os.path.join(os.path.dirname(base_dir), "storage")
META_FOLDER = os.path.join(os.path.dirname(base_dir), "metadata")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(META_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "upload":
            file = request.files.get("file")
            password = request.form.get("password")
            if not file or not password:
                flash("Please choose a file and enter a password.", "danger")
                return redirect(url_for("index"))

            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename + ".enc")
            meta_path = os.path.join(META_FOLDER, filename + ".json")

            data = file.read()
            encrypted = encrypt_file(data, password)

            with open(file_path, "wb") as f:
                f.write(encrypted)
            save_metadata(meta_path, filename)

            flash(f"File '{filename}' encrypted and stored successfully!", "success")
            return redirect(url_for("index"))

        elif action == "decrypt":
            filename = request.form.get("filename")
            password = request.form.get("password")
            file_path = os.path.join(UPLOAD_FOLDER, filename + ".enc")

            if not os.path.exists(file_path):
                flash("File not found.", "danger")
                return redirect(url_for("index"))

            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted = decrypt_file(encrypted_data, password)

                out_path = os.path.join("/tmp", filename)
                with open(out_path, "wb") as f:
                    f.write(decrypted)

                flash(f"File '{filename}' decrypted successfully!", "info")
                return send_file(out_path, as_attachment=True)
            except Exception:
                flash("Decryption failed! Incorrect password.", "danger")
                return redirect(url_for("index"))

    files = [f[:-5] for f in os.listdir(META_FOLDER) if f.endswith(".json")]
    return render_template("index.html", files=files)


if __name__ == "__main__":
    app.run(debug=True)
