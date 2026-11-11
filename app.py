
from flask import Flask, render_template, request, redirect, session
import os
import secrets
import hmac
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    files = os.listdir(UPLOAD_FOLDER)
    files = sorted(files, reverse=True)
    return render_template(
        "index.html",
        media=files,
        admin=session.get("admin", False)
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        with open("admin.txt") as f:
            password = f.read().strip()

        if hmac.compare_digest(
            request.form.get("password", ""),
            password
        ):
            session["admin"] = True
            return redirect("/")

        return "Неверный пароль"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("admin"):
        return "Доступ запрещён", 403

    file = request.files.get("file")

    if file and file.filename:
        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[-1].lower()

        if ext not in ["jpg", "jpeg", "png", "webp", "gif"]:
            return "Неподдерживаемый формат", 400

        name = secrets.token_hex(8) + "_" + filename
        file.save(os.path.join(UPLOAD_FOLDER, name))

    return redirect("/")

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

