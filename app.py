from flask import Flask, render_template, request, redirect, session
import os, secrets, hmac

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

os.makedirs("static/uploads", exist_ok=True)

@app.route("/")
def home():
    files = os.listdir("static/uploads")
    return render_template("index.html", media=files, admin=session.get("admin", False))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        with open("admin.txt") as f:
            password = f.read().strip()
        if hmac.compare_digest(request.form.get("password", ""), password):
            session["admin"] = True
            return redirect("/")
        return "Неверный пароль"
    return render_template("login.html")

@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("admin"):
        return "Доступ запрещён", 403
    file = request.files.get("file")
    if file and file.filename:
        name = secrets.token_hex(8) + "_" + os.path.basename(file.filename)
        file.save(os.path.join("static/uploads", name))
    return redirect("/")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
