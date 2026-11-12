from flask import Flask, render_template, request, redirect, session
from werkzeug.utils import secure_filename
from models import db, User
import os
import secrets
import hmac
import requests
import mimetypes

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///shaman.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

UPLOAD_FOLDER = "static/uploads"
COVER_FOLDER = "static/covers"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(COVER_FOLDER, exist_ok=True)

AUDIO_EXTENSIONS = {"mp3", "wav", "ogg", "m4a"}
IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

def storage_headers(content_type="application/json"):
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
        "Content-Type": content_type
    }

def list_storage(prefix):
    response = requests.post(
        SUPABASE_URL + "/storage/v1/object/list/music",
        headers=storage_headers(),
        json={"prefix": prefix, "limit": 1000, "offset": 0},
        timeout=30
    )
    response.raise_for_status()
    return response.json()

def public_url(path):
    return SUPABASE_URL + "/storage/v1/object/public/music/" + path

def upload_storage(path, file, content_type):
    response = requests.post(
        SUPABASE_URL + "/storage/v1/object/music/" + path,
        headers={
            **storage_headers(content_type),
            "x-upsert": "false"
        },
        data=file.read(),
        timeout=120
    )
    response.raise_for_status()

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    tracks = []
    covers = {}
    track_urls = {}

    try:
        audio_objects = list_storage("audio")
        cover_objects = list_storage("covers")

        for item in audio_objects:
            name = item.get("name", "")
            if name.startswith("audio/"):
                name = name[len("audio/"):]

            if "." in name and name.rsplit(".", 1)[1].lower() in AUDIO_EXTENSIONS:
                tracks.append(name)
                track_urls[name] = public_url("audio/" + name)

        tracks.sort(reverse=True)

        for item in cover_objects:
            name = item.get("name", "")
            if name.startswith("covers/"):
                name = name[len("covers/"):]

            covers[name] = public_url("covers/" + name)

        for track in tracks:
            base = os.path.splitext(track)[0]
            for ext in IMAGE_EXTENSIONS:
                cover_name = base + "." + ext
                if cover_name in covers:
                    covers[track] = covers[cover_name]
                    break

    except Exception as error:
        app.logger.error("Supabase storage error: %s", error)

    return render_template(
        "index.html",
        tracks=tracks,
        covers=covers,
        track_urls=track_urls,
        admin=session.get("admin", False),
        user=User.query.get(session.get("user_id"))
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            return "Логин должен содержать от 3 до 30 символов", 400
        if len(password) < 8:
            return "Пароль должен содержать минимум 8 символов", 400
        if User.query.filter_by(username=username).first():
            return "Такой логин уже занят", 400
        if User.query.filter_by(email=email).first():
            return "Эта почта уже зарегистрирована", 400

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session.clear()
        session["user_id"] = user.id
        return redirect("/")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            return redirect("/")

        return "Неверный логин или пароль", 401

    return render_template("login.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = os.environ.get("ADMIN_PASSWORD", "")

        if password and hmac.compare_digest(
            request.form.get("password", ""), password
        ):
            session["admin"] = True
            return redirect("/")

        return "Неверный пароль", 401

    return render_template("admin_login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("admin"):
        return "Доступ запрещён", 403

    if not SUPABASE_URL or not SUPABASE_KEY:
        return "Supabase не настроен в Render", 500

    file = request.files.get("file")
    if not file or not file.filename:
        return "Файл не выбран", 400

    filename = secure_filename(file.filename)
    if "." not in filename:
        return "Неподдерживаемый формат", 400

    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in AUDIO_EXTENSIONS:
        return "Разрешены MP3, WAV, OGG и M4A", 400

    unique_name = secrets.token_hex(8) + "_" + filename
    audio_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    try:
        upload_storage("audio/" + unique_name, file, audio_type)

        cover = request.files.get("cover")
        if cover and cover.filename:
            cover_filename = secure_filename(cover.filename)

            if "." in cover_filename:
                cover_ext = cover_filename.rsplit(".", 1)[1].lower()

                if cover_ext in IMAGE_EXTENSIONS:
                    cover_name = os.path.splitext(unique_name)[0] + "." + cover_ext
                    cover_type = mimetypes.guess_type(cover_name)[0] or "image/jpeg"
                    upload_storage("covers/" + cover_name, cover, cover_type)

    except requests.RequestException as error:
        app.logger.error("Supabase upload error: %s", error)
        return "Ошибка загрузки в Supabase. Проверь настройки хранилища.", 500

    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
