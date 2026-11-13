from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.utils import secure_filename
from models import db, User, Track, Favorite
from authlib.integrations.flask_client import OAuth
import os
import secrets
import hmac
import requests
import mimetypes

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)

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

        for filename in tracks:
            record = Track.query.filter_by(filename=filename).first()
            if record is None:
                record = Track(
                    filename=filename,
                    title=os.path.splitext(filename)[0]
                )
                db.session.add(record)

        db.session.commit()

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
        track_info={t.filename: t for t in Track.query.all()},
        top_tracks=Track.query.order_by(Track.plays.desc()).limit(10).all(),
        admin=session.get("admin", False),
        user=User.query.get(session.get("user_id"))
    )

@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/play/<path:filename>", methods=["POST"])
def count_play(filename):
    track = Track.query.filter_by(filename=filename).first()
    if not track:
        return {"error": "Трек не найден"}, 404

    track.plays += 1
    db.session.commit()
    return {"plays": track.plays}


@app.route("/login/google")
def google_login():
    if not os.environ.get("GOOGLE_CLIENT_ID") or not os.environ.get("GOOGLE_CLIENT_SECRET"):
        return "Google-вход пока не настроен", 503

    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        info = token.get("userinfo") or google.parse_id_token(token)
        email = info.get("email", "").strip().lower()

        if not email or not info.get("email_verified"):
            return "Не удалось подтвердить Google-почту", 400

        user = User.query.filter_by(email=email).first()

        if user is None:
            base = email.split("@")[0][:25] or "user"
            username = base
            number = 1

            while User.query.filter_by(username=username).first():
                suffix = str(number)
                username = base[:30-len(suffix)] + suffix
                number += 1

            user = User(
                username=username,
                email=email,
                password_hash=secrets.token_hex(32)
            )
            db.session.add(user)
            db.session.commit()

        session.clear()
        session["user_id"] = user.id
        return redirect("/")

    except Exception:
        app.logger.exception("Google login failed")
        return "Ошибка входа через Google. Попробуй ещё раз.", 400


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

    title = request.form.get("title", "").strip()[:120] or os.path.splitext(filename)[0]
    artist = request.form.get("artist", "").strip()[:120] or "Неизвестный исполнитель"
    description = request.form.get("description", "").strip()[:2000]
    genre = request.form.get("genre", "").strip()[:60] or "Другой"

    year_raw = request.form.get("year", "").strip()
    try:
        year = int(year_raw) if year_raw else None
        if year and not 1900 <= year <= 2100:
            year = None
    except ValueError:
        year = None
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

        db.session.add(Track(
            filename=unique_name,
            title=title,
            artist=artist,
            description=description,
            genre=genre,
            year=year
        ))
        db.session.commit()

    except requests.RequestException as error:
        app.logger.error(
            "Supabase upload error: %s | Response: %s",
            error,
            getattr(getattr(error, "response", None), "text", "Нет ответа")
        )
        return "Ошибка загрузки в Supabase. Проверьте логи Render.", 500

    return redirect("/")


def delete_storage(path):
    response = requests.delete(
        SUPABASE_URL + "/storage/v1/object/music/" + path,
        headers=storage_headers(),
        timeout=30
    )
    response.raise_for_status()


@app.route("/admin/track/<int:track_id>/edit", methods=["POST"])
def edit_track(track_id):
    if not session.get("admin"):
        return "Доступ запрещён", 403

    track = db.session.get(Track, track_id)
    if not track:
        return "Трек не найден", 404

    title = request.form.get("title", "").strip()
    artist = request.form.get("artist", "").strip()
    description = request.form.get("description", "").strip()
    genre = request.form.get("genre", "").strip()
    year_raw = request.form.get("year", "").strip()

    if not title or len(title) > 120:
        return "Название обязательно (до 120 символов)", 400
    if len(artist) > 120 or len(description) > 2000 or len(genre) > 60:
        return "Слишком длинное поле", 400

    try:
        year = int(year_raw) if year_raw else None
    except ValueError:
        return "Некорректный год", 400

    if year is not None and not 1900 <= year <= 2100:
        return "Год должен быть от 1900 до 2100", 400

    track.title = title
    track.artist = artist or "Неизвестный исполнитель"
    track.description = description
    track.genre = genre or "Другой"
    track.year = year

    db.session.commit()
    return redirect("/")


@app.route("/admin/track/<int:track_id>/delete", methods=["POST"])
def delete_track(track_id):
    if not session.get("admin"):
        return "Доступ запрещён", 403

    track = db.session.get(Track, track_id)
    if not track:
        return "Трек не найден", 404

    if not SUPABASE_URL or not SUPABASE_KEY:
        return "Supabase не настроен", 500

    try:
        base = os.path.splitext(track.filename)[0]
        cover_objects = list_storage("covers")

        for item in cover_objects:
            name = item.get("name", "")
            if name.startswith("covers/"):
                name = name[len("covers/"):]
            if os.path.splitext(name)[0] == base:
                delete_storage("covers/" + name)

        delete_storage("audio/" + track.filename)

    except requests.RequestException:
        app.logger.exception("Не удалось удалить файлы трека")
        return "Ошибка удаления файлов в Supabase", 500

    Favorite.query.filter_by(track=track.filename).delete()
    db.session.delete(track)
    db.session.commit()

    return redirect("/")




@app.route("/api/youtube/search")
def youtube_search():
    api_key = os.environ.get("YOUTUBE_API_KEY", "")
    query = request.args.get("q", "").strip()

    if not api_key:
        return {"error": "YouTube API не настроен"}, 503

    if len(query) < 2:
        return {"items": []}

    try:
        response = requests.get(
            "https://www.googleapis.com/youtube/v3/search",
            params={
                "part": "snippet",
                "q": query,
                "type": "video",
                "videoEmbeddable": "true",
                "videoSyndicated": "true",
                "maxResults": 10,
                "key": api_key
            },
            timeout=15
        )
        response.raise_for_status()
        data = response.json()

        items = []
        for item in data.get("items", []):
            snippet = item.get("snippet", {})
            video_id = item.get("id", {}).get("videoId")
            if not video_id:
                continue

            thumbnails = snippet.get("thumbnails", {})
            image = (
                thumbnails.get("high")
                or thumbnails.get("medium")
                or thumbnails.get("default")
                or {}
            )

            items.append({
                "videoId": video_id,
                "title": snippet.get("title", ""),
                "channelTitle": snippet.get("channelTitle", ""),
                "thumbnail": image.get("url", "")
            })

        return {"items": items}

    except requests.RequestException:
        app.logger.exception("Ошибка поиска YouTube")
        return {"error": "Не удалось выполнить поиск YouTube"}, 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
