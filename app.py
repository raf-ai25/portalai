import os
import secrets
import unicodedata
from functools import wraps
from pathlib import Path

import bleach
import markdown
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from markupsafe import Markup
from io import BytesIO
from flask import send_file
from openpyxl import Workbook
from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================
# تنظیمات پایه
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "CHANGE_THIS_SECRET_KEY_IN_PRODUCTION_2026",
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + str(BASE_DIR / "db1.sqlite3")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ============================================================
# مدل‌های دیتابیس
# ============================================================

user_category_access = db.Table(
    "user_category_access",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column(
        "category_id",
        db.Integer,
        db.ForeignKey("category.id"),
        primary_key=True,
    ),
)


user_app_access = db.Table(
    "user_app_access",
    db.Column(
        "user_id",
        db.Integer,
        db.ForeignKey("user.id"),
        primary_key=True,
    ),
    db.Column(
        "app_id",
        db.Integer,
        db.ForeignKey("app_item.id"),
        primary_key=True,
    ),
)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    active = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    categories = db.relationship(
        "Category",
        secondary=user_category_access,
        backref="allowed_users",
        lazy=True,
    )

    apps = db.relationship(
        "AppItem",
        secondary=user_app_access,
        backref="allowed_users",
        lazy=True,
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140), nullable=False)
    icon = db.Column(db.String(80), default="fa-layer-group")
    image_url = db.Column(db.String(500), default="")
    description = db.Column(db.Text, default="")

    active = db.Column(
        db.Boolean,
        default=True,
        nullable=False,
    )

    apps = db.relationship(
        "AppItem",
        backref="category",
        cascade="all, delete-orphan",
        lazy=True,
    )




class AppItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    category_id = db.Column(
        db.Integer,
        db.ForeignKey("category.id"),
        nullable=False,
    )

    title = db.Column(db.String(140), nullable=False)
    icon = db.Column(db.String(80), default="fa-cube")
    description = db.Column(db.Text, default="")
    link = db.Column(db.String(500), default="#")
    enabled = db.Column(db.Boolean, default=True)



# ============================================================
# امنیت و ابزارهای کمکی
# ============================================================

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def normalize_role_value(role):
    if role is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(role)).strip()
    normalized = normalized.replace("ي", "ی").replace("ك", "ک")
    return normalized


def user_can_access_settings(user):
    if not user:
        return False

    if getattr(user, "is_admin", False):
        return True

    role = getattr(user, "role", None)
    if role is None:
        return False

    return normalize_role_value(role) == "مدیر"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("برای مشاهده این صفحه ابتدا وارد شوید.", "warning")
            return redirect(url_for("login"))

        if not user.active:
            session.clear()
            flash("حساب کاربری شما غیرفعال است.", "danger")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user_can_access_settings(user):
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def superadmin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or user.username != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        if not submitted_token or submitted_token != session.get("csrf_token"):
            abort(400, "CSRF token نامعتبر است.")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.context_processor
def global_context():
    return {
        "current_user": current_user(),
        "current_theme": session.get("theme", "default"),
        "csrf_token": get_csrf_token(),
        "can_access_settings": user_can_access_settings,
    }


@app.template_filter("markdown_safe")
def markdown_safe(text):
    raw_html = markdown.markdown(
        text or "",
        extensions=["extra", "nl2br"],
    )

    allowed_tags = [
        "p", "br", "strong", "em", "b", "i",
        "ul", "ol", "li",
        "h1", "h2", "h3", "h4",
        "blockquote", "code", "pre",
        "a",
    ]

    clean_html = bleach.clean(
        raw_html,
        tags=allowed_tags,
        attributes={"a": ["href", "title", "target", "rel"]},
        protocols=["http", "https", "mailto"],
        strip=True,
    )

    return Markup(clean_html)


def can_access_category(category_id):
    user = current_user()

    if not user:
        return False

    if user.is_admin:
        return True

    return any(category.id == category_id for category in user.categories)


# ============================================================
# داده‌های اولیه
# ============================================================

def seed_database():
    if User.query.first():
        return

    admin = User(
        username="admin",
        active=True,
        is_admin=True,
    )
    admin.set_password("admin12345")
    db.session.add(admin)

    categories_data = [
        {
            "title": "طراحی و بهره‌وری",
            "icon": "fa-pen-nib",
            "description": "ابزارهای خلاقیت، مدیریت فعالیت‌ها و افزایش بهره‌وری تیمی.",
        },
        {
            "title": "فناوری و توسعه",
            "icon": "fa-code",
            "description": "سرویس‌های توسعه نرم‌افزار، زیرساخت و ابزارهای فنی.",
        },
        {
            "title": "آموزش و دانش",
            "icon": "fa-graduation-cap",
            "description": "منابع آموزشی، مستندات، دانش سازمانی و یادگیری.",
        },
        {
            "title": "ارتباطات و کسب‌وکار",
            "icon": "fa-comments",
            "description": "ابزارهای ارتباطی، همکاری تیمی و سرویس‌های کسب‌وکار.",
        },
    ]

    categories = []

    for data in categories_data:
        category = Category(
            title=data["title"],
            icon=data["icon"],
            description=data["description"],
        )
        db.session.add(category)
        categories.append(category)

    db.session.flush()

    apps_data = [
        {
            "category": categories[0],
            "title": "مدیریت پروژه",
            "icon": "fa-list-check",
            "description": """### مدیریت پروژه

سامانه‌ای برای ثبت، پیگیری و مدیریت فعالیت‌ها، وظایف و پروژه‌های سازمانی.""",
            "link": "https://example.com",
        },
        {
            "category": categories[1],
            "title": "محیط توسعه ابری",
            "icon": "fa-terminal",
            "description": """### محیط توسعه ابری

دسترسی یکپارچه به ابزارهای توسعه، مخازن کد و سرویس‌های فنی.""",
            "link": "https://example.com",
        },
        {
            "category": categories[2],
            "title": "کتابخانه دانش",
            "icon": "fa-book-open",
            "description": """### کتابخانه دانش

مرجع مستندات، راهنماها، فرآیندها و دانش سازمانی.""",
            "link": "https://example.com",
        },
        {
            "category": categories[3],
            "title": "مرکز ارتباط تیم",
            "icon": "fa-users",
            "description": """### مرکز ارتباط تیم

ابزار همکاری تیمی، اطلاع‌رسانی و تعامل بین واحدهای سازمان.""",
            "link": "https://example.com",
        },
    ]

    for data in apps_data:
        db.session.add(
            AppItem(
                category_id=data["category"].id,
                title=data["title"],
                icon=data["icon"],
                description=data["description"],
                link=data["link"],
                enabled=True,
            )
        )

    db.session.commit()


# ============================================================
# قالب اصلی
# ============================================================

BASE_TEMPLATE = """
<!doctype html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>{{ title }} | پورتال هوش مصنوعی فها</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">

    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">

    <style>
        :root {
            --primary: #4f46e5;
            --primary-dark: #3730a3;
            --sidebar: #171b2f;
            --sidebar-text: #dce1ff;
            --bg: #f3f5fb;
            --surface: #ffffff;
            --surface-soft: #f8f9ff;
            --text: #1d2433;
            --muted: #687083;
            --border: #e5e8f0;
            --shadow: 0 12px 35px rgba(32, 40, 75, .10);
        }

        body.theme-default {
            --primary: #4f46e5;
            --primary-dark: #3730a3;
            --sidebar: #171b2f;
            --sidebar-text: #dce1ff;
            --bg: #f3f5fb;
            --surface: #ffffff;
            --surface-soft: #f8f9ff;
            --text: #1d2433;
            --muted: #687083;
            --border: #e5e8f0;
        }

        body.theme-dark {
            --primary: #9b8cff;
            --primary-dark: #7868eb;
            --sidebar: #0d111b;
            --sidebar-text: #eef0ff;
            --bg: #121722;
            --surface: #1d2430;
            --surface-soft: #252d3b;
            --text: #f4f6fb;
            --muted: #b4bdcf;
            --border: #394355;
            --shadow: 0 12px 35px rgba(0, 0, 0, .30);
        }

        body.theme-lite {
            --primary: #8b5cf6;
            --primary-dark: #6d42d6;
            --sidebar: #402c73;
            --sidebar-text: #f7f3ff;
            --bg: #f5f3ff;
            --surface: #ffffff;
            --surface-soft: #fbfaff;
            --text: #303042;
            --muted: #71717f;
            --border: #e7defd;
            --shadow: 0 12px 35px rgba(106, 72, 172, .13);
        }

        * {
            font-family: "Vazirmatn", sans-serif;
        }

        body {
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            transition: all .25s ease;
        }

        .sidebar {
            width: 270px;
            min-height: 100vh;
            background: var(--sidebar);
            color: var(--sidebar-text);
            position: fixed;
            right: 0;
            top: 0;
            z-index: 1040;
            padding: 22px 15px;
            transition: transform .3s ease;
        }

        .brand {
            display: flex;
            gap: 12px;
            align-items: center;
            color: #fff;
            font-size: 1.1rem;
            font-weight: 800;
            padding: 10px 12px 25px;
            border-bottom: 1px solid rgba(255,255,255,.12);
            margin-bottom: 18px;
        }

        .brand-icon,
        .icon-box {
            display: grid;
            place-items: center;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--primary), #a78bfa);
            color: #fff;
        }

        .brand-icon {
            width: 42px;
            height: 42px;
        }

        .sidebar .nav-link {
            color: var(--sidebar-text);
            padding: 12px 14px;
            border-radius: 12px;
            margin-bottom: 7px;
            transition: .2s;
        }

        .sidebar .nav-link:hover,
        .sidebar .nav-link.active {
            color: #fff;
            background: rgba(255,255,255,.13);
        }

        .sidebar .nav-link i {
            width: 26px;
        }

        .main-content {
            margin-right: 270px;
            padding: 28px;
        }

        .topbar,
        .surface-card,
        .app-card,
        .stat-card,
        .table-wrap {
            background: var(--surface);
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
        }

        .topbar {
            padding: 14px 18px;
            border-radius: 16px;
            margin-bottom: 24px;
        }

        .surface-card,
        .table-wrap {
            border-radius: 18px;
            padding: 22px;
        }

        .app-card,
        .stat-card {
            border-radius: 18px;
            padding: 20px;
            height: 100%;
            color: var(--text);
            transition: transform .2s ease, box-shadow .2s ease;
        }

        .app-card:hover {
            transform: translateY(-6px);
            box-shadow: 0 18px 45px rgba(50, 48, 120, .18);
        }

        .app-link {
            text-decoration: none;
            color: inherit;
        }

        .icon-box {
            width: 58px;
            height: 58px;
            font-size: 1.35rem;
        }

        .text-muted,
        .muted {
            color: var(--muted) !important;
        }

        .form-control,
        .form-select,
        textarea {
            background: var(--surface-soft) !important;
            color: var(--text) !important;
            border-color: var(--border) !important;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: var(--primary) !important;
            box-shadow: 0 0 0 .25rem rgba(126, 92, 246, .18) !important;
        }

        .table {
            color: var(--text);
        }

        .table > :not(caption) > * > * {
            background: transparent;
            color: var(--text);
            border-bottom-color: var(--border);
        }

        .btn-primary {
            border: 0;
            background: var(--primary);
        }

        .btn-primary:hover {
            background: var(--primary-dark);
        }

        .nav-tabs {
            border-bottom-color: var(--border);
        }

        .nav-tabs .nav-link {
            color: var(--muted);
        }

        .nav-tabs .nav-link.active {
            background: var(--surface);
            color: var(--primary);
            border-color: var(--border) var(--border) var(--surface);
        }

        .theme-select {
            width: 150px;
        }

        .markdown p:last-child {
            margin-bottom: 0;
        }

        @media (max-width: 991px) {
            .sidebar {
                transform: translateX(110%);
            }

            .sidebar.show {
                transform: translateX(0);
            }

            .main-content {
                margin-right: 0;
                padding: 18px;
            }
        }
    </style>
</head>

<body class="theme-{{ current_theme }}">

    {% if current_user %}
    <aside id="sidebar" class="sidebar">
        <div class="brand">
            <span class="brand-icon"><i class="fa-solid fa-layer-group"></i></span>
            <span>پورتال هوش مصنوعی فها</span>
        </div>

        <nav class="nav flex-column">
            <a class="nav-link" href="{{ url_for('dashboard') }}">
                <i class="fa-solid fa-chart-line"></i>
                داشبورد
            </a>

            <a class="nav-link" href="{{ url_for('categories') }}">
                <i class="fa-solid fa-folder-tree"></i>
                دسته‌بندی اپلیکیشن‌ها
            </a>

            <a class="nav-link" href="{{ url_for('apps') }}">
                <i class="fa-solid fa-table-cells-large"></i>
                همه اپلیکیشن‌ها
            </a>


            {% if current_user and current_user.username == 'admin' %}
            <a class="nav-link" href="{{ url_for('users') }}">
                <i class="fa-solid fa-users-gear"></i>
                مدیریت کاربران
            </a>
            {% endif %}

            {% if current_user and can_access_settings(current_user) %}
            <a class="nav-link" href="{{ url_for('settings') }}">
                <i class="fa-solid fa-sliders"></i>
                تنظیمات و مدیریت محتوا
            </a>
            {% endif %}

            <a class="nav-link mt-3" href="{{ url_for('logout') }}">
                <i class="fa-solid fa-right-from-bracket"></i>
                خروج
            </a>
        </nav>
    </aside>
    {% endif %}

    <main class="{% if current_user %}main-content{% else %}container py-5{% endif %}">

        {% if current_user %}
        <div class="topbar d-flex align-items-center justify-content-between gap-3 flex-wrap">
            <div>
                <strong>سلام {{ current_user.username }}</strong>
                <span class="muted ms-2">به پورتال خوش آمدید</span>
            </div>

            <div class="d-flex align-items-center gap-2">
                <button class="btn btn-outline-secondary d-lg-none" onclick="toggleSidebar()">
                    <i class="fa-solid fa-bars"></i>
                </button>

                <form method="post" action="{{ url_for('set_theme') }}">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

                    <select class="form-select theme-select" name="theme" onchange="this.form.submit()">
                        <option value="dark" {% if current_theme == 'dark' %}selected{% endif %}>
                            تم Dark
                        </option>
                        <option value="default" {% if current_theme == 'default' %}selected{% endif %}>
                            تم پیش‌فرض
                        </option>
                        <option value="lite" {% if current_theme == 'lite' %}selected{% endif %}>
                            تم Lite
                        </option>
                    </select>
                </form>
            </div>
        </div>
        {% endif %}

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            {% endfor %}
        {% endwith %}

        {{ content|safe }}
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

    <script>
        function toggleSidebar() {
            document.getElementById("sidebar").classList.toggle("show");
        }
    </script>
</body>
</html>
"""


def render_page(title, content_template, **context):
    rendered_content = render_template_string(content_template, **context)

    return render_template_string(
        BASE_TEMPLATE,
        title=title,
        content=Markup(rendered_content),
    )

def workbook_response(filename, headers, rows):
    """ساخت و ارسال فایل Excel بدون ایجاد فایل موقت روی سرور."""
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Export"

    worksheet.append(headers)

    for row in rows:
        worksheet.append(row)

    # کمی خواناتر شدن ستون‌ها
    for column_cells in worksheet.columns:
        max_length = 0

        for cell in column_cells:
            value = "" if cell.value is None else str(cell.value)
            max_length = max(max_length, len(value))

        column_letter = column_cells[0].column_letter
        worksheet.column_dimensions[column_letter].width = min(
            max(max_length + 2, 12),
            50,
        )

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )


# ============================================================
# ورود، خروج و Theme
# ============================================================

@app.route("/", methods=["GET"])
@login_required
def dashboard():
    categories = Category.query.filter_by(active=True).all()
    apps = AppItem.query.filter_by(enabled=True).limit(6).all()

    dashboard_template = """
    <div class="mb-4">
        <h3 class="fw-bold">داشبورد</h3>
        <p class="muted mb-0">دسترسی سریع به سرویس‌ها و اپلیکیشن‌های سازمانی</p>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-md-4">
            <div class="stat-card">
                <div class="muted">تعداد دسته‌بندی‌ها</div>
                <div class="display-6 fw-bold">{{ categories|length }}</div>
            </div>
        </div>

        <div class="col-md-4">
            <div class="stat-card">
                <div class="muted">اپلیکیشن‌های فعال</div>
                <div class="display-6 fw-bold">{{ apps|length }}</div>
            </div>
        </div>

        <div class="col-md-4">
            <div class="stat-card">
                <div class="muted">کاربر جاری</div>
                <div class="fs-4 fw-bold">{{ current_user.username }}</div>
            </div>
        </div>
    </div>

    <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="fw-bold mb-0">اپلیکیشن‌های منتخب</h5>
        <a href="{{ url_for('apps') }}" class="btn btn-sm btn-outline-primary">
            مشاهده همه
        </a>
    </div>

    <div class="row g-3">
        {% for item in apps %}
        <div class="col-md-6 col-xl-4">
            {% if item.link and item.link != '#' %}
            <a class="app-link" href="{{ item.link }}">
            {% else %}
            <a class="app-link" href="{{ url_for('app_detail', app_id=item.id) }}">
            {% endif %}
                <div class="app-card">
                    <div class="icon-box mb-3">
                        <i class="fa-solid {{ item.icon }}"></i>
                    </div>
                    <h5 class="fw-bold">{{ item.title }}</h5>
                    <div class="markdown muted">
                        {{ item.description|markdown_safe }}
                    </div>
                </div>
            </a>
        </div>
        {% endfor %}
    </div>
    """

    return render_page(
        "داشبورد",
        dashboard_template,
        categories=categories,
        apps=apps,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.active and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            get_csrf_token()

            flash("با موفقیت وارد شدید.", "success")
            return redirect(url_for("dashboard"))

        flash("نام کاربری یا رمز عبور صحیح نیست.", "danger")

    login_template = """
    <div class="row justify-content-center">
        <div class="col-md-7 col-lg-5">
            <div class="surface-card mt-5">
                <div class="text-center mb-4">
                    <div class="icon-box mx-auto mb-3">
                        <i class="fa-solid fa-layer-group"></i>
                    </div>
                    <h4 class="fw-bold">ورود به پلتفرم هوش مصنوعی</h4>
                    <p class="muted mb-0">نام کاربری و رمز عبور خود را وارد کنید.</p>
                </div>

                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

                    <div class="mb-3">
                        <label class="form-label">نام کاربری</label>
                        <input class="form-control" name="username" required autofocus>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">رمز عبور</label>
                        <input class="form-control" type="password" name="password" required>
                    </div>

                    <button class="btn btn-primary w-100">
                        <i class="fa-solid fa-right-to-bracket ms-1"></i>
                        ورود به سامانه
                    </button>
                </form>

                <div class="alert alert-warning mt-4 mb-0 small">
                    ورود اولیه: <strong>کاربر مهمان</strong> /
                    <strong>با راهبر سامانه تماش بگیرید</strong>
                    <br>
                    پس از ورود، رمز مدیر را تغییر دهید.
                </div>
            </div>
        </div>
    </div>
    """

    return render_page("ورود", login_template)


@app.route("/logout")
def logout():
    session.clear()
    flash("با موفقیت خارج شدید.", "success")
    return redirect(url_for("login"))


@app.post("/theme")
@login_required
def set_theme():
    theme = request.form.get("theme", "default")

    if theme not in {"default", "dark", "lite"}:
        theme = "default"

    session["theme"] = theme

    return redirect(request.referrer or url_for("dashboard"))


# ============================================================
# اپلیکیشن‌ها و دسته‌بندی‌ها
# ============================================================

@app.get("/apps")
@login_required
def apps():
    query_text = request.args.get("q", "").strip()

    query = AppItem.query.filter_by(enabled=True)

    if query_text:
        query = query.filter(AppItem.title.ilike(f"%{query_text}%"))

    items = query.order_by(AppItem.title.asc()).all()

    apps_template = """
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
        <div>
            <h3 class="fw-bold mb-1">همه اپلیکیشن‌ها</h3>
            <p class="muted mb-0">کاتالوگ سرویس‌ها و برنامه‌های سازمانی</p>
        </div>

        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">
            <i class="fa-solid fa-arrow-right"></i>
            بازگشت
        </a>
    </div>

    <div class="surface-card mb-4">
        <form class="row g-2">
            <div class="col-md-10">
                <input
                    class="form-control"
                    name="q"
                    value="{{ q }}"
                    placeholder="جستجو در عنوان اپلیکیشن‌ها..."
                >
            </div>
            <div class="col-md-2">
                <button class="btn btn-primary w-100">
                    <i class="fa-solid fa-magnifying-glass"></i>
                    جستجو
                </button>
            </div>
        </form>
    </div>

    <div class="row g-3">
        {% for item in apps %}
        <div class="col-md-6 col-xl-4">
            {% if item.link and item.link != '#' %}
            <a class="app-link" href="{{ item.link }}">
            {% else %}
            <a class="app-link" href="{{ url_for('app_detail', app_id=item.id) }}">
            {% endif %}
                <div class="app-card">
                    <div class="d-flex justify-content-between gap-3">
                        <div class="icon-box">
                            <i class="fa-solid {{ item.icon }}"></i>
                        </div>
                        <span class="badge text-bg-light align-self-start">
                            {{ item.category.title }}
                        </span>
                    </div>

                    <h5 class="fw-bold mt-3">{{ item.title }}</h5>

                    <div class="markdown muted">
                        {{ item.description|markdown_safe }}
                    </div>

                    <div class="mt-3 small text-primary">
                        ورود مستقیم به سرویس
                        <i class="fa-solid fa-arrow-left"></i>
                    </div>
                </div>
            </a>
        </div>
        {% else %}
        <div class="col-12">
            <div class="alert alert-info">
                اپلیکیشنی برای نمایش وجود ندارد.
            </div>
        </div>
        {% endfor %}
    </div>
    """

    return render_page("همه اپلیکیشن‌ها", apps_template, apps=items, q=query_text)

# اضافه شد
@app.get("/app/<int:app_id>")
@login_required
def app_detail(app_id):
    item = db.session.get(AppItem, app_id)

    if item is None or not item.enabled:
        abort(404)

    user = current_user()
    if not user.is_admin:
        allowed_categories = {c.id for c in user.categories}
        allowed_apps = {a.id for a in user.apps}
        if item.category_id not in allowed_categories and item.id not in allowed_apps:
            abort(403)

    app_detail_template = """
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
        <div>
            <h3 class="fw-bold mb-1">{{ item.title }}</h3>
            {% if item.category %}
            <p class="muted mb-0">{{ item.category.title }}</p>
            {% endif %}
        </div>

        <a href="{{ url_for('apps') }}" class="btn btn-outline-secondary">
            <i class="fa-solid fa-arrow-right"></i>
            بازگشت به اپلیکیشن‌ها
        </a>
    </div>

    <div class="surface-card">
        <div class="icon-box mb-3">
            <i class="fa-solid {{ item.icon }}"></i>
        </div>

        <div class="markdown muted">
            {{ item.description|markdown_safe }}
        </div>

        {% if item.link and item.link != "#" %}
        <a href="{{ item.link }}" class="btn btn-primary mt-4" target="_blank" rel="noopener noreferrer">
            <i class="fa-solid fa-arrow-up-right-from-square"></i>
            ورود به برنامه
        </a>
        {% endif %}
    </div>
    """

    return render_page(
        item.title,
        app_detail_template,
        item=item,
    )


# Users:
@app.route("/users", methods=["GET", "POST"])
@superadmin_required
def users():
    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            active = request.form.get("active") == "1"
            is_admin = request.form.get("is_admin") == "1"

            if not username or not password:
                flash("نام کاربری و رمز عبور الزامی است.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("این نام کاربری قبلاً ثبت شده است.", "danger")
            else:
                user = User(
                    username=username,
                    active=active,
                    is_admin=is_admin,
                )
                user.set_password(password)

                category_ids = [
                    int(v) for v in request.form.getlist("category_ids") if v.isdigit()
                ]
                app_ids = [
                    int(v) for v in request.form.getlist("app_ids") if v.isdigit()
                ]

                user.categories = Category.query.filter(
                    Category.id.in_(category_ids)
                ).all() if category_ids else []

                user.apps = AppItem.query.filter(
                    AppItem.id.in_(app_ids)
                ).all() if app_ids else []

                db.session.add(user)
                db.session.commit()
                flash("کاربر با موفقیت ایجاد شد.", "success")
                return redirect(url_for("users"))

        elif action == "update":
            user_id = request.form.get("user_id", type=int)
            user = db.session.get(User, user_id)

            if user is None:
                flash("کاربر یافت نشد.", "danger")
            else:
                user.username = request.form.get("username", "").strip() or user.username
                new_password = request.form.get("password", "").strip()
                user.active = request.form.get("active") == "1"
                user.is_admin = request.form.get("is_admin") == "1"

                if new_password:
                    user.set_password(new_password)

                category_ids = [
                    int(v) for v in request.form.getlist("category_ids") if v.isdigit()
                ]
                app_ids = [
                    int(v) for v in request.form.getlist("app_ids") if v.isdigit()
                ]

                user.categories = Category.query.filter(
                    Category.id.in_(category_ids)
                ).all() if category_ids else []

                user.apps = AppItem.query.filter(
                    AppItem.id.in_(app_ids)
                ).all() if app_ids else []

                db.session.commit()
                flash("تغییرات کاربر ذخیره شد.", "success")
                return redirect(url_for("users"))

    items = User.query.order_by(User.username.asc()).all()
    categories = Category.query.order_by(Category.title.asc()).all()
    apps_list = AppItem.query.order_by(AppItem.title.asc()).all()

    users_template = """
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
        <div>
            <h3 class="fw-bold mb-1">مدیریت کاربران</h3>
            <p class="muted mb-0">افزودن، ویرایش و تعیین دسترسی کاربران</p>
        </div>

        <div class="d-flex gap-2">
            <a href="{{ url_for('export_users') }}"
               class="btn btn-outline-success">
                <i class="fa-solid fa-file-excel"></i>
                دانلود Excel
            </a>

            <a href="{{ url_for('dashboard') }}"
               class="btn btn-outline-secondary">
                <i class="fa-solid fa-arrow-right"></i>
                بازگشت
            </a>
        </div>
    </div>


    <div class="surface-card mb-4">
        <form method="post" class="row g-3">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="action" value="create">

            <div class="col-md-3">
                <label class="form-label">نام کاربری</label>
                <input name="username" class="form-control" required>
            </div>

            <div class="col-md-3">
                <label class="form-label">رمز عبور</label>
                <input name="password" type="password" class="form-control" required>
            </div>

            <div class="col-md-2">
                <label class="form-label">وضعیت</label>
                <select name="active" class="form-select">
                    <option value="1">فعال</option>
                    <option value="0">غیرفعال</option>
                </select>
            </div>

            <div class="col-md-2">
                <label class="form-label">نقش</label>
                <select name="is_admin" class="form-select">
                    <option value="0">کاربر</option>
                    <option value="1">مدیر</option>
                </select>
            </div>

            <div class="col-12">
                <label class="form-label">دسترسی به دسته‌ها</label>
                <div class="d-flex flex-wrap gap-2">
                    <label class="badge text-bg-light border">
                        <input type="checkbox" class="select-all-checkbox" data-target="create-category-access">
                        انتخاب همه
                    </label>
                    {% for category in categories %}
                    <label class="badge text-bg-light border">
                        <input type="checkbox" class="create-category-access" name="category_ids" value="{{ category.id }}">
                        {{ category.title }}
                    </label>
                    {% endfor %}
                </div>
            </div>

            <div class="col-12">
                <label class="form-label">دسترسی به اپ‌ها</label>
                <div class="d-flex flex-wrap gap-2">
                    <label class="badge text-bg-light border">
                        <input type="checkbox" class="select-all-checkbox" data-target="create-app-access">
                        انتخاب همه
                    </label>
                    {% for app in apps_list %}
                    <label class="badge text-bg-light border">
                        <input type="checkbox" class="create-app-access" name="app_ids" value="{{ app.id }}">
                        {{ app.title }}
                    </label>
                    {% endfor %}
                </div>
            </div>

            <div class="col-12">
                <button class="btn btn-primary" type="submit">
                    <i class="fa-solid fa-plus"></i>
                    افزودن کاربر
                </button>
            </div>
        </form>
    </div>

    <div class="surface-card">
        <div class="table-responsive">
            <table class="table align-middle mb-0">
                <thead>
                    <tr>
                        <th>کاربر</th>
                        <th>وضعیت</th>
                        <th>نقش</th>
                        <th>دسترسی</th>
                        <th>عملیات</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>
                            {% if user.active %}
                            <span class="badge text-bg-success">فعال</span>
                            {% else %}
                            <span class="badge text-bg-danger">غیرفعال</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if user.is_admin %}
                            <span class="badge text-bg-primary">مدیر</span>
                            {% else %}
                            <span class="badge text-bg-light">کاربر</span>
                            {% endif %}
                        </td>
                        <td>
                            <div class="small">
                                <div>{{ user.categories|length }} گروه</div>
                                <div>{{ user.apps|length }} اپ</div>
                            </div>
                        </td>
                        <td>
                            <form method="post" action="{{ url_for('delete_user', user_id=user.id) }}" class="d-inline">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                                <button class="btn btn-sm btn-outline-danger" type="submit">
                                    <i class="fa-solid fa-trash"></i>
                                </button>
                            </form>
                            <button class="btn btn-sm btn-outline-secondary"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#edit-user-{{ user.id }}">
                                <i class="fa-solid fa-pen"></i>
                            </button>
                        </td>
                    </tr>
                    <tr class="collapse" id="edit-user-{{ user.id }}">
                        <td colspan="5">
                            <form method="post" class="row g-3 py-2">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                                <input type="hidden" name="action" value="update">
                                <input type="hidden" name="user_id" value="{{ user.id }}">

                                <div class="col-md-3">
                                    <input name="username" class="form-control" value="{{ user.username }}" required>
                                </div>

                                <div class="col-md-3">
                                    <input name="password" type="password" class="form-control" placeholder="رمز جدید">
                                </div>

                                <div class="col-md-2">
                                    <select name="active" class="form-select">
                                        <option value="1" {% if user.active %}selected{% endif %}>فعال</option>
                                        <option value="0" {% if not user.active %}selected{% endif %}>غیرفعال</option>
                                    </select>
                                </div>

                                <div class="col-md-2">
                                    <select name="is_admin" class="form-select">
                                        <option value="0" {% if not user.is_admin %}selected{% endif %}>کاربر</option>
                                        <option value="1" {% if user.is_admin %}selected{% endif %}>مدیر</option>
                                    </select>
                                </div>

                                <div class="col-12">
                                    <label class="form-label">دسته‌های مجاز</label>
                                    <div class="d-flex flex-wrap gap-2">
                                        <label class="badge text-bg-light border">
                                            <input type="checkbox" class="select-all-checkbox" data-target="edit-category-access-{{ user.id }}">
                                            انتخاب همه
                                        </label>
                                        {% for category in categories %}
                                        <label class="badge text-bg-light border">
                                            <input type="checkbox" class="edit-category-access-{{ user.id }}" name="category_ids" value="{{ category.id }}"
                                                   {% if category in user.categories %}checked{% endif %}>
                                            {{ category.title }}
                                        </label>
                                        {% endfor %}
                                    </div>
                                </div>

                                <div class="col-12">
                                    <label class="form-label">اپ‌های مجاز</label>
                                    <div class="d-flex flex-wrap gap-2">
                                        <label class="badge text-bg-light border">
                                            <input type="checkbox" class="select-all-checkbox" data-target="edit-app-access-{{ user.id }}">
                                            انتخاب همه
                                        </label>
                                        {% for app in apps_list %}
                                        <label class="badge text-bg-light border">
                                            <input type="checkbox" class="edit-app-access-{{ user.id }}" name="app_ids" value="{{ app.id }}"
                                                   {% if app in user.apps %}checked{% endif %}>
                                            {{ app.title }}
                                        </label>
                                        {% endfor %}
                                    </div>
                                </div>

                                <div class="col-12">
                                    <button class="btn btn-primary" type="submit">
                                        <i class="fa-solid fa-floppy-disk"></i>
                                        ذخیره تغییرات
                                    </button>
                                </div>
                            </form>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="5" class="text-center muted">کاربری ثبت نشده است.</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <script>
    (function () {
        function targetCheckboxes(control) {
            var targetClass = control.getAttribute("data-target");
            if (!targetClass) return [];
            var escaped = window.CSS && CSS.escape
                ? CSS.escape(targetClass)
                : targetClass.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
            return document.querySelectorAll("." + escaped);
        }

        function updateSelectAll(control) {
            var targets = targetCheckboxes(control);
            var checkedCount = Array.prototype.filter.call(targets, function (checkbox) {
                return checkbox.checked;
            }).length;
            control.checked = targets.length > 0 && checkedCount === targets.length;
            control.indeterminate = checkedCount > 0 && checkedCount < targets.length;
        }

        function updateAllSelectControls() {
            document.querySelectorAll(".select-all-checkbox").forEach(updateSelectAll);
        }

        function initializeSelectAll() {
            updateAllSelectControls();
            document.addEventListener("change", function (event) {
                if (event.target.matches(".select-all-checkbox")) {
                    targetCheckboxes(event.target).forEach(function (checkbox) {
                        checkbox.checked = event.target.checked;
                    });
                    updateSelectAll(event.target);
                } else if (event.target.matches("[class*='create-category-access'], [class*='create-app-access'], [class*='edit-category-access-'], [class*='edit-app-access-']")) {
                    updateAllSelectControls();
                }
            });
        }

        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", initializeSelectAll);
        } else {
            initializeSelectAll();
        }
    })();
    </script>
    """

    return render_page(
        "مدیریت کاربران",
        users_template,
        users=items,
        categories=categories,
        apps_list=apps_list,
    )

@app.post("/users/<int:user_id>/delete")
@superadmin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash("آخرین مدیر سامانه را نمی‌توان حذف کرد.", "danger")
        return redirect(url_for("users"))
    db.session.delete(user)
    db.session.commit()
    flash("کاربر حذف شد.", "success")
    return redirect(url_for("users"))




# Setting:

@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "create_category":
            category = Category(
                title=request.form.get("title", "").strip(),
                icon=request.form.get("icon", "fa-layer-group").strip(),
                image_url=request.form.get("image_url", "").strip(),
                description=request.form.get("description", "").strip(),
                active=request.form.get("active", "1") == "1",
            )

            
            db.session.add(category)
            db.session.commit()
            flash("گروه اپلیکیشن ایجاد شد.", "success")
            return redirect(url_for("settings", tab="categories"))

        if action == "update_category":
            category = db.session.get(Category, request.form.get("category_id", type=int))
            if category is None:
                abort(404)
            category.title = request.form.get("title", "").strip()
            category.icon = request.form.get("icon", "fa-layer-group").strip()
            category.image_url = request.form.get("image_url", "").strip()
            category.description = request.form.get("description", "").strip()
            category.active = request.form.get("active", "1") == "1"

            db.session.commit()
            flash("گروه اپلیکیشن به‌روزرسانی شد.", "success")
            return redirect(url_for("settings", tab="categories"))

        if action == "delete_category":
            category = db.session.get(Category, request.form.get("category_id", type=int))
            if category is None:
                abort(404)
            db.session.delete(category)
            db.session.commit()
            flash("گروه اپلیکیشن حذف شد.", "success")
            return redirect(url_for("settings", tab="categories"))

        if action == "create_app":
            item = AppItem(
                category_id=request.form.get("category_id", type=int),
                title=request.form.get("title", "").strip(),
                icon=request.form.get("icon", "fa-cube").strip(),
                description=request.form.get("description", "").strip(),
                link=request.form.get("link", "#").strip(),
                enabled=request.form.get("enabled") == "1",
            )
            db.session.add(item)
            db.session.commit()
            flash("اپلیکیشن ایجاد شد.", "success")
            return redirect(url_for("settings", tab="apps"))

        if action == "update_app":
            item = db.session.get(AppItem, request.form.get("app_id", type=int))
            if item is None:
                abort(404)
            item.category_id = request.form.get("category_id", type=int)
            item.title = request.form.get("title", "").strip()
            item.icon = request.form.get("icon", "fa-cube").strip()
            item.description = request.form.get("description", "").strip()
            item.link = request.form.get("link", "#").strip()
            item.enabled = request.form.get("enabled") == "1"
            db.session.commit()
            flash("اپلیکیشن به‌روزرسانی شد.", "success")
            return redirect(url_for("settings", tab="apps"))

        if action == "delete_app":
            item = db.session.get(AppItem, request.form.get("app_id", type=int))
            if item is None:
                abort(404)
            db.session.delete(item)
            db.session.commit()
            flash("اپلیکیشن حذف شد.", "success")
            return redirect(url_for("settings", tab="apps"))

    categories = Category.query.order_by(Category.title.asc()).all()
    apps_list = AppItem.query.order_by(AppItem.title.asc()).all()
    active_tab = request.args.get("tab", "categories")

    settings_template = """
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
        <div>
            <h3 class="fw-bold mb-1">تنظیمات و مدیریت محتوا</h3>
            <p class="muted mb-0">مدیریت گروه‌های اپلیکیشن و اپلیکیشن‌ها</p>
        </div>

        <div class="d-flex flex-wrap gap-2">
            <a href="{{ url_for('export_categories') }}"
               class="btn btn-outline-success">
                <i class="fa-solid fa-file-excel"></i>
                Excel گروه‌ها
            </a>

            <a href="{{ url_for('export_apps') }}"
               class="btn btn-outline-success">
                <i class="fa-solid fa-file-excel"></i>
                Excel اپلیکیشن‌ها
            </a>

            <a href="{{ url_for('dashboard') }}"
               class="btn btn-outline-secondary">
                <i class="fa-solid fa-arrow-right"></i>
                بازگشت
            </a>
        </div>
    </div>
    

    <ul class="nav nav-tabs mb-4">
        <li class="nav-item">
            <a class="nav-link {% if active_tab == 'categories' %}active{% endif %}"
               href="{{ url_for('settings', tab='categories') }}">
                گروه اپلیکیشن
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link {% if active_tab == 'apps' %}active{% endif %}"
               href="{{ url_for('settings', tab='apps') }}">
                اپلیکیشن‌ها
            </a>
        </li>
    </ul>

    {% if active_tab == 'categories' %}
    <div class="surface-card mb-4">
        <form method="post" class="row g-3">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="action" value="create_category">

            <div class="col-md-4">
                <label class="form-label">عنوان</label>
                <input name="title" class="form-control" required>
            </div>

            <div class="col-md-4">
                <label class="form-label">آیکون</label>
                <input name="icon" class="form-control" value="fa-layer-group">
            </div>

            <div class="col-md-4">
                <label class="form-label">عکس/تصویر</label>
                <input name="image_url" class="form-control">
            </div>

            <div class="col-12">
                <label class="form-label">توضیحات</label>
                <textarea name="description" class="form-control" rows="4"></textarea>
            </div>

            <div class="col-md-3">
                <label class="form-label">وضعیت</label>
                <select name="active" class="form-select">
                    <option value="1" selected>فعال</option>
                    <option value="0">غیرفعال</option>
                </select>
            </div>

            <div class="col-12">
                <button class="btn btn-primary" type="submit">

                    <i class="fa-solid fa-plus"></i>
                    افزودن گروه
                </button>
            </div>
        </form>
    </div>


            <div class="surface-card">
                <div class="table-responsive">
                    <table class="table align-middle mb-0">
                        <thead>
                            <tr>
                                <th>عنوان</th>
                                <th>آیکون</th>
                                <th>توضیحات</th>
                                <th>وضعیت</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>

                        <tbody>
                            {% for category in categories %}
                            <tr>
                                <td>{{ category.title }}</td>
                                <td>{{ category.icon }}</td>
                                <td class="text-truncate" style="max-width: 320px;">
                                    {{ category.description }}
                                </td>

                                <td>
                                    {% if category.active %}
                                    <span class="badge text-bg-success">فعال</span>
                                    {% else %}
                                    <span class="badge text-bg-danger">غیرفعال</span>
                                    {% endif %}
                                </td>

                                <td>
                                    <button class="btn btn-sm btn-outline-primary"
                                            type="button"
                                            data-bs-toggle="collapse"
                                            data-bs-target="#edit-category-{{ category.id }}">
                                        <i class="fa-solid fa-pen"></i>
                                    </button>

                                    <form method="post"
                                          action="{{ url_for('settings') }}"
                                          class="d-inline">
                                        <input type="hidden"
                                               name="csrf_token"
                                               value="{{ csrf_token }}">

                                        <input type="hidden"
                                               name="action"
                                               value="delete_category">

                                        <input type="hidden"
                                               name="category_id"
                                               value="{{ category.id }}">

                                        <button class="btn btn-sm btn-outline-danger"
                                                type="submit"
                                                onclick="return confirm('گروه و تمام اپلیکیشن‌های وابسته حذف شوند؟')">
                                            <i class="fa-solid fa-trash"></i>
                                        </button>
                                    </form>
                                </td>
                            </tr>



                            <tr class="collapse bg-body-tertiary"
                                id="edit-category-{{ category.id }}">
                                <td colspan="5" class="p-3">
                                    <form method="post" action="{{ url_for('settings') }}" class="row g-3">
                                        <input type="hidden"
                                               name="csrf_token"
                                               value="{{ csrf_token }}">

                                        <input type="hidden"
                                               name="action"
                                               value="update_category">

                                        <input type="hidden"
                                               name="category_id"
                                               value="{{ category.id }}">

                                        <div class="col-md-4">
                                            <label class="form-label">عنوان</label>
                                            <input name="title"
                                                   class="form-control"
                                                   value="{{ category.title }}"
                                                   required>
                                        </div>

                                        <div class="col-md-4">
                                            <label class="form-label">آیکون</label>
                                            <input name="icon"
                                                   class="form-control"
                                                   value="{{ category.icon }}">
                                        </div>

                                        <div class="col-md-4">
                                            <label class="form-label">عکس/تصویر</label>
                                            <input name="image_url"
                                                   class="form-control"
                                                   value="{{ category.image_url }}">
                                        </div>

                                        <div class="col-12">
                                            <label class="form-label">توضیحات</label>
                                            <textarea name="description"
                                                      class="form-control"
                                                      rows="3">{{ category.description }}</textarea>
                                        </div>

                                        <div class="col-md-3">
                                            <label class="form-label">وضعیت</label>
                                            <select name="active" class="form-select">
                                                <option value="1"
                                                    {% if category.active %}selected{% endif %}>
                                                    فعال
                                                </option>

                                                <option value="0"
                                                    {% if not category.active %}selected{% endif %}>
                                                    غیرفعال
                                                </option>
                                            </select>
                                        </div>

                                        <div class="col-12">
                                            <button class="btn btn-primary" type="submit">
                                                <i class="fa-solid fa-floppy-disk"></i>
                                                ثبت ویرایش
                                            </button>
                                        </div>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>



                </tbody>
            </table>
        </div>
    </div>
    {% else %}
    <div class="surface-card mb-4">
        <form method="post" class="row g-3">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="action" value="create_app">

            <div class="col-md-4">
                <label class="form-label">دسته</label>
                <select name="category_id" class="form-select" required>
                    {% for category in categories %}
                    <option value="{{ category.id }}">{{ category.title }}</option>
                    {% endfor %}
                </select>
            </div>

            <div class="col-md-4">
                <label class="form-label">عنوان</label>
                <input name="title" class="form-control" required>
            </div>

            <div class="col-md-4">
                <label class="form-label">آیکون</label>
                <input name="icon" class="form-control" value="fa-cube">
            </div>

            <div class="col-12">
                <label class="form-label">توضیحات</label>
                <textarea name="description" class="form-control" rows="4"></textarea>
            </div>

            <div class="col-md-6">
                <label class="form-label">لینک</label>
                <input name="link" class="form-control" placeholder="https://...">
            </div>

            <div class="col-md-3">
                <label class="form-label">وضعیت</label>
                <select name="enabled" class="form-select">
                    <option value="1">فعال</option>
                    <option value="0">غیرفعال</option>
                </select>
            </div>

            <div class="col-12">
                <button class="btn btn-primary" type="submit">
                    <i class="fa-solid fa-plus"></i>
                    افزودن اپلیکیشن
                </button>
            </div>
        </form>
    </div>

    <div class="surface-card">
        <div class="table-responsive">
            <table class="table align-middle mb-0">
                <thead>
                    <tr>
                        <th>عنوان</th>
                        <th>دسته</th>
                        <th>وضعیت</th>
                        <th>لینک</th>
                        <th>عملیات</th>
                    </tr>
                </thead>

                <tbody>
                    {% for app in apps_list %}
                    <tr>
                        <td>{{ app.title }}</td>

                        <td>{{ app.category.title if app.category else '-' }}</td>

                        <td>
                            {% if app.enabled %}
                            <span class="badge text-bg-success">فعال</span>
                            {% else %}
                            <span class="badge text-bg-danger">غیرفعال</span>
                            {% endif %}
                        </td>

                        <td class="text-truncate" style="max-width: 260px;">
                            {{ app.link }}
                        </td>

                        <td>
                            <button class="btn btn-sm btn-outline-primary"
                                    type="button"
                                    data-bs-toggle="collapse"
                                    data-bs-target="#edit-app-{{ app.id }}">
                                <i class="fa-solid fa-pen"></i>
                            </button>

                            <form method="post"
                                  action="{{ url_for('settings') }}"
                                  class="d-inline">
                                <input type="hidden"
                                       name="csrf_token"
                                       value="{{ csrf_token }}">

                                <input type="hidden"
                                       name="action"
                                       value="delete_app">

                                <input type="hidden"
                                       name="app_id"
                                       value="{{ app.id }}">

                                <button class="btn btn-sm btn-outline-danger"
                                        type="submit"
                                        onclick="return confirm('اپلیکیشن حذف شود؟')">
                                    <i class="fa-solid fa-trash"></i>
                                </button>
                            </form>
                        </td>
                    </tr>

                    <tr class="collapse bg-body-tertiary"
                        id="edit-app-{{ app.id }}">
                        <td colspan="5" class="p-3">
                            <form method="post" action="{{ url_for('settings') }}" class="row g-3">
                                <input type="hidden"
                                       name="csrf_token"
                                       value="{{ csrf_token }}">

                                <input type="hidden"
                                       name="action"
                                       value="update_app">

                                <input type="hidden"
                                       name="app_id"
                                       value="{{ app.id }}">

                                <div class="col-md-4">
                                    <label class="form-label">عنوان</label>
                                    <input name="title"
                                           class="form-control"
                                           value="{{ app.title }}"
                                           required>
                                </div>

                                <div class="col-md-4">
                                    <label class="form-label">دسته</label>
                                    <select name="category_id"
                                            class="form-select"
                                            required>
                                        {% for category in categories %}
                                        <option value="{{ category.id }}"
                                            {% if category.id == app.category_id %}selected{% endif %}>
                                            {{ category.title }}
                                        </option>
                                        {% endfor %}
                                    </select>
                                </div>

                                <div class="col-md-4">
                                    <label class="form-label">آیکون</label>
                                    <input name="icon"
                                           class="form-control"
                                           value="{{ app.icon }}">
                                </div>

                                <div class="col-12">
                                    <label class="form-label">توضیحات</label>
                                    <textarea name="description"
                                              class="form-control"
                                              rows="3">{{ app.description }}</textarea>
                                </div>

                                <div class="col-md-8">
                                    <label class="form-label">لینک</label>
                                    <input name="link"
                                           class="form-control"
                                           value="{{ app.link }}">
                                </div>

                                <div class="col-md-4">
                                    <label class="form-label">وضعیت</label>
                                    <select name="enabled" class="form-select">
                                        <option value="1"
                                            {% if app.enabled %}selected{% endif %}>
                                            فعال
                                        </option>

                                        <option value="0"
                                            {% if not app.enabled %}selected{% endif %}>
                                            غیرفعال
                                        </option>
                                    </select>
                                </div>

                                <div class="col-12">
                                    <button class="btn btn-primary" type="submit">
                                        <i class="fa-solid fa-floppy-disk"></i>
                                        ثبت ویرایش
                                    </button>
                                </div>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
               # </tbody>
           # </table>
       # </div>
    #</div>

                </tbody>
            </table>
        </div>
    </div>
    {% endif %}
    """

    return render_page(
        "تنظیمات و مدیریت محتوا",
        settings_template,
        categories=categories,
        apps_list=apps_list,
        active_tab=active_tab,
    )


@app.get("/settings/export/categories.xlsx")
@admin_required
def export_categories():
    categories = Category.query.order_by(Category.id.asc()).all()

    return workbook_response(
        "groups.xlsx",
        [
            "شناسه",
            "عنوان گروه",
            "آیکون",
            "تصویر",
            "توضیحات",
            "وضعیت",
        ],
        [
            [
                category.id,
                category.title,
                category.icon,
                category.image_url,
                category.description,
                "فعال" if category.active else "غیرفعال",
            ]
            for category in categories
        ],
    )


@app.get("/settings/export/apps.xlsx")
@admin_required
def export_apps():
    apps = AppItem.query.order_by(AppItem.id.asc()).all()

    return workbook_response(
        "applications.xlsx",
        [
            "شناسه",
            "گروه",
            "عنوان اپلیکیشن",
            "آیکون",
            "توضیحات",
            "لینک",
            "وضعیت",
        ],
        [
            [
                item.id,
                item.category.title if item.category else "",
                item.title,
                item.icon,
                item.description,
                item.link,
                "فعال" if item.enabled else "غیرفعال",
            ]
            for item in apps
        ],
    )


@app.get("/users/export.xlsx")
@superadmin_required
def export_users():
    users_list = User.query.order_by(User.id.asc()).all()

    return workbook_response(
        "users.xlsx",
        [
            "شناسه",
            "نام کاربری",
            "وضعیت",
            "مدیر سامانه",
            "گروه‌های مجاز",
            "اپلیکیشن‌های مجاز",
        ],
        [
            [
                user.id,
                user.username,
                "فعال" if user.active else "غیرفعال",
                "بله" if user.is_admin else "خیر",
                "، ".join(category.title for category in user.categories),
                "، ".join(item.title for item in user.apps),
            ]
            for user in users_list
        ],
    )


@app.get("/category/<int:category_id>")
@login_required
def category_detail(category_id):        
    category = db.session.get(Category, category_id)

    if category is None:
        abort(404)

    if not category.active:
        abort(404)

    items = [item for item in category.apps if item.enabled]

    category_detail_template = """
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
        <div>
            <h3 class="fw-bold mb-1">{{ category.title }}</h3>
            <p class="muted mb-0">اپلیکیشن‌های این دسته‌بندی</p>
        </div>

        <a href="{{ url_for('categories') }}" class="btn btn-outline-secondary">
            <i class="fa-solid fa-arrow-right"></i>
            بازگشت به دسته‌بندی‌ها
        </a>
    </div>

    {% if category.description %}
    <div class="surface-card mb-4">
        <div class="markdown muted">
            {{ category.description|markdown_safe }}
        </div>
    </div>
    {% endif %}

    <div class="row g-3">
        {% for item in apps %}
        <div class="col-md-6 col-xl-4">
            {% if item.link and item.link != '#' %}
            <a class="app-link" href="{{ item.link }}">
            {% else %}
            <a class="app-link" href="{{ url_for('app_detail', app_id=item.id) }}">
            {% endif %}
                <div class="app-card">
                    <div class="icon-box">
                        <i class="fa-solid {{ item.icon }}"></i>
                    </div>

                    <h5 class="fw-bold mt-3">{{ item.title }}</h5>

                    <div class="markdown muted">
                        {{ item.description|markdown_safe }}
                    </div>

                    <div class="mt-3 small text-primary">
                        ورود مستقیم به سرویس
                        <i class="fa-solid fa-arrow-left"></i>
                    </div>
                </div>
            </a>
        </div>
        {% else %}
        <div class="col-12">
            <div class="alert alert-info">
                اپلیکیشن فعالی در این دسته وجود ندارد.
            </div>
        </div>
        {% endfor %}
    </div>
    """

    return render_page(
        category.title,
        category_detail_template,
        category=category,
        apps=items,
    )


@app.get("/categories")
@login_required
def categories():
    items = Category.query.filter_by(active=True).order_by(Category.title.asc()).all()   
    
    categories_template = """
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
        <div>
            <h3 class="fw-bold mb-1">دسته‌بندی اپلیکیشن‌ها</h3>
            <p class="muted mb-0">
                انتخاب دسته و مشاهده سرویس‌های مرتبط
            </p>
        </div>

        <a href="{{ url_for('apps') }}" class="btn btn-outline-secondary">
            <i class="fa-solid fa-arrow-right"></i>
            بازگشت به اپلیکیشن‌ها
        </a>
    </div>

    <div class="row g-4">
        {% for category in categories %}
        <div class="col-md-6">
            <a class="app-link"
               href="{{ url_for('category_detail', category_id=category.id) }}">

                <div class="app-card">
                    <div class="row align-items-center">
                        <div class="col-auto">
                            <div class="icon-box">
                                <i class="fa-solid {{ category.icon }}"></i>
                            </div>
                        </div>

                        <div class="col">
                            <h4 class="fw-bold">
                                {{ category.title }}
                            </h4>

                            <div class="markdown muted">
                                {{ category.description|markdown_safe }}
                            </div>

                            <div class="mt-3 text-primary small">
                                {{ category.apps|length }}
                                اپلیکیشن
                                <i class="fa-solid fa-arrow-left"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </a>
        </div>
        {% else %}
        <div class="col-12">
            <div class="alert alert-info">
                هنوز دسته‌بندی‌ای تعریف نشده است.
            </div>
        </div>
        {% endfor %}
    </div>
    """

    return render_page(
        "دسته‌بندی‌ها",
        categories_template,
        categories=items,
    )



with app.app_context():
    db.create_all()
    seed_database()




if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000,
    )



