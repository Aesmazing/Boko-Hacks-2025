from flask import Blueprint, render_template, session

apps_bp = Blueprint("apps", __name__)

@apps_bp.route("/apps/<app_name>")
def load_app(app_name):
    template_map = {
        "notes": "notes.html",
        "upload": "files.html",
        "chat": "chat.html",
        "api": "api.html",
        "admin_login": "admin_login.html",
        "admin_register": "admin_register.html",
        "admin-dashboard": "admin_hub.html",
        "401k": "401k.html",
        "news": "news.html",  # Add the news template
    }

    if app_name == "admin":
        return render_template(
            "admin.html",
            is_logged_in=session.get('admin_logged_in', False),
            is_default_admin=session.get('is_default_admin', False)
        )

    template_name = template_map.get(app_name)
    if template_name:
        return render_template(template_name)

    return "<h3>Error</h3><p>Application not found.</p>", 404