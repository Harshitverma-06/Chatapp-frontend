import os
from functools import wraps
from typing import Any, Dict, Optional

import requests
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


BACKEND_URL = os.environ.get("BACKEND_URL", "https://chatapp-backend-vofr.onrender.com").rstrip("/")

app = Flask(__name__)
# Used only to store frontend session data (JWT + user object). No DB.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")


def _backend_headers() -> Dict[str, str]:
    """
    Integration point: backend accepts JWT via cookie `accessToken`
    OR `Authorization: Bearer <token>`.

    This Flask frontend stores the access token in the Flask session and
    sends it as Bearer auth for protected routes.
    """
    token = session.get("access_token")
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _backend_request(
    method: str,
    path: str,
    *,
    json: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    files: Optional[Dict[str, Any]] = None,
    timeout: int = 20,
) -> requests.Response:
    url = f"{BACKEND_URL}{path}"
    return requests.request(
        method=method.upper(),
        url=url,
        headers=_backend_headers(),
        json=json,
        data=data,
        files=files,
        timeout=timeout,
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("access_token"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.get("/")
def home():
    if session.get("access_token"):
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


@app.get("/login")
def login():
    return render_template("login.html", backend_url=BACKEND_URL)


@app.post("/login")
def login_post():
    identifier = (request.form.get("identifier") or "").strip()
    password = request.form.get("password") or ""

    if not identifier or not password:
        flash("Please enter your email/username and password.", "error")
        return redirect(url_for("login"))

    # Backend supports email OR username (plus password).
    payload: Dict[str, Any] = {"password": password}
    if "@" in identifier:
        payload["email"] = identifier
    else:
        payload["username"] = identifier

    try:
        resp = _backend_request("POST", "/api/auth/login", json=payload)
    except requests.RequestException as e:
        flash(f"Backend unreachable: {e}", "error")
        return redirect(url_for("login"))

    try:
        body = resp.json()
    except ValueError:
        flash(f"Login failed (non-JSON response), status {resp.status_code}.", "error")
        return redirect(url_for("login"))

    if resp.status_code >= 400 or not body.get("success"):
        flash(body.get("message") or "Login failed.", "error")
        return redirect(url_for("login"))

    data = body.get("data") or {}
    session["access_token"] = data.get("accessToken")
    session["refresh_token"] = data.get("refreshToken")
    session["user"] = data.get("user")

    if not session.get("access_token"):
        flash("Login succeeded but accessToken was missing in response.", "error")
        return redirect(url_for("login"))

    return redirect(url_for("chat"))


@app.get("/register")
def register():
    return render_template("register.html", backend_url=BACKEND_URL)


@app.post("/register")
def register_post():
    username = (request.form.get("username") or "").strip()
    fullname = (request.form.get("fullname") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    avatar = request.files.get("avatar")

    if not (username and fullname and email and password):
        flash("All fields are required.", "error")
        return redirect(url_for("register"))

    # Backend expects multipart/form-data for signup (with optional `avatar` file).
    data = {
        "username": username,
        "fullname": fullname,
        "email": email,
        "password": password,
    }

    files = None
    if avatar and avatar.filename:
        files = {"avatar": (avatar.filename, avatar.stream, avatar.mimetype or "application/octet-stream")}

    try:
        resp = _backend_request("POST", "/api/auth/signup", data=data, files=files)
    except requests.RequestException as e:
        flash(f"Backend unreachable: {e}", "error")
        return redirect(url_for("register"))

    try:
        body = resp.json()
    except ValueError:
        flash(f"Registration failed (non-JSON response), status {resp.status_code}.", "error")
        return redirect(url_for("register"))

    if resp.status_code >= 400 or not body.get("success"):
        flash(body.get("message") or "Registration failed.", "error")
        return redirect(url_for("register"))

    flash("Account created. Please log in.", "success")
    return redirect(url_for("login"))


@app.post("/logout")
@login_required
def logout():
    # Backend route exists and is protected; we attempt it but always clear local session.
    try:
        _backend_request("POST", "/api/auth/logout")
    except requests.RequestException:
        pass
    session.clear()
    return redirect(url_for("login"))


@app.get("/chat")
@login_required
def chat():
    selected_user_id = request.args.get("user") or session.get("selected_user_id")
    selected_user_id = (selected_user_id or "").strip() or None
    session["selected_user_id"] = selected_user_id

    contacts = []
    chats = []
    messages = []
    selected_user = None

    # Contacts list (all users except current user).
    try:
        r_contacts = _backend_request("GET", "/api/message/contacts")
        if r_contacts.ok:
            contacts_body = r_contacts.json()
            contacts = contacts_body.get("data") or []
    except Exception:
        contacts = []

    # Chat partners list (users you've messaged with).
    try:
        r_chats = _backend_request("GET", "/api/message/chats")
        if r_chats.ok:
            chats_body = r_chats.json()
            chats = chats_body.get("data") or []
    except Exception:
        chats = []

    # If user selected, fetch messages between current user and selected user.
    if selected_user_id:
        try:
            r_msgs = _backend_request("GET", f"/api/message/{selected_user_id}")
            if r_msgs.ok:
                msgs_body = r_msgs.json()
                messages = msgs_body.get("data") or []
        except Exception:
            messages = []

        # Find selected user object from contacts/chats lists (best effort).
        for u in (contacts or []) + (chats or []):
            if str(u.get("_id")) == str(selected_user_id):
                selected_user = u
                break

    return render_template(
        "chat.html",
        backend_url=BACKEND_URL,
        me=session.get("user"),
        contacts=contacts,
        chats=chats,
        selected_user_id=selected_user_id,
        selected_user=selected_user,
        messages=messages,
    )


@app.get("/api/me")
@login_required
def api_me():
    """
    Fetch current user from backend (source of truth).
    Backend route: GET /api/auth/check (returns req.user)
    """
    try:
        resp = _backend_request("GET", "/api/auth/check")
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Backend unreachable: {e}"}), 502

    try:
        body = resp.json()
    except ValueError:
        return jsonify({"success": False, "message": "Backend returned non-JSON response."}), 502

    if resp.status_code >= 400:
        # backend typically returns ApiError { success:false, message, ... }
        return jsonify({"success": False, "message": body.get("message") or "Unauthorized."}), resp.status_code

    # /api/auth/check returns the user object directly (not wrapped)
    if isinstance(body, dict) and body.get("_id"):
        session["user"] = body
        return jsonify({"success": True, "data": body})

    # fallback if backend later wraps it
    data = (body.get("data") if isinstance(body, dict) else None) or body
    if isinstance(data, dict) and data.get("_id"):
        session["user"] = data
        return jsonify({"success": True, "data": data})

    return jsonify({"success": False, "message": "Unexpected response from backend."}), 502


@app.patch("/api/profile/avatar")
@login_required
def api_update_avatar():
    """
    Update avatar via backend:
      PATCH /api/auth/update-avatar (multipart/form-data field: avatar)
    """
    avatar = request.files.get("avatar")
    if not avatar or not avatar.filename:
        return jsonify({"success": False, "message": "Please choose an image file."}), 400

    files = {"avatar": (avatar.filename, avatar.stream, avatar.mimetype or "application/octet-stream")}
    try:
        resp = _backend_request("PATCH", "/api/auth/update-avatar", files=files)
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Backend unreachable: {e}"}), 502

    try:
        body = resp.json()
    except ValueError:
        return jsonify({"success": False, "message": "Backend returned non-JSON response."}), 502

    if resp.status_code >= 400 or not body.get("success"):
        return jsonify({"success": False, "message": body.get("message") or "Failed to update avatar."}), resp.status_code

    user = (body.get("data") or {}) if isinstance(body, dict) else {}
    if user:
        session["user"] = user
    return jsonify({"success": True, "data": user, "message": body.get("message")})


@app.post("/api/profile/password")
@login_required
def api_update_password():
    """
    Update password via backend:
      POST /api/auth/change-password (JSON: oldPassword, newPassword)
    """
    payload = request.get_json(silent=True) or {}
    old_password = (payload.get("oldPassword") or "").strip()
    new_password = (payload.get("newPassword") or "").strip()

    if not old_password or not new_password:
        return jsonify({"success": False, "message": "Old password and new password are required."}), 400

    try:
        resp = _backend_request("POST", "/api/auth/change-password", json={"oldPassword": old_password, "newPassword": new_password})
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Backend unreachable: {e}"}), 502

    try:
        body = resp.json()
    except ValueError:
        return jsonify({"success": False, "message": "Backend returned non-JSON response."}), 502

    if resp.status_code >= 400 or not body.get("success"):
        return jsonify({"success": False, "message": body.get("message") or "Failed to update password."}), resp.status_code

    return jsonify({"success": True, "message": body.get("message") or "Password updated."})


@app.put("/api/profile/account")
@login_required
def api_update_account_details():
    """
    Update account details via backend:
      PUT /api/auth/update-profile (JSON: username, fullname, email)
    """
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    fullname = (payload.get("fullname") or "").strip()
    email = (payload.get("email") or "").strip()

    if not (username and fullname and email):
        return jsonify({"success": False, "message": "Username, fullname, and email are required."}), 400

    try:
        resp = _backend_request("PUT", "/api/auth/update-profile", json={"username": username, "fullname": fullname, "email": email})
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Backend unreachable: {e}"}), 502

    try:
        body = resp.json()
    except ValueError:
        return jsonify({"success": False, "message": "Backend returned non-JSON response."}), 502

    if resp.status_code >= 400 or not body.get("success"):
        return jsonify({"success": False, "message": body.get("message") or "Failed to update account details."}), resp.status_code

    user = (body.get("data") or {}) if isinstance(body, dict) else {}
    if user:
        session["user"] = user
    return jsonify({"success": True, "data": user, "message": body.get("message")})


@app.post("/send")
@login_required
def send_message():
    receiver_id = (request.form.get("receiver_id") or "").strip()
    text = (request.form.get("text") or "").strip()
    image = request.files.get("image")

    if not receiver_id:
        flash("Please select a user to chat with.", "error")
        return redirect(url_for("chat"))

    # Backend route: POST /api/message/send/:id
    # It accepts multipart/form-data with optional `text` and optional file field `image`.
    data: Dict[str, Any] = {}
    if text:
        data["text"] = text

    files = None
    if image and image.filename:
        files = {"image": (image.filename, image.stream, image.mimetype or "application/octet-stream")}

    if not data and not files:
        flash("Type a message or attach an image.", "error")
        return redirect(url_for("chat", user=receiver_id))

    try:
        resp = _backend_request("POST", f"/api/message/send/{receiver_id}", data=data, files=files)
    except requests.RequestException as e:
        flash(f"Failed to send message: {e}", "error")
        return redirect(url_for("chat", user=receiver_id))

    try:
        body = resp.json()
    except ValueError:
        flash(f"Send failed (non-JSON response), status {resp.status_code}.", "error")
        return redirect(url_for("chat", user=receiver_id))

    if resp.status_code >= 400 or not body.get("success"):
        flash(body.get("message") or "Failed to send message.", "error")
    return redirect(url_for("chat", user=receiver_id))


@app.post("/message/delete/<message_id>")
@login_required
def delete_message(message_id: str):
    selected_user_id = session.get("selected_user_id")
    selected_user_id = (selected_user_id or "").strip() or None

    try:
        resp = _backend_request("DELETE", f"/api/message/delete/{message_id}")
    except requests.RequestException as e:
        flash(f"Failed to delete message: {e}", "error")
        return redirect(url_for("chat", user=selected_user_id) if selected_user_id else url_for("chat"))

    try:
        body = resp.json()
    except ValueError:
        flash(f"Delete failed (non-JSON response), status {resp.status_code}.", "error")
        return redirect(url_for("chat", user=selected_user_id) if selected_user_id else url_for("chat"))

    if resp.status_code >= 400 or not body.get("success"):
        flash(body.get("message") or "Failed to delete message.", "error")
    else:
        flash(body.get("message") or "Message deleted.", "success")

    return redirect(url_for("chat", user=selected_user_id) if selected_user_id else url_for("chat"))


if __name__ == "__main__":
    # Flask frontend runs independently from Node backend.
    # Start backend separately, then run:  python app.py
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)

