from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
from sqlalchemy.orm import selectinload
from sqlalchemy import func, desc, asc
from app.extensions import limiter, csrf

import os, json, math



from db.models import Host, Service, Website, get_session, init_db
from app.secrets_manager import SECRETS_FILE
from app.utils import save_form_data, update_ip_range, get_scan_profile, set_scan_profile
from app.config_loader import load_config
from app.scanner import start_scan_background, cancel_scan, scan_status

main = Blueprint("main", __name__)

@main.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        ip_range = request.form["ip_range"].strip()
        token = request.form["token"].strip()
        chat_id = request.form["chat_id"].strip()
        db_password = request.form["db_password"].strip()
        save_form_data(ip_range, token, chat_id, db_password)
        return redirect(url_for("main.dashboard"))
    return render_template("secrets_setup.html")

@main.route("/reset", methods=["GET", "POST"])
@limiter.limit("2 per minute")
def reset():
    if request.method == "POST":
        ip_range = request.form["ip_range"].strip()
        token = request.form["token"].strip()
        chat_id = request.form["chat_id"].strip()
        db_password = request.form["db_password"].strip()
        save_form_data(ip_range, token, chat_id, db_password)
        return redirect(url_for("main.dashboard"))
    cfg = load_config() if os.path.exists(SECRETS_FILE) else {}
    return render_template("reset_secrets.html", cfg=cfg)

@main.route("/", methods=["GET", "POST"])
def dashboard():
    secrets_ok = os.path.exists(SECRETS_FILE)
    ip_range = None; telegram_ok = False; masked_chat = None; db_ok = False
    profile = get_scan_profile()

    if secrets_ok:
        cfg = load_config() or {}
        ip_range = (cfg.get("app") or {}).get("ip_range")
        tg = cfg.get("telegram") or {}
        chat_id = tg.get("chat_id")
        telegram_ok = bool(tg.get("token") and chat_id)
        if chat_id: masked_chat = f"***{str(chat_id)[-3:]}"
        try:
            init_db(); s = get_session(); s.close(); db_ok = True
        except Exception as e:
            print(f"[dashboard] DB health check failed: {e}"); db_ok = False

        if request.method == "POST":
            action = request.form.get("action")
            if action == "update_range":
                try:
                    new_range = request.form.get("new_ip_range", "").strip()
                    update_ip_range(new_range); flash("IP range updated.", "success")
                except ValueError as ve:
                    flash(str(ve), "danger")
                except Exception:
                    flash("Failed to update IP range.", "danger")
                return redirect(url_for("main.dashboard"))

    status = scan_status()
    return render_template(
        "dashboard.html",
        secrets_ok=secrets_ok, ip_range=ip_range, telegram_ok=telegram_ok,
        masked_chat=masked_chat, db_ok=db_ok, scan_status=status, profile=profile
    )

def _apply_query_filters(session, q, status, osfam, svc_contains, pmin, pmax):
    base = session.query(Host)
    if q:
        like = f"%{q.lower()}%"
        base = base.filter(
            func.lower(Host.ip).like(like) |
            func.lower(Host.hostname).like(like) |
            func.lower(Host.os).like(like)
        )
    if status in ("up","down"):
        base = base.join(Website, isouter=True).filter(
            (Website.status.is_(True) if status=="up" else Website.status.is_(False))
        )
    if osfam in ("windows","linux","other"):
        if osfam == "windows":
            base = base.filter(func.lower(Host.os).like("%win%") | func.lower(Host.os).like("%microsoft%"))
        elif osfam == "linux":
            base = base.filter(
                func.lower(Host.os).like("%linux%") | func.lower(Host.os).like("%ubuntu%") |
                func.lower(Host.os).like("%debian%") | func.lower(Host.os).like("%centos%")
            )
        else:
            base = base.filter(~func.lower(Host.os).like("%win%"), ~func.lower(Host.os).like("%linux%"))
    if svc_contains or pmin is not None or pmax is not None:
        s = session.query(Service.host_id).filter(Service.state=="open")
        if svc_contains:
            like = f"%{svc_contains.lower()}%"
            s = s.filter(func.lower(Service.service).like(like) | func.lower(Service.product).like(like))
        if pmin is not None: s = s.filter(Service.port >= pmin)
        if pmax is not None: s = s.filter(Service.port <= pmax)
        s = s.distinct().subquery()
        base = base.filter(Host.id == s.c.host_id)
    return base

@main.route("/results")
def results():
    init_db(); session = get_session()
    try:
        page = max(1, int(request.args.get("page", 1)))
        per = min(200, max(10, int(request.args.get("per", 50))))
        sort = request.args.get("sort", "ip"); direction = request.args.get("dir", "asc")
        q = request.args.get("q", "").strip()
        status = request.args.get("status", "").lower().strip()
        osfam = request.args.get("osfam", "").lower().strip()
        svc_contains = request.args.get("svc", "").strip()
        try:
            pmin = int(request.args.get("pmin")) if request.args.get("pmin") else None
            pmax = int(request.args.get("pmax")) if request.args.get("pmax") else None
        except ValueError:
            pmin = pmax = None

        base = _apply_query_filters(session, q, status, osfam, svc_contains, pmin, pmax)
        port_counts = session.query(Service.host_id, func.count(Service.id).label("pc")).group_by(Service.host_id).subquery()
        query = base.outerjoin(port_counts, Host.id == port_counts.c.host_id)

        if sort == "os": order_col = Host.os
        elif sort == "hostname": order_col = Host.hostname
        elif sort == "status":
            from sqlalchemy.orm import aliased
            W = aliased(Website); query = query.outerjoin(W, W.host_id == Host.id); order_col = W.status
        elif sort == "port_count": order_col = func.coalesce(port_counts.c.pc, 0)
        else: order_col = Host.ip

        query = query.order_by(desc(order_col) if direction=="desc" else asc(order_col), asc(Host.ip))
        total_items = query.count(); total_pages = max(1, math.ceil(total_items / per))
        if page > total_pages: page = total_pages

        rows = query.options(selectinload(Host.services), selectinload(Host.website))\
                    .limit(per).offset((page-1)*per).all()

        return render_template("results.html",
            hosts=rows, page=page, per=per, total_pages=total_pages, total_items=total_items,
            sort=sort, direction=direction, q=q, status=status, osfam=osfam, svc=svc_contains, pmin=pmin, pmax=pmax
        )
    finally:
        session.close()

# ---------- Exports (fixed) ----------
@main.route("/results.csv")
def results_csv():
    init_db(); session = get_session()
    try:
        q = request.args.get("q", "").strip()
        status = request.args.get("status", "").lower().strip()
        osfam = request.args.get("osfam", "").lower().strip()
        svc_contains = request.args.get("svc", "").strip()
        pmin = request.args.get("pmin"); pmax = request.args.get("pmax")
        try:
            pmin = int(pmin) if pmin else None
            pmax = int(pmax) if pmax else None
        except ValueError:
            pmin = pmax = None

        base = _apply_query_filters(session, q, status, osfam, svc_contains, pmin, pmax)\
               .order_by(asc(Host.ip))\
               .options(selectinload(Host.website), selectinload(Host.services))
        rows = base.all()

        def generate():
            yield "ip,hostname,os,port_count,website_status,website_title,website_url\n"
            for h in rows:
                pc = len(h.services or [])
                ws_status = ("UP" if (h.website and h.website.status) else "DOWN") if h.website else "N/A"
                title = (h.website.title.replace(',', ' ') if (h.website and h.website.title) else "")
                url = (h.website.url if (h.website and h.website.url) else "")
                yield f"{h.ip},{(h.hostname or '').replace(',', ' ')},{(h.os or '').replace(',', ' ')},{pc},{ws_status},{title},{url}\n"

        resp = Response(generate(), mimetype="text/csv")
        resp.headers["Content-Disposition"] = "attachment; filename=results.csv"
        return resp
    finally:
        session.close()

@main.route("/results.json")
def results_json():
    init_db(); session = get_session()
    try:
        q = request.args.get("q", "").strip()
        status = request.args.get("status", "").lower().strip()
        osfam = request.args.get("osfam", "").lower().strip()
        svc_contains = request.args.get("svc", "").strip()
        pmin = request.args.get("pmin"); pmax = request.args.get("pmax")
        try:
            pmin = int(pmin) if pmin else None
            pmax = int(pmax) if pmax else None
        except ValueError:
            pmin = pmax = None

        base = _apply_query_filters(session, q, status, osfam, svc_contains, pmin, pmax)\
               .order_by(asc(Host.ip))\
               .options(selectinload(Host.website), selectinload(Host.services))
        rows = base.all()

        payload = []
        for h in rows:
            payload.append({
                "ip": h.ip, "hostname": h.hostname, "os": h.os, "cpu": h.cpu, "ram": h.ram,
                "website": {
                    "status": h.website.status if h.website else None,
                    "title": h.website.title if h.website else None,
                    "url": h.website.url if h.website else None,
                } if h.website else None,
                "services": [
                    {"proto": s.proto, "port": s.port, "service": s.service, "product": s.product, "version": s.version, "state": s.state}
                    for s in (h.services or [])
                ]
            })
        resp = Response(json.dumps(payload), mimetype="application/json")
        resp.headers["Content-Disposition"] = "attachment; filename=results.json"
        return resp
    finally:
        session.close()

# ---------- Scan control ----------
@main.route("/scan/start", methods=["POST"])
@limiter.limit("5 per minute")
def scan_start():
    profile = (request.get_json(silent=True) or {}).get("profile", "").lower().strip() if request.is_json else ""
    if profile not in ("quick","balanced","deep"):
        profile = get_scan_profile()
    set_scan_profile(profile)
    started = start_scan_background({"profile": profile})
    return jsonify({"ok": True, "started": started, "status": scan_status()})

@main.route("/scan/cancel", methods=["POST"])
@limiter.limit("5 per minute")
def scan_cancel():
    cancel_scan()
    return jsonify({"ok": True, "status": scan_status()})

@main.route("/scan/status", methods=["GET"])
def scan_status_api():
    return jsonify(scan_status())
