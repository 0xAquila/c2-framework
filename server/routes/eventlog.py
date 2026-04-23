from flask import Blueprint, render_template, jsonify, request
from database import db, EventLog
from routes.auth import require_login

eventlog_bp = Blueprint('eventlog', __name__)


@eventlog_bp.route('/eventlog')
@require_login
def eventlog():
    return render_template('eventlog.html')


@eventlog_bp.route('/api/events')
@require_login
def get_events():
    limit  = min(int(request.args.get('limit', 200)), 500)
    offset = int(request.args.get('offset', 0))
    etype  = request.args.get('type')   # optional filter

    q = EventLog.query
    if etype:
        q = q.filter_by(event_type=etype)
    events = q.order_by(EventLog.timestamp.desc()).offset(offset).limit(limit).all()

    return jsonify([{
        'id':          e.id,
        'timestamp':   e.timestamp.isoformat(),
        'event_type':  e.event_type,
        'agent_id':    e.agent_id,
        'hostname':    e.agent_hostname,
        'description': e.description,
    } for e in events])
