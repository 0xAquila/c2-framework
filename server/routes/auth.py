from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, render_template, current_app, abort

auth_bp = Blueprint('auth', __name__)


def _gateway_passed():
    """True if the request carries the correct X-Operator-Key header."""
    key = request.headers.get('X-Operator-Key', '')
    return key == current_app.config['OPERATOR_KEY']


def require_login(f):
    """Session guard: unauthenticated requests return 404 — /login must not be discoverable."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            abort(404)
        return f(*args, **kwargs)
    return decorated


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('operator.dashboard'))

    # C2 profile gateway: no correct header → 404, indistinguishable from any missing page
    if not _gateway_passed():
        abort(404)

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        # Credentials come from app.config — never hardcoded
        if (username == current_app.config['OPERATOR_USER'] and
                password == current_app.config['OPERATOR_PASS']):
            session['authenticated'] = True
            session.permanent = True
            return redirect(url_for('operator.dashboard'))
        error = 'Invalid credentials.'

    return render_template('login.html', error=error)


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect('/')
