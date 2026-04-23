from flask import Blueprint, render_template
from routes.auth import require_login

gallery_bp = Blueprint('gallery', __name__)


@gallery_bp.route('/gallery')
@require_login
def gallery():
    return render_template('gallery.html')
