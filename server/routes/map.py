from flask import Blueprint, render_template
from routes.auth import require_login

map_bp = Blueprint('map', __name__)


@map_bp.route('/map')
@require_login
def network_map():
    return render_template('map.html')
