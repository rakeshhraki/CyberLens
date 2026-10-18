from flask import Blueprint, jsonify
from sqlalchemy import func

from database.models import Analysis, db, utc_to_ist_iso


history_bp = Blueprint('history', __name__)


@history_bp.route('/api/history', methods=['GET'])
def get_history():
    try:
        analyses = (
            Analysis.query
            .order_by(Analysis.created_at.desc())
            .all()
        )

        history = []

        for analysis in analyses:
            history.append({
                'id': analysis.id,
                'filename': analysis.filename,
                'sha256': analysis.sha256,
                'file_type': analysis.file_type,
                'mime_type': analysis.mime_type,
                'file_size': analysis.file_size,
                'entropy': analysis.entropy,
                'risk_score': analysis.risk_score,
                'severity': analysis.severity,
                'indicators': analysis.indicators,
                'created_at': utc_to_ist_iso(analysis.created_at)
            })

        return jsonify({
            'success': True,
            'count': len(history),
            'data': history
        }), 200

    except Exception:
        return jsonify({
            'success': False,
            'error': 'Unable to retrieve analysis history'
        }), 500


@history_bp.route('/api/history/<int:analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    try:
        analysis = Analysis.query.get(analysis_id)

        if not analysis:
            return jsonify({
                'success': False,
                'error': 'Analysis not found'
            }), 404

        return jsonify({
            'success': True,
            'data': analysis.to_dict()
        }), 200

    except Exception:
        return jsonify({
            'success': False,
            'error': 'Unable to retrieve analysis'
        }), 500


@history_bp.route('/api/dashboard-stats', methods=['GET'])
def dashboard_stats():
    """Return aggregate statistics used by the CyberLens overview dashboard."""
    try:
        total = Analysis.query.count()
        low = Analysis.query.filter_by(severity='LOW').count()
        medium = Analysis.query.filter_by(severity='MEDIUM').count()
        high = Analysis.query.filter_by(severity='HIGH').count()
        critical = Analysis.query.filter_by(severity='CRITICAL').count()

        average_risk = db.session.query(
            func.avg(Analysis.risk_score)
        ).scalar()

        recent = (
            Analysis.query
            .order_by(Analysis.created_at.desc())
            .limit(7)
            .all()
        )

        return jsonify({
            'success': True,
            'data': {
                'total': total,
                'low': low,
                'medium': medium,
                'high': high,
                'critical': critical,
                'average_risk': (
                    round(float(average_risk), 1)
                    if average_risk is not None
                    else 0
                ),
                'risk_distribution': {
                    'low': low,
                    'medium': medium,
                    'high': high,
                    'critical': critical
                },
                'recent': [
                    {
                        'id': item.id,
                        'filename': item.filename,
                        'file_type': item.file_type,
                        'risk_score': item.risk_score or 0,
                        'severity': item.severity or 'LOW',
                        'created_at': utc_to_ist_iso(item.created_at)
                    }
                    for item in recent
                ]
            }
        }), 200

    except Exception:
        return jsonify({
            'success': False,
            'error': 'Unable to retrieve dashboard statistics'
        }), 500