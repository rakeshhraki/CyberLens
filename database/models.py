from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON


db = SQLAlchemy()

IST = ZoneInfo("Asia/Kolkata")


def utc_to_ist_iso(value):
    """Convert stored UTC datetime to ISO-8601 timestamp in IST."""

    if not value:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(IST).isoformat()


class Analysis(db.Model):
    """Analysis model for storing file investigation results."""

    __tablename__ = 'analyses'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    # IMPORTANT:
    # SHA-256 identifies the file content,
    # NOT the investigation.
    #
    # The same file can therefore be analyzed
    # multiple times and create separate investigations.
    sha256 = db.Column(db.String(64), nullable=False, index=True)

    md5 = db.Column(
        db.String(32),
        nullable=False
    )

    sha1 = db.Column(
        db.String(40),
        nullable=False
    )

    file_type = db.Column(
        db.String(100),
        nullable=False
    )

    mime_type = db.Column(
        db.String(100)
    )

    file_size = db.Column(
        db.BigInteger,
        nullable=False
    )

    entropy = db.Column(
        db.Float
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    severity = db.Column(
        db.String(20),
        default='LOW'
    )

    indicators = db.Column(
        JSON
    )

    analysis_data = db.Column(
        JSON
    )

    # Keep database storage in UTC.
    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    def __repr__(self):
        return f'<Analysis {self.id}: {self.filename}>'

    def to_dict(self):
        """Convert analysis to dictionary for JSON serialization."""

        return {
            'id': self.id,
            'filename': self.filename,
            'sha256': self.sha256,
            'md5': self.md5,
            'sha1': self.sha1,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'entropy': self.entropy,
            'risk_score': self.risk_score,
            'severity': self.severity,
            'indicators': self.indicators,
            'analysis_data': self.analysis_data,
            'created_at': utc_to_ist_iso(
                self.created_at
            )
        }