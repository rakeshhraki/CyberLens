import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')

    if not SECRET_KEY:
        raise RuntimeError(
            'SECRET_KEY environment variable is not configured'
        )

    MAX_CONTENT_LENGTH = min(
        int(os.environ.get('MAX_UPLOAD_SIZE', 8388608)),
        8388608
    )

    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'uploads'
    )

    SQLALCHEMY_DATABASE_URI = (
        os.environ.get('DATABASE_URL')
        or 'sqlite:///cyberlens.db'
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    ALLOWED_EXTENSIONS = {
        'pdf',
        'doc',
        'docx',
        'jpg',
        'jpeg',
        'png',
        'txt'
    }

    ALLOWED_MIME_TYPES = {
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'image/jpeg',
        'image/jpg',
        'image/png',
        'text/plain'
    }