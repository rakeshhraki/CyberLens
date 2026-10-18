from flask import Flask, render_template

from config import Config
from database.models import db
from routes.analysis import analysis_bp
from routes.history import history_bp


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

app.register_blueprint(analysis_bp)
app.register_blueprint(history_bp)


with app.app_context():
    db.create_all()


@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/analyze')
def analyze():
    return render_template('analyze.html')


@app.route('/history')
def history():
    return render_template('history.html')


@app.route('/reports')
def reports():
    return render_template('reports.html')


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(
        debug=False,
        host='0.0.0.0',
        port=5000
    )