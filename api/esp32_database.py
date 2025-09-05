from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///esp32database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my_password'
db = SQLAlchemy(app)

@app.before_request
def enforce_foreign_keys():
    db.session.execute(text('PRAGMA foreign_keys = ON'))

class Tags(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(80), nullable=False)

@app.route('/verificar_tag', methods=['POST'])
def verificar_tag():
    dados = request.json
    tag = dados.get('tag')
    access_ok = Tags.query.filter_by(tag=tag).first()
    if access_ok:
        return jsonify({"sucess": True, "mensagem": "Tag encontrada!"}), 200
    else:
        return jsonify({"sucess": False, "mensagem": "Tag não encontrada!"}), 401

if __name__ == "__main__":
    with app.app_context():
        enforce_foreign_keys()
        db.create_all()
    app.run(host="0.0.0.0", port=5000)