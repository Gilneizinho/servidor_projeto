from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, func
from flask_cors import CORS
from functools import wraps
import smtplib
from email.message import EmailMessage
import jwt
import logging
import re
import random
from pytz import timezone
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:///esp32database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my_password'
db = SQLAlchemy(app)
EMAIL_ORIGEM = "matheussilveiravaladao1998@gmail.com"
EMAIL_SENHA_APP = "w r d p q m o n x d m y g o b y"
SMTP_SERVIDOR = "smtp.gmail.com"
SMTP_PORTA = 587

@app.before_request
def enforce_foreign_keys():
    db.session.execute(text('PRAGMA foreign_keys = ON'))

class Tags(db.Model):
    __tablename__ = 'tags'
    tag = db.Column(db.String(80), primary_key=True, unique=True, nullable=False)
    nome = db.Column(db.Integer, nullable=False)

class Logs(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tag = db.Column(db.Integer, nullable=False, unique=True)
    cpf = db.Column(db.Integer, nullable=False, unique=True)
    data_inicio = db.Column(db.DateTime)
    data_fim = db.Column(db.DateTime)
    kWh = db.Column(db.Float, nullable=False)

class Pessoas(db.Model):
    __tablename__ = 'pessoas'
    id = db.Column(db.Integer)
    nome = db.Column(db.Integer, nullable=False)
    tag = db.Column(db.String(80), unique=True, nullable=False)
    cpf = db.Column(db.String(80),  primary_key=True, nullable=False, unique=True)
    senha = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    def verificar_senha(self, senha):
        return check_password_hash(self.senha, senha)

class Pendentes(db.Model):
    __tablename__ = 'pendentes'
    id = db.Column(db.Integer)
    nome = db.Column(db.Integer, nullable=False)
    tag = db.Column(db.String(80), unique=True, nullable=False)
    cpf = db.Column(db.String(80),  primary_key=True, nullable=False, unique=True)
    approved = db.Column(db.Boolean, nullable=False)
    senha = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)

class Verificar(db.Model):
    __tablename__ = 'verificar'
    email = db.Column(db.String(80), primary_key=True, nullable=False)
    code = db.Column(db.Integer, nullable=False)
    expiration = db.Column(db.String(80), nullable=False)
    verificado = db.Column(db.Boolean, nullable=False, default=False)
    def expirado(self):
        return datetime.now(timezone('America/Sao_Paulo')) > self.expiration

class Master(db.Model):
    __tablename__ = 'master'
    id = db.Column(db.Integer)
    master = db.Column(db.Boolean, default=True)
    tag = db.Column(db.String(80),  primary_key=True, nullable=False, unique=True)
    cpf = db.Column(db.String(80), nullable=False, unique=True)
    senha = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    def verificar_senha(self, senha):
        return check_password_hash(self.senha, senha)

logging.basicConfig(filename="log.txt", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def criar_token(usuario, tipo_usuario):
    payload = {
        'user_id': usuario.id,
        'tipo': tipo_usuario,
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_requerido(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            try:
                token = token.split()[1]
                dados = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                g.user_id = dados['user_id']
                g.tipo = dados['tipo']
            except jwt.ExpiredSignatureError:
                return jsonify({"success": False, "message": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"success": False, "message": "Token inválido"}), 401
            return f(*args, **kwargs)
        else:
            return jsonify({"success": False, "message": "Token inexistente"}), 401
    return decorator

def valida_email(email):
    """Retorna True se o email tiver formato válido, False caso contrário."""
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return bool(re.match(email_regex, email))


def valida_cpf(cpf):
    str_cpf = ''.join(filter(str.isdigit, str(cpf)))
    if len(str_cpf) != 11:
        return False
    if str_cpf in [s * 11 for s in "0123456789"]:
        return False
    soma = sum(int(str_cpf[i]) * (10 - i) for i in range(9))
    resto = (soma * 10) % 11
    if resto == 10 or resto == 11:
        resto = 0
    if resto != int(str_cpf[9]):
        return False
    soma = sum(int(str_cpf[i]) * (11 - i) for i in range(10))
    resto = (soma * 10) % 11
    if resto == 10 or resto == 11:
        resto = 0
    if resto != int(str_cpf[10]):
        return False
    return True

@app.route('/buscar_tags', methods=['GET'])
def buscar_tags():
    tags = Tags.query.with_entities(Tags.tag).all()
    return jsonify({"tags": tags}), 200

@app.route('/gerarcodigo', methods=['POST'])
def gerarcodigo():
    dados = request.get_json()
    email = dados.get('email')
    emailexists = Pessoas.query.filter_by(email=email).first()
    if emailexists:
        return jsonify({'sucess': False, "message": f'E-mail já cadastrado.'}), 409
    code = ''.join(random.choices('0123456789', k=6))
    expira = datetime.now() + timedelta(minutes=5)
    verificacao = Verificar.query.get(email)
    if verificacao:
        verificacao.code = code
        verificacao.expiration = expira
    else:
        pseudo_cadastro = Verificar(email=email, code=code, expiration=expira)
        db.session.add(pseudo_cadastro)
    db.session.commit()
    try:
        msg = EmailMessage()
        msg["Subject"] = f"Seu código de verificação"
        msg["From"] = EMAIL_ORIGEM
        msg["To"] = email
        msg.set_content(f"Seu código: {code}")
        try:
            with smtplib.SMTP(SMTP_SERVIDOR, SMTP_PORTA) as smtp:
                smtp.starttls()
                smtp.login(EMAIL_ORIGEM, EMAIL_SENHA_APP)
                smtp.send_message(msg)
            print("E-mail enviado com sucesso.")
            logger.info("E-mail enviado com sucesso.")
        except Exception as e:
            print("Erro ao enviar e-mail:", e)
            logger.error("Erro ao enviar e-mail:", e)
    except Exception as e:
        logger.error("Erro ao enviar e-mail:", e)
        return jsonify({'error': f'Erro ao enviar e-mail: {e}'}), 500
    logger.info('Código enviado! Verifique seu e-mail.')
    return jsonify({'message': 'Código enviado! Verifique seu e-mail.'}), 200

def enviar_email(email, status, solicitacao):
    try:
        msg = EmailMessage()
        msg["Subject"] = f"Resultado da solicitação de {solicitacao}"
        msg["From"] = EMAIL_ORIGEM
        msg["To"] = email
        msg.set_content(f"Sua solicitação de {solicitacao} no site Bolsa2025 foi {status}")
        try:
            with smtplib.SMTP(SMTP_SERVIDOR, SMTP_PORTA) as smtp:
                smtp.starttls()
                smtp.login(EMAIL_ORIGEM, EMAIL_SENHA_APP)
                #smtp.send_message(msg)
            print("E-mail enviado com sucesso.")
            logger.info("E-mail enviado com sucesso.")
        except Exception as e:
            print("Erro ao enviar e-mail:", e)
            logger.error("Erro ao enviar e-mail:", e)
    except Exception as e:
        logger.error("Erro ao enviar e-mail:", e)
        return jsonify({'error': f'Erro ao enviar e-mail: {e}'}), 500
    logger.info('E-mail enviado ao usuário.')
    return jsonify({'message': 'E-mail enviado ao usuário.'}), 200

@app.route('/verificar_codigo', methods=['POST'])
def verificar_codigo():
    dados = request.get_json()
    email = dados.get('email')
    code = dados.get('codigo')
    verificacao = Verificar.query.filter_by(email=email).first()
    expiration_dt = datetime.strptime(verificacao.expiration, "%Y-%m-%d %H:%M:%S.%f")
    if not verificacao:
        return jsonify({'error': 'E-mail não encontrado'}), 404
    if verificacao.verificado:
        return jsonify({'message': 'E-mail já verificado'}), 200
    if expiration_dt < datetime.now():
        return jsonify({'error': 'Código expirado'}), 400
    if verificacao.code != int(code):
        return jsonify({'error': 'Código incorreto'}), 400
    verificacao.verificado = True
    db.session.commit()
    return jsonify({'message': 'E-mail verificado com sucesso', "validado": True}), 200

@app.route('/pagina_inicial', methods=['GET'])
@token_requerido
def pagina_inicial():
    user_id = g.user_id
    usuario = db.session.query(Pessoas).filter(Pessoas.id == user_id).first()
    if not usuario:
        return jsonify({"success": False, "message": "Usuario não encontrado."}), 404
    return jsonify({
        "success": True,
        "usuario": {
            "nome": usuario.nome,
            "tag": usuario.tag}})

@app.route('/master_painel', methods=['GET'])
@token_requerido
def master_painel():
    master = g.tipo
    if not master or master != "master":
        return jsonify({"message": "Você não tem permissão para acessar esta página."}), 403
    return jsonify({"message": "Login bem sucedido!"}), 200

@app.route('/verificar_tag', methods=['POST'])
def verificar_tag():
    dados = request.json
    tag = dados.get('tag')
    access_ok = Tags.query.filter_by(tag=tag).first()
    if access_ok:
        print(tag)
        return jsonify({"sucess": True, "mensagem": "Tag encontrada!"}), 200
    else:
        return jsonify({"sucess": False, "mensagem": "Tag não encontrada!"}), 401

@app.route('/registro_log', methods=['POST'])
def registro_log():
    dados = request.json
    tag = dados.get('tag')
    data_inicial = datetime.strptime(dados.get('data_inicial'), "%Y-%m-%d %H:%M:%S")
    data_final = datetime.strptime(dados.get('data_final'), "%Y-%m-%d %H:%M:%S")
    kWh = dados.get('kWh')
    cadastrar_log = Logs.query.filter_by(tag=tag).first()
    if cadastrar_log == None:
        tag_pessoal = Pessoas.query.filter_by(tag=tag).first()
        cadastrar_novo_log = Logs(tag=tag_pessoal.tag, cpf=tag_pessoal.cpf, data_inicio=data_inicial, data_fim=data_final, kWh=kWh)
        db.session.add(cadastrar_novo_log)
        db.session.commit()
        print('oi ' + tag, data_inicial, data_final, kWh)
    else:
        cadastrar_novo_log = Logs(tag=cadastrar_log.tag, cpf=cadastrar_log.cpf, data_inicio=data_inicial, data_fim=data_final, kWh=kWh)
        db.session.add(cadastrar_novo_log)
        db.session.commit()
        print('oi2 ' + tag, data_inicial, data_final, kWh)


    return jsonify({"sucess": True, "mensagem": "Recebido com sucesso!"}), 200

@app.route('/reset_password', methods=['POST'])
def reset_password():
    dados = request.json
    email = dados.get('email')
    senha = dados.get('senha')
    code = dados.get('codigo')
    verificacao = Verificar.query.filter_by(email=email).first()
    expiration_dt = datetime.strptime(verificacao.expiration, "%Y-%m-%d %H:%M:%S.%f")
    if not verificacao:
        return jsonify({'error': 'E-mail não encontrado'}), 404
    if expiration_dt < datetime.now():
        return jsonify({'error': 'Código expirado'}), 400
    if verificacao.code != int(code):
        return jsonify({'error': 'Código incorreto'}), 400
    att_senha = Pessoas.query.filter_by(email=email).first()
    senha_hash = generate_password_hash(senha)
    att_senha.senha = senha_hash
    db.session.commit()
    return jsonify({'message': 'Senha atualizada com sucesso!', "sucess": True}), 200

@app.route('/cadastro_tag', methods=['POST'])
def cadastro_tag():
    data = request.get_json()
    tag = data.get('tag')
    excluir_flag = data.get('excluir')
    print(data)
    tag_encontrada = Tags.query.filter_by(tag=tag).first()
    if tag_encontrada:
        if excluir_flag is True:
            if tag_encontrada.nome != "":
                logger.info("Você não pode excluir uma tag associada a alguém!")
                return jsonify({"sucess": False, "mensagem": "Você não pode excluir uma tag associada a alguém!"}), 422
            exclusao_tag(tag_encontrada)
            logger.info("Tag excluída com sucesso!")
            return jsonify({
                "success": True,
                "message": f"Tag {tag} excluída com sucesso!"
            }), 200
        else:
            logger.info(f"Deseja excluir a tag {tag}?")
            return jsonify({
                "success": False,
                "message": f"Deseja excluir a tag {tag}?"
            }), 202
    else:
        nova_tag = Tags(tag=tag, nome="")
        try:
            db.session.add(nova_tag)
            db.session.commit()
            logger.info("Tag cadastrada com sucesso!")
            return jsonify({
                "success": True,
                "message": "Tag cadastrada com sucesso!"
            }), 201
        except Exception as e:
            db.session.rollback()
            logger.error("Erro ao cadastrar a tag: {str(e)}")
            return jsonify({
                "success": False,
                "message": f"Erro ao cadastrar a tag: {str(e)}"
            }), 500

def exclusao_tag(tag):
    db.session.delete(tag)
    db.session.commit()

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({"success": True, "message": "Logout com sucesso!"})

@app.route('/log', methods=['GET'])
@token_requerido
def log():
    user_id = g.user_id
    usuario = db.session.query(Pessoas).filter(Pessoas.id == user_id).first()
    logdados = db.session.query(Logs).filter(Logs.cpf == usuario.cpf).all()
    consumo = sum(u.kWh for u in logdados)
    logs = [
        {
            "data_inicio": log.data_inicio.strftime("%d-%m-%Y %H:%M:%S"),
            "data_fim": log.data_fim.strftime("%d-%m-%Y %H:%M:%S"),
            "kWh": log.kWh
        }
        for log in logdados
    ]
    return jsonify({
        "success": True,
        "log": {
            "consumo": consumo,
            "logdados": logs}})

@app.route('/lost_tag', methods=['POST'])
@token_requerido
def lost_tag():
    data = request.json
    tag = data.get('tag')
    tag_encontrada = Tags.query.filter_by(tag=tag).first()
    tag_user = db.session.query(Pessoas).filter_by(tag=tag).first()
    if tag_encontrada:
        tag_user.tag = ''
        db.session.delete(tag_encontrada)
        db.session.commit()
        return jsonify({"success": True, "message": "Tag deletada com sucesso!"})

@app.route('/pedidos_tag', methods=['GET'])
def pedidos_tag():
    pessoas = Pessoas.query.filter_by(tag="").all()
    lista_pessoas = [
        {
            'id': assoc.id,
            'nome': assoc.nome,
            'tag': assoc.tag,
            'cpf': assoc.cpf}
        for assoc in pessoas]
    return jsonify(lista_pessoas)

@app.route('/cadastro', methods=['POST'])
def cadastro():
    if request.method == 'POST':
        data = request.get_json()
        nome = data.get('nome')
        cpf = data.get('cpf')
        senha = data.get('senha')
        email = data.get('email')
        if not email or not senha:
            return jsonify({"success": False, "message": "Email e senha são obrigatórios"}), 400
        if not valida_email(email):
            return jsonify({"success": False, "message": "Email está em formato incorreto"}), 400
        if not valida_cpf(cpf):
            return jsonify({"success": False, "message": "CPF está em formato incorreto"}), 400
        senha_hash = generate_password_hash(senha)
        proximo_id = db.session.query(func.max(Pendentes.id)).scalar()
        proximo_id = 1 if proximo_id is None else proximo_id + 1
        novo_usuario = Pendentes(id=proximo_id, nome=nome, tag="", cpf=cpf, approved=False, senha=senha_hash, email=email)
        try:
            db.session.add(novo_usuario)
            db.session.commit()
            return jsonify({
                "success": True,
                "message": "Cadastro solicitado com sucesso!<br>Seu cadastro será avaliado por um administrador e em breve você terá um retorno via email.",
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Erro ao cadastrar o usuário. {str(e)}"}), 400

@app.route('/lista_pendentes', methods=['GET'])
def lista_pendentes():
    usuarios = Pendentes.query.filter_by(approved=False).all()
    lista_usuarios = [
        {
            'id': assoc.id,
            'nome': assoc.nome,
            'tag': assoc.tag,
            'cpf': assoc.cpf,
            'aprovado': assoc.approved}
        for assoc in usuarios]
    return jsonify(lista_usuarios)

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        email = data.get('email')
        senha = data.get('senha')
        if not email or not senha:
            return jsonify({"success": False, "message": "Email e senha são obrigatórios"}), 400
        if not valida_email(email):
            return jsonify({"success": False, "message": "Email está em formato incorreto"}), 400
        master_user = Master.query.filter_by(email=email).first()
        normal_user = Pessoas.query.filter_by(email=email).first()
        pendentes_user = Pendentes.query.filter_by(email=email).first()
        if master_user:
            if master_user.verificar_senha(senha):
                token = criar_token(master_user, 'master')
                return jsonify({"success": True, "token": token, "tipo": "master"}), 200
            return jsonify({"success": False, "message": "Nome ou senha incorretos"}), 401
        elif normal_user:
            if normal_user.verificar_senha(senha):
                token = criar_token(normal_user, 'normal')
                return jsonify({"success": True, "token": token, "tipo": "normal"}), 200
            return jsonify({"success": False, "message": "Nome ou senha incorretos"}), 401
        elif pendentes_user and not pendentes_user.approved:
            return jsonify({"success": False, "message": 'Seu cadastro ainda não foi aprovado!'}), 401
        else:
            return jsonify({"success": False, "message": "Usuário não cadastrado"}), 400

@app.route('/master_user', methods=['GET'])
def master_user():
    usuarios = Pendentes.query.filter_by(approved=False).all()
    lista_usuarios = [
        {
            'nome': assoc.nome,
            'tag': assoc.tag,
            'cpf': assoc.cpf,
            'aprovado': assoc.approved}
        for assoc in usuarios]
    return jsonify(lista_usuarios)

@app.route('/aprovar/<int:id>', methods=['POST'])
@token_requerido
def aprovar(id):
    data = request.get_json()
    estado = data.get('aprovado')
    solicitacao = data.get('solicitacao')
    usuario_pendente = db.session.query(Pendentes).filter_by(id=id).first()
    usuario_normal = db.session.query(Pessoas).filter_by(id=id).first()
    if not usuario_pendente and solicitacao == "cadastro" or not usuario_normal and solicitacao == "tag":
        return jsonify({"success": False, "message": "Usuário não encontrado."}), 404
    if solicitacao == 'tag':
        if estado == False:
            enviar_email(usuario_normal.email, "recusada", solicitacao="pedido por nova TAG")
            return jsonify({"success": False, "message": "Usuário não irá receber uma nova TAG."}), 401
        else:
            dado = Tags.query.filter_by(nome="").first()
            if dado:
                dado.nome = usuario_normal.nome
                try:
                    db.session.commit()
                    return jsonify({"success": True, "message": f"Usuário recebeu uma nova TAG."})
                except Exception as e:
                    db.session.rollback()
                    return jsonify({"success": False, "message": f"Erro ao conceder tag para o usuário. {str(e)}"}), 400
            else:
                return jsonify({"success": False, "message": "Não há tags disponíveis!"}), 404
    elif solicitacao == 'cadastro':
        if estado == False:
            db.session.delete(usuario_pendente)
            enviar_email(usuario_pendente.email, "recusada", solicitacao)
            return jsonify({"success": False, "message": "Cadastro de usuário não autorizado."}), 401
        else:
            usuario_pendente.approved = estado
            dado = Tags.query.filter_by(nome="").first()
            if dado:
                dado.nome = usuario_pendente.nome
                try:
                    proximo_id = db.session.query(func.max(Pessoas.id)).scalar()
                    proximo_id = 1 if proximo_id is None else proximo_id + 1
                    novo_usuario = Pessoas(id=proximo_id, nome=usuario_pendente.nome, tag=dado.tag, cpf=usuario_pendente.cpf, senha=usuario_pendente.senha, email=usuario_pendente.email)
                    del_temp = db.session.query(Verificar).filter_by(email=usuario_pendente.email).first()
                    db.session.add(novo_usuario)
                    db.session.delete(del_temp)
                    db.session.delete(usuario_pendente)
                    db.session.commit()
                    return jsonify({"success": True, "message": f"Usuário foi aprovado."})
                except Exception as e:
                    db.session.rollback()
                    return jsonify({"success": False, "message": f"Erro ao aprovar o usuário. {str(e)}"}), 400
            else:
                return jsonify({"success": False, "message": "Não há tags disponíveis!"}), 404

if __name__ == "__main__":
    with app.app_context():
        enforce_foreign_keys()
        db.create_all()
    app.run(host="0.0.0.0", port=5050)
