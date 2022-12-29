from flask_restful import Resource, reqparse
#from werkzeug.security import safe_str_cmp     # deprecated
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from blacklist import BLACKLIST

from models.usuario import UserModel
import hmac     # para fazer a validaçao da string de senha
import traceback
from flask import make_response, render_template


# var global
atributos = reqparse.RequestParser() # instanciando o objeto atributo da classe RequestParser
atributos.add_argument('login', type=str, required=True, help="O campo 'login' é obrigatório.")
atributos.add_argument('senha', type=str, required=True, help="O campo 'senha' é obrigatório.")
atributos.add_argument('email', type=str)
atributos.add_argument('ativado', type=bool)

class User(Resource):
    # /usuarios/{user_id}
    def get(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return{'message': 'User_id não encontrado'}, 404     #not found

    @jwt_required()
    def delete(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            try:
                user.delete_user()
            except:
                return {'message': 'An internal error occurred trying to save data.'}, 500
            return {'message': 'User deleted.'}
        return {'message': 'User not found.'}, 404

class UserRegister(Resource):
    #/cadastro
    #@jwt_required()
    def post(self):

        dados = atributos.parse_args()
        if not dados.get('email') or dados.get('email') is None:
            return {'message': "Email cannot be blank."}, 400

        if UserModel.find_by_email(dados['email']):
            return {"message": "O email '{}' já existe.".format(dados['email'])}

        if UserModel.find_by_login(dados['login']):
            return {"message": "O login '{}' já existe.". format(dados['login'])}

        user = UserModel(**dados)
        user.ativado = False
        try:
            user.save_user()
            user.send_confirmation_email()
        except:
            user.delete_user()
            traceback.print_exc()
            return {"message": "Erro interno"}, 500
        return {"message": "Usuário criado com sucesso"}, 201  # created


class UserLogin(Resource):

    @classmethod
    def post(cls):
        dados = atributos.parse_args()

        user = UserModel.find_by_login(dados['login'])

        # if user and safe_str_cmp(user.senha, dados['senha']): # deprecated
        if user and hmac.compare_digest(user.senha,dados['senha']):
            if user.ativado:
                token_de_acesso = create_access_token(identity=user.user_id)
                return {'access token': token_de_acesso}, 200
            else:
                return {"message": 'User not active'}, 400
        return {"message": 'User or password is incorrect'}, 401    # unauthorized


class UserLogout(Resource):

    @jwt_required()
    def post(self):
        jwt_id = get_jwt()['jti']   # JWT Token Identifier
        BLACKLIST.add(jwt_id)
        return {'message': 'Logged Out'}, 200


class UserConfirm(Resource):
    # /confirma/{user_id}
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_user(user_id)

        if not user:
            return {'message': "User ID '{}' not found.".format(user_id) }, 404

        user.ativado = True
        user.save_user()
        # return {'message': "User ID '{}' confirmed.".format(user_id) }, 200
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('user_confirm.html', email=user.email, usuario=user.login), 200, headers)


















