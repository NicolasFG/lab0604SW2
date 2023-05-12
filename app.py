from flask import Flask
from flask import request, jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager, get_jwt,verify_jwt_in_request
import bcrypt
from flask import g
from functools import wraps




app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

API_KEY_VAL = "000000111111"


# access_token= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY4Mzg1NTA3MywianRpIjoiMzRlZTNiOTUtOThkZC00MGUwLWE0ODQtZTE2NWNhMTcwOGZmIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InRlc3QiLCJuYmYiOjE2ODM4NTUwNzMsImV4cCI6MTY4Mzg1NTk3M30.h-P6m9z9TYGz1CdeW_ow2ug3RBm8EvLEQo89J8ICIfg"

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401
    
    claims = {"group" : "/group01"}

    access_token = create_access_token(identity=username, additional_claims=claims)
    return jsonify(access_token=access_token)

def required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        jwt_data = get_jwt()
        print(jwt_data)
        path = request.path

        if path != jwt_data["group"]:
            return "restringido"
        
        return f(*args, **kwargs)
    return decorated_function



@app.route('/group01', methods=["POST"])
@jwt_required()
def group01():
    api_key = request.json.get("api_key", None)
    print(api_key)
    api_key_bytes = bytes(API_KEY_VAL, 'utf-8')
    hash_from_api = bytes(api_key, 'utf-8')
    current_user = get_jwt_identity()
    if bcrypt.checkpw(api_key_bytes, hash_from_api):
        return jsonify(logged_in_as=current_user), 200
    else:
     return jsonify(result="Incorrect api key")


@app.route('/group02')
@required
def group02():
    return jsonify({'result': 'este es el grupo 02'})

@app.route('/group03')
@required
def group03():
    return jsonify({'result': 'este es el grupo 03'})

@app.route('/group04')
@required
def group04():
    return jsonify({'result': 'este es el grupo 04'})

if __name__ == "__main__":
    app.run(debug=True, port=5000)