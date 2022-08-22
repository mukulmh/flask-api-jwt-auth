import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
ma = Marshmallow(app)

# user model/class
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    jwt_token = db.Column(db.String(128), nullable=True)
    movie = db.relationship('Movie')

    def __repr__(self):
        return '<User %r>' %self.id

# user schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'password', 'created_at', 'jwt_token')

user_schema = UserSchema()
users_schema = UserSchema(many=True)


# token authentication function
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token required!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
            if token != current_user.jwt_token:
                return jsonify({'message': 'Token expired!'})
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


# get all user
@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):

    users = User.query.order_by(User.created_at).all()
    result = users_schema.dump(users)
 
    return jsonify(result)


# get one user
@app.route('/user/<int:id>', methods=['GET'])
@token_required
def get_one_user(current_user,id):
    user = User.query.get_or_404(id)
    
    return user_schema.jsonify(user)


# register user
@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


# update user
@app.route('/user/<int:id>', methods=['PUT'])
@token_required
def update_user(current_user,id):
    user_to_update = User.query.get_or_404(id)
    hashed_password = generate_password_hash(request.json['password'], method='sha256')
    user_to_update.email = request.json['email']
    user_to_update.password = hashed_password

    db.session.commit()
    return jsonify({'message': 'User has been updated!'})


# delete user
@app.route('/user/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user,id):
    user_to_delete = User.query.get_or_404(id)

    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'message': 'The user has been deleted!'})


# login user
@app.route('/login')
def login():
    auth = request.get_json()

    if not auth:
        return jsonify({'message': 'login required!'})
    
    user = User.query.filter_by(email = auth['email']).first()
    
    if not user:
        return jsonify({'message': 'No user found!'})
    
    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'])
        user.jwt_token = token
        db.session.commit()
        
        return jsonify({'token': token})

    return jsonify({'message': 'Login with valid email and password!'})


# logut user
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    user = current_user
    user.jwt_token = None
    db.session.commit()

    return jsonify({'message': 'User logged out!'})


# movie model/class
class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey ('user.id'))

    def __repr__(self):
        return '<Item %r>' % self.id

# movie schema
class MovieSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description', 'created_at')

movie_schema = MovieSchema()
movies_schema = MovieSchema(many=True)


# create / retrieve movie(s)
@app.route('/movie', methods=['POST','GET'])
@token_required
def index(current_user):
    if request.method == 'POST':
        movie_name = request.json['name']
        movie_description = request.json['description']

        new_movie = Movie(name = movie_name, description = movie_description)

        try:
            db.session.add(new_movie)
            db.session.commit()
            return movie_schema.jsonify(new_movie)
        except:
            return jsonify({ 'msg': 'There was an error inserting data'})
    else:
        movies = Movie.query.order_by(Movie.created_at).all()
        result = movies_schema.dump(movies)

        return jsonify(result)


# retrieve movie by id
@app.route('/movie/<int:id>', methods=['GET'])
def get_movie(id):
    movie = Movie.query.get_or_404(id)
    
    return movie_schema.jsonify(movie)


# delete movie by id
@app.route('/movie/<int:id>', methods=['DELETE'])
def delete(id):
    movie_to_delete = Movie.query.get_or_404(id)
    
    try:
        db.session.delete(movie_to_delete)
        db.session.commit()
        return movie_schema.jsonify(movie_to_delete)
    except:
        return jsonify({ 'msg': 'Error while deleting data'})


# update movie by id
@app.route('/movie/<int:id>', methods=['PUT'])
def update(id):
    movie = Movie.query.get_or_404(id)
    
    movie.name = request.json['name']
    movie.description = request.json['description']

    try:
        db.session.commit()
        return movie_schema.jsonify(movie)

    except:
        return jsonify({'msg': 'Error updating data!'})


if __name__ == "main":
    app.run(debug=True)