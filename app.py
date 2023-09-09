from flask import Flask, request, render_template,redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskapp.db'
app.config['SECRET_KEY'] = 'myflaskappfordemo'
db = SQLAlchemy(app)
jwt = JWTManager(app)

class Image_data(db.Model):
    sl = db.Column(db.Integer, primary_key=True)
    
    image = db.Column(db.String)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)








@app.route('/')
def login():
          cookie = request.cookies.get('auth')
          if cookie is not None:
                    return render_template('index.html')
          else:
                    return render_template('Login.html')


          


@app.route('/signup')
def createuser():
          return render_template('Signup.html')



from flask import redirect, url_for

@app.route('/register', methods=['POST'])
def registeruser():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    
    return "successfull"




@app.route('/auth', methods=['POST'])
def loguser():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user.id)
    resp = make_response()
    resp.set_cookie('auth', access_token)
    return access_token





@app.route('/homepage')

def home():
          return render_template('index.html')


@app.route('/capture')

def capture():
          return render_template('capture.html')



@app.route('/add', methods=['POST'])
def upload():
    cookie = request.cookies.get('auth')
    
    if cookie is not None:
        if 'image' in request.files:
            image_file = request.files['image']
            
            if image_file.filename != '':
                new_image = Image_data(image=base64.b64encode(image_file.read()).decode('utf-8'))
                db.session.add(new_image)
                db.session.commit()
                return render_template('show.html', image_data=new_image.image)
            
            return "Image upload failed."
    else:
        return render_template('Login.html')


if __name__ == '__main__':
    app.run(debug=True, port=7000)
