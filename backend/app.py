from flask import Flask, request, make_response, jsonify, json
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_login import LoginManager
from sqlalchemy.exc import IntegrityError
from json import JSONDecodeError
import cloudinary
import cloudinary.uploader
import os
import jwt
import datetime
import ast
from dotenv import load_dotenv
from functools import wraps
import re

from models import db, Doctor, Doc_address

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'  # Convert to boolean
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
SECRET_KEY = os.getenv('SECRET_KEY')
app.json.compact = False

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

migrate = Migrate(app, db)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

CORS(app)
api = Api(app)

# Token creation function
def create_token(email,password):
    
    token = jwt.encode({
        'email': email,
        'password':password,
        'exp': datetime.datetime.now() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')

    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Get token from the Authorization header
        if not token:
            return make_response(jsonify({"error": "Token is missing!"}), 401)
        
        try:
            # Decode the token to verify it's valid
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return make_response(jsonify({"error": "Token has expired!"}), 401)
        except jwt.InvalidTokenError:
            return make_response(jsonify({"error": "Invalid token!"}), 401)
        
        # If everything is okay, call the wrapped function and return its response
        return f(*args, **kwargs)
    return decorated



    
    

# Home Resource
class Home(Resource):
    def get(self):
        message = {
            "message": "API is working"
        }
        return make_response(message, 200)

api.add_resource(Home, '/')

# Doctor Resource

class DoctorResource(Resource):
    def get(self):
        message = {
            "message": "Getting doctor!"
        }
        return make_response(message, 200)
    
    @token_required
    def post(self):

        try:

            
            image_file = request.files.get('image')
            image_url = None  # Initialize image_url

            
            if image_file:
                # Upload image to Cloudinary
                upload_response = cloudinary.uploader.upload(image_file)
                image_url = upload_response.get('secure_url')

            address_str = request.form.get('address')

            
            # Ensure that the string doesn't contain any extra characters
            address_data = json.loads(address_str)
            
            if not isinstance(address_data, dict):
                raise ValueError("Address data must be a dictionary")
            

            
            address = Doc_address(**address_data)

            db.session.add(address)
            db.session.commit()

            new_doctor = Doctor(
                name=request.form['name'],
                email=request.form['email'],
                password=request.form['password'],
                speciality=request.form['speciality'],
                degree=request.form['degree'],
                experience=request.form['experience'],
                about=request.form['about'],
                fees=request.form['fees'],
                image=image_url,
                address_id=address.id
            )
            

            db.session.add(new_doctor)
            db.session.commit()


            doctor_dict = new_doctor.to_dict()


            response = jsonify({
                "success": True, 
                "message": "Doctor added successfully", 
                "doctor": doctor_dict
            })

            return make_response(response, 201)
        
        except IntegrityError:
            db.session.rollback()
            response = jsonify({
                "success": False, 
                "message": "Email already exists. Please use a different email."
            })
            return make_response(response, 400)
            
        except Exception as e:
            print("Unexpected Error:", str(e))  # More general catch for any unexpected errors
            db.session.rollback()  # Rollback the session if any exception occurs
            response = jsonify({"success": False, "message":str(e)})
            return make_response(response, 500)

api.add_resource(DoctorResource, '/doctors')

# Login Resource
class Login(Resource):
    
    def post(self):
        try:
            data = request.get_json()  # Get JSON request data
            email = data.get('email')
            password = data.get('password')

            # Validate email and password existence
            if not email or not password:
                return {"error": "Email and password are required"}, 400



            # Check if email and password match the environment variables
            if email == os.getenv('ADMIN_EMAIL') and password == os.getenv('ADMIN_PASSWORD'):
                token = create_token(email,password)
                json_response = jsonify({"success": True, "token": token})

                return make_response(json_response, 200)
            response = jsonify({"success": False,"message": "Invalid Credentials!"})
            return make_response(response, 401)
        except Exception as e:
            return make_response(jsonify({"success": False,"error": f"An error occurred: {str(e)}"}), 400)

# Add the Login resource to the API
api.add_resource(Login, '/admin/login')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
