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
import bcrypt
from sqlalchemy.orm.attributes import flag_modified

from models import db, Doctor, Doc_address, User, Appointment

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

# Admin Token verification function
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

# User Token verification function
def user_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Get token from the Authorization header
        if not token:
            return make_response(jsonify({"error": "Token is missing!"}), 401)
        
        try:
            # Decode the token to verify it's valid
            if token.startswith('Bearer '):
                token = token.split(' ')[1]

            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            kwargs['user_id'] = payload.get('user_id')


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

# Admin add doctor resource
class AdminAddDoctor(Resource):
    
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

api.add_resource(AdminAddDoctor, '/admin-add-doctor')

#API for fetching doctors for admin
class AdminDoctor(Resource):

    @token_required
    def post(self):

        try:

            doctors = Doctor.query.all()

            doctor_list = [doctor.to_dict() for doctor in doctors]

            response = jsonify({
                "success": True,
                "doctors": doctor_list
            })
            return make_response(response, 200)
        
        except Exception as e:
            print("Error fetching doctors:", str(e))
            return make_response(jsonify({"success": False, "message": "Error fetching doctors"}), 500)
        

api.add_resource(AdminDoctor, '/admin-doctors')

#API for updating doctor availability
class UpdateDoctorAvailability(Resource):
    @token_required
    def patch(self, doctor_id):
        try:
            doctor = Doctor.query.get(doctor_id)
            

            if doctor:
                if doctor.available == True:

                    doctor.available = False
                    db.session.add(doctor)
                    db.session.commit()

                else:
                    doctor.available = True
                    db.session.add(doctor)
                    db.session.commit()

                
            new_doc = doctor.to_dict()

            response = jsonify({
                "success": True,
                "doctor": new_doc,
                "message":"Availability updated successfully"
            })

            return make_response(response, 200)

        except Exception as e:
            db.session.rollback()
            print({str(e)})
            return make_response(
                jsonify({
                    "success": False,
                    "message": f"An error occurred: {str(e)}"
                }), 
                500
            )

api.add_resource(UpdateDoctorAvailability, '/admin-update-doctor-availability/<int:doctor_id>')

#API for user getting doctor
class DoctorList(Resource):

    def get(self):

        try:

            doctors = Doctor.query.all()

            exclude_fields = ["email"]

            doctor_list = []

            for doctor in doctors:
                doctor_dict = doctor.to_dict()

                # Remove the fields you want to exclude
                for field in exclude_fields:
                    doctor_dict.pop(field, None)

                doctor_list.append(doctor_dict)

            response = jsonify({
                "success": True,
                "doctors": doctor_list
            })
            return make_response(response, 200)
        
        except Exception as e:
            print("Error fetching doctors:", str(e))
            return make_response(jsonify({"success": False, "message": "Error fetching doctors"}), 500)
        
api.add_resource(DoctorList, '/doctors/list')

#API for registering new user
class RegisterUser(Resource):
    def post(self):
        try:
            data = request.get_json()
            name = data['name']
            email = data['email']
            password = data['password']

            if not name or not email or not password:
                response = jsonify({
                    "success": False,
                    "message": "All fields are required"
                })
                return make_response(response, 200)

            try:
                userData = User(
                    email = email,
                    name = name,
                    password = password
                )
            except ValueError as validation_error:
                # Extract the specific validation error message
                error_message = str(validation_error)
                response = jsonify({
                    "success": False,
                    "message": error_message
                })
                return make_response(response, 200)

            db.session.add(userData)
            
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                response = jsonify({
                    "success": False, 
                    "message": "Email already exists. Please use a different email."
                })
                return make_response(response, 200)

            # Create token using user ID after successful commit
            token = jwt.encode({
                'user_id': userData.id,
                'email': email,
                'exp': datetime.datetime.now() + datetime.timedelta(hours=24)
            }, SECRET_KEY, algorithm='HS256')

            if isinstance(token, bytes):
                token = token.decode('utf-8')

            user_dict = userData.to_dict()

            response = jsonify({
                "success": True,
                "token": token
            })

            return make_response(response, 201)

        except Exception as e:
            db.session.rollback()
            return make_response(jsonify({
                "success": False, 
                "message": f"Error registering user: {str(e)}"
            }), 500)
        
api.add_resource(RegisterUser, '/user/register')

#API for user login
class UserLogin(Resource):
    def post(self):
        try:
            data = request.get_json()  # Get JSON request data
            email = data.get('email')
            password = data.get('password')

            # Validate email and password existence
            if not email or not password:
                return {"error": "Email and password are required"}, 400
            
            user = User.query.filter_by(email=email).first()

            if not user:
                return make_response(jsonify({
                    "success": False,
                    "message": "User does not exist"
                }), 200)
            
            # Verify password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                token = jwt.encode({
                    'user_id': user.id,
                    'email': user.email,
                    'exp': datetime.datetime.now() + datetime.timedelta(hours=24)
                }, SECRET_KEY, algorithm='HS256')

                if isinstance(token, bytes):
                    token = token.decode('utf-8')

                return make_response(jsonify({
                    "success": True,
                    "token": token,
                }), 200)
            
            else:
                return make_response(jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 200)

        except Exception as e:
            return make_response(jsonify({"success": False,"error": f"An error occurred: {str(e)}"}), 400)


api.add_resource(UserLogin, '/user/login')

#API to get user profile data
class GetProfile(Resource):
    @user_token_required
    def get(self, user_id):
        userdata = User.query.get(user_id)
        if not userdata:
            return make_response(jsonify({"success": False,"message": "User not found"}), 200)
        
        serialized_user_data = userdata.to_dict()

            
        return make_response(jsonify({
                    "success": True,
                    "userData": serialized_user_data
                }), 200)
    
    @user_token_required
    def patch(self, user_id):
        try:
            
            user = User.query.get(user_id)

            name = request.form.get('name')
            gender = request.form.get('gender')
            dob = request.form.get('dob')
            phone = request.form.get('phone')
            address = request.form.get('address')

            image_file = request.files.get('image')
            if image_file:
                # Upload image to Cloudinary
                upload_response = cloudinary.uploader.upload(image_file)
                image_url = upload_response.get('secure_url')
                user.image = image_url

            
            address_data = json.loads(address)
            

            if not name or not phone or not dob or not gender:
                response = jsonify({"success":False, "message":"missing details"})
                return make_response(response, 200)


            

            user.name = name
            user.gender = gender
            user.dob = dob
            user.phone = phone
            user.address = address_data
            
            

            db.session.add(user)
            db.session.commit()

            response = jsonify({"success":True, "message":"Profile Updated"})

            return make_response(response, 201)

        except Exception as e:
            return make_response(jsonify({"success": False,"error": f"An error occurred: {str(e)}"}), 400)
        
api.add_resource(GetProfile, '/user-profile')

#API to book appointment
class BookAppointment(Resource):
    @user_token_required
    def post(self, user_id):
        try:

            data = request.get_json()
            docId = data.get('docId')
            slotDate = data.get('slotDate')
            slotTime = data.get('slotTime')

            if not all([docId, slotDate, slotTime]):
                response = jsonify({
                    "success": False,
                    "message": "Missing required fields: docId, slotDate, and slotTime"
                })
                return make_response(response, 200)

            docData = Doctor.query.get(docId)
            userData = User.query.get(user_id)
            serializedUserData = userData.to_dict()
            serializedDocData = docData.to_dict()


            if docData.available == False:
                response = jsonify({"success":False, "message":"Doctor not available"})
                return make_response(response, 200)


            if docData.slots_booked is None:
                docData.slots_booked = {}

            # Check if slot is already booked
            if slotDate in docData.slots_booked:
                if slotTime in docData.slots_booked[slotDate]:
                    return make_response(jsonify({
                        "success": False,
                        "message": "This slot is already booked"
                    }), 200)
            else:
                docData.slots_booked[slotDate] = []

            # Add new slot
            # Update doctor's slots
            docData.slots_booked[slotDate].append(slotTime)
            
            flag_modified(docData, 'slots_booked')

            new_appointment = Appointment(
                userId = user_id,
                docId = docId,
                userData = serializedUserData,
                docData = serializedDocData,
                amount = docData.fees,
                slotTime = slotTime,
                slotDate = slotDate

            )

            
            db.session.add(docData)
            db.session.add(new_appointment)
            db.session.commit()
            
            
            response = jsonify({
                "success": True, 
                "message": "Slot booked successfully"
            })
            return make_response(response, 200)


        except Exception as e:
            db.session.rollback()
            print(f"Error booking slot: {str(e)}")  # For debugging
            response = jsonify({
                "success": False, 
                "message": f"An error occurred: {str(e)}"
            })
            return make_response(response, 500)

api.add_resource(BookAppointment, '/book-appointment')

# Login Resource
class AdminLogin(Resource):
    
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
api.add_resource(AdminLogin, '/admin/login')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
