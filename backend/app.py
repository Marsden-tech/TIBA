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
import pytz
from dotenv import load_dotenv
from functools import wraps
import base64
import bcrypt
import requests
import logging
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
            return make_response(jsonify({"success":False, "error": "Token is missing!"}), 200)
        
        try:
            # Decode the token to verify it's valid
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return make_response(jsonify({"success":False, "error": "Token has expired!"}), 200)
        except jwt.InvalidTokenError:
            return make_response(jsonify({"success":False, "error": "Invalid token!"}), 200)
        
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


            if not docData.available:
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
                "message": "Appointment booked successfully"
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

#API to get user appointments data
class UserAppointment(Resource):

    @user_token_required
    def get(self, user_id):
        try:
            appointments = Appointment.query.filter_by(userId=user_id).all()
            serialized_appointments = [appointment.to_dict() for appointment in appointments]
        
            response = jsonify({"success":True, "appointments": serialized_appointments})

            return make_response(response, 200)

        except Exception as e:
            print(f"Error getting appointment: {str(e)}")  # For debugging
            response = jsonify({
                "success": False, 
                "message": f"An error occurred: {str(e)}"
            })
            return make_response(response, 500)

api.add_resource(UserAppointment, '/user/list-appointments')

#API to cancel appointment
class CancelAppointment(Resource):
    @user_token_required
    def post(self, user_id):
        try:
            # Get data from request
            data = request.get_json()
            appointmentId = data.get('appointmentId')
            
            if not appointmentId:
                return make_response(jsonify({
                    "success": False,
                    "message": "Appointment ID is required"
                }), 400)
            
            # Find the appointment
            appointment = Appointment.query.get(appointmentId)
            
            if not appointment:
                return make_response(jsonify({
                    "success": False,
                    "message": "Appointment not found"
                }), 404)
            
            # Check if user owns this appointment
            if appointment.userId != user_id:
                return make_response(jsonify({
                    "success": False,
                    "message": "Unauthorized to cancel this appointment"
                }), 403)
            
            # Cancel the appointment
            appointment.cancelled = True
            
            # If you're also managing doctor's slots, remove the slot from booked slots
            try:
                doctor = Doctor.query.get(appointment.docId)
                if doctor and doctor.slots_booked:
                    slots_booked = doctor.slots_booked
                    if appointment.slotDate in slots_booked:
                        slots_booked[appointment.slotDate] = [
                            slot for slot in slots_booked[appointment.slotDate] 
                            if slot != appointment.slotTime
                        ]
                        flag_modified(doctor, 'slots_booked')
            except Exception as e:
                print(f"Error updating doctor slots: {str(e)}")
            print(doctor.slots_booked)
            # Save changes
            db.session.commit()
            print(doctor.slots_booked)
            
            return make_response(jsonify({
                "success": True,
                "message": "Appointment cancelled successfully"
            }), 200)
            
        except Exception as e:
            db.session.rollback()
            print(f"Error cancelling appointment: {str(e)}")
            return make_response(jsonify({
                "success": False,
                "message": "Error cancelling appointment"
            }), 500)

# Register the resource
api.add_resource(CancelAppointment, '/cancel-appointment')


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


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class MpesaAPI:
    def __init__(self):
        # Core MPESA credentials
        self.business_shortcode = os.getenv('MPESA_BUSINESS_SHORTCODE')
        self.consumer_key = os.getenv('MPESA_CONSUMER_KEY')
        self.consumer_secret = os.getenv('MPESA_CONSUMER_SECRET')
        self.passkey = os.getenv('MPESA_PASSKEY')

        # API endpoints
        self.auth_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        self.stk_push_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        
        # Validate configuration
        self._validate_config()
        
        logger.info("MPESA API initialized successfully")

    def _validate_config(self):
        """Validate all required configuration is present"""
        required_configs = [
            'MPESA_BUSINESS_SHORTCODE',
            'MPESA_CONSUMER_KEY',
            'MPESA_CONSUMER_SECRET',
            'MPESA_PASSKEY',
        ]
        
        missing_configs = [config for config in required_configs 
                         if not os.getenv(config)]
        
        if missing_configs:
            raise ValueError(f"Missing required configurations: {', '.join(missing_configs)}")

    def get_access_token(self):
        """Get OAuth access token from Safaricom"""
        try:
            auth_string = base64.b64encode(
                f"{self.consumer_key}:{self.consumer_secret}".encode()
            ).decode()
            
            headers = {"Authorization": f"Basic {auth_string}"}
            
            response = requests.get(self.auth_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            logger.debug("Successfully retrieved access token")
            
            return token_data["access_token"]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get access token: {str(e)}")
            raise Exception("Failed to get access token from Safaricom")

    def generate_password(self):
        """Generate password for STK push"""
        timestamp = datetime.datetime.now(pytz.timezone('Africa/Nairobi')).strftime('%Y%m%d%H%M%S')
        password_str = f"{self.business_shortcode}{self.passkey}{timestamp}"
        return base64.b64encode(password_str.encode()).decode(), timestamp

    def initiate_stk_push(self, phone_number, amount, reference):
        """
        Initiate STK push payment
        
        Args:
            phone_number (str): Customer phone number
            amount (float): Amount to charge
            reference (str): Unique reference for the transaction
            
        Returns:
            dict: Response from MPESA API
        """
        try:
            # Format phone number
            if phone_number.startswith('+'):
                phone_number = phone_number[1:]
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
                
            # Get credentials
            access_token = self.get_access_token()
            password, timestamp = self.generate_password()
            
            
            # Prepare request
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "BusinessShortCode": self.business_shortcode,
                "Password": password,
                "Timestamp": timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": int(float(amount)),  # Convert Numeric to int
                "PartyA": phone_number,
                "PartyB": self.business_shortcode,
                "PhoneNumber": phone_number,
                "CallBackURL": "https://6d66-154-159-238-160.ngrok-free.app/mpesa-callback",
                "AccountReference": reference,
                "TransactionDesc": f"Payment for Appointment {reference}"
            }
            
            logger.debug(f"Initiating STK push with {payload}")
            
            # Make request
            response = requests.post(
                self.stk_push_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"STK push initiated successfully: {result}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to initiate STK push: {str(e)}")
            raise Exception("Failed to initiate payment with Safaricom")
        except Exception as e:
            logger.error(f"Unexpected error during STK push: {str(e)}")
            raise

class InitiatePayment(Resource):
    @user_token_required
    def post(self, user_id):
        """
        Initiate a new MPESA payment
        
        Expected payload:
        {
            "phone": "254712345678",
            "appointment_id": "123"
        }
        """
        try:
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['phone', 'appointment_id']
            missing_fields = [field for field in required_fields 
                            if field not in data]
            
            if missing_fields:
                return {
                    "success": False,
                    "message": f"Missing required fields: {', '.join(missing_fields)}"
                }, 400
            
            # Get appointment and validate
            appointment = Appointment.query.get(data['appointment_id'])
            if not appointment:
                return {
                    "success": False,
                    "message": "Appointment not found"
                }, 404
                
            if appointment.payment:
                return {
                    "success": False,
                    "message": "Appointment has already been paid"
                }, 400
                
            if appointment.cancelled:
                return {
                    "success": False,
                    "message": "Cannot pay for cancelled appointment"
                }, 400
            
            if appointment.checkout_request_id:
                old_id = appointment.checkout_request_id
                appointment.checkout_request_id = None
                db.session.commit()
            
            # Initialize payment
            mpesa = MpesaAPI()
            result = mpesa.initiate_stk_push(
                phone_number=data['phone'],
                amount=float(appointment.amount),  # Use amount from appointment
                reference=str(appointment.id)
            )
            
            # Store checkout request ID
            appointment.checkout_request_id = result.get('CheckoutRequestID')
            db.session.commit()
            
            return {
                "success": True,
                "message": "Payment initiated successfully",
                "data": result
            }, 200
            
        except Exception as e:
            logger.error(f"Payment initiation error: {str(e)}")
            db.session.rollback()
            response = jsonify({
                "success": False,
                "message": "Enter a valid Safaricom phone number."
            })
            return make_response(response, 200)

class MpesaCallback(Resource):
    def post(self):
        """Handle MPESA payment callbacks"""
        try:
            callback_data = request.get_json()
            logger.info(f"Received MPESA callback: {callback_data}")
            
            # Extract callback data
            body = callback_data.get('Body', {}).get('stkCallback', {})
            checkout_request_id = body.get('CheckoutRequestID')
            result_code = body.get('ResultCode')
            
            if not checkout_request_id:
                logger.error("Missing CheckoutRequestID in callback")
                return {"success": False, "message": "Invalid callback data"}, 400
            
            # Find appointment
            appointment = Appointment.query.filter_by(
                checkout_request_id=checkout_request_id
            ).first()
            
            if not appointment:
                logger.error(f"No appointment found for checkout ID: {checkout_request_id}")
                return {"success": False, "message": "Appointment not found"}, 404

            # Process payment result
            if result_code == 0:  # Success
                # Extract payment details
                items = body.get('CallbackMetadata', {}).get('Item', [])
                receipt_number = next(
                    (item['Value'] for item in items if item['Name'] == 'MpesaReceiptNumber'),
                    None
                )
                
                # Update appointment
                appointment.payment = True
                appointment.transaction_id = receipt_number
                appointment.payment_details = callback_data
                appointment.checkout_request_id = None  # Clear for retry if needed
                
                logger.info(f"Payment successful for appointment {appointment.id}")
                
            else:  # Failed
                # Update appointment for retry
                appointment.payment = False
                appointment.payment_details = callback_data
                appointment.checkout_request_id = None  # Clear for retry

                response = jsonify({"success":False, "message":"Payment Unsuccessfull"})
                logger.warning(f"Payment failed for appointment {appointment.id}")

                return make_response(response, 200)
            
            db.session.commit()
            
            response = jsonify( {
                "success": True,
                "message": "Callback processed successfully"
            }),
            return make_response(response, 200)
            
        except Exception as e:
            logger.error(f"Callback processing error: {str(e)}")
            db.session.rollback()
            return {
                "success": False,
                "message": f"Callback processing failed: {str(e)}"
            }, 500

# Add routes
api.add_resource(InitiatePayment, '/initiate-payment')
api.add_resource(MpesaCallback, '/mpesa-callback')


#ADMIN API ENDPOINTS

#Admin appointment list
class AppointmentsAdmin(Resource):
    @token_required
    def get():
        try:
            appointments = Appointment.query.all()
            
            appointment_list = [appointment.to_dict() for appointment in appointments]

            response = jsonify({
                "success": True,
                "appointments": appointment_list
            })
            return make_response(response, 200)

        except Exception as e:
            
            response = jsonify({
                "success": False,
                "message": f"{str(e)}"
            })

            return make_response(response, 200)
        
api.add_resource(AppointmentsAdmin, '/admin-appointments')
        

if __name__ == '__main__':
    app.run(port=5555, debug=True)
