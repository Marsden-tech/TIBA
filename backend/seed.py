from app import app
from models import db, User, Appointment
import bcrypt


with app.app_context():

    Appointment.query.delete()
    db.session.commit()

print('Dont mess!!')
