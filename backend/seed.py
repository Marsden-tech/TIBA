from app import app
from models import db, Doctor, Doc_address
import bcrypt


with app.app_context():

    Doctor.query.delete()
    Doc_address.query.delete()
    db.session.commit()
