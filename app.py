from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask import Flask,render_template,flash,redirect, url_for,request
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from forms import RegistrationForm,LoginForm
from  flask_login import LoginManager, login_user, current_user, login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Email,EqualTo
import time

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(50), index=True, unique=True)
  email = db.Column(db.String(150), unique = True, index = True)
  password_hash = db.Column(db.String(150))
  joined_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)

  def set_password(self, password):
        self.password_hash = generate_password_hash(password)

  def check_password(self,password):
      return check_password_hash(self.password_hash,password)
  

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/register', methods = ['POST','GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username =form.username.data, email = form.email.data)
        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registration.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
            return redirect(next or url_for('home'))
        flash('Invalid email address or Password.')    
    return render_template('login.html', form=form)

@app.route("/forbidden",methods=['GET', 'POST'])
@login_required
def protected():
    return redirect(url_for('forbidden.html'))

@app.route("/logout")

def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()
