#import
from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap

#define app
app = Flask(__name__)

#add app
bootstrap = Bootstrap(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

#add configuraton
app.config['SECRET_KEY'] = 'mysecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Shreya%40412@localhost:3307/database1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#user table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    tasks = db.relationship('Task', backref='user')

#task table
class Task(db.Model):
    idtask = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    taskname = db.Column(db.String(50), nullable=False)
    desc = db.Column(db.String(200), nullable=False)
    finished = db.Column(db.Boolean, default=False)
    
#load user    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#signup form
class SignupForm(FlaskForm):

    email = EmailField('email', validators=[InputRequired(), Length(min=6, max=50), Email(message="Invalid Email")], render_kw={"placeholder": "Email"})

    username = StringField('username',validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=12),
    Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,12}$', flags=0, message="Enter password with Uppercase and special character and number"), 
    EqualTo('confirmpass', message='Passwords must match')], render_kw={"placeholder": "Password"})

    confirmpass = PasswordField('confirmpass',validators=[InputRequired(), Length(min=8, max=12)], render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField('Sign Up')

    #validate username
    def validate_username(self, username):

        #check if username is already taken
        user = User()
        existing_user_username = user.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('Username already exists Choose a different one')

#login form
class LoginForm(FlaskForm):

    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#task form
class TaskForm(FlaskForm):

    taskname = StringField('title', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Title"})

    desc = TextAreaField('desc', validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Description"})

    submit = SubmitField('Add Task')

#update form
class UpdateForm(FlaskForm):

    taskname = StringField('title', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Title"})

    desc = TextAreaField('desc', validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Description"})

    finished = BooleanField('finished')

    submit = SubmitField('Update Task')

#define routes

#home route
@app.route('/')
def home():
    return render_template('home.html')

#login route
@app.route('/login', methods=['GET', 'POST'])
def login():

    #loginform
    form = LoginForm()

    msg="Invalid Username or Password"

    #if form is submitted
    if form.validate_on_submit():

        #get username 
        user = User.query.filter_by(username=form.username.data).first()
        
        #if user exists
        if user:

            #check password
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for('dashboard'))

        return render_template('login.html', form=form, msg=msg)

    return render_template('login.html', form=form)

#signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    
    #signup form
    form = SignupForm()

    #if method is post
    if request.method == 'POST':

        #if form is submitted
        if form.validate_on_submit():

            #encrypt password
            hashed_password = bcrypt.generate_password_hash(form.password.data)

            #create user
            new_user = User(email=form.email.data, username=form.username.data, password=hashed_password)

            #add user to database
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login')) 

        #if form is not submitted
        else: 
            msg="Enter Correct Details"
            return render_template('signup.html', form=form, msg=msg)

    return render_template('signup.html', form=form)

#dashboard route
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():

    #get user
    user = User.query.filter_by(username=current_user.username).first()
    #get tasks
    taskname = Task.query.filter_by(id=user.id).all()

    return render_template('dashboard.html', user=user, taskname=taskname)

#add task route
@app.route('/addtask', methods=['GET', 'POST'])
@login_required
def addtask():

    #task form
    form = TaskForm()

    #if form is submitted
    if form.validate_on_submit():

        #create task
        new_task = Task(taskname=form.taskname.data, desc=form.desc.data, id=current_user.id)

        #add task to database
        db.session.add(new_task)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('add.html', form=form)

#update task route as per idtask
@app.route('/update/<int:idtask>', methods=['GET', 'POST'])
@login_required
def update(idtask):

    #get task
    task = Task.query.filter_by(idtask=idtask).first()

    #update form
    form = UpdateForm()

    #if form is submitted
    if form.validate_on_submit():

        #update task
        task.taskname = form.taskname.data
        task.desc = form.desc.data
        task.finished = form.finished.data

        #add new task to database
        db.session.add(task)
        db.session.commit()

        return redirect(url_for('dashboard'))

    #if form is not submitted
    form.taskname.data = task.taskname
    form.desc.data = task.desc
    form.finished.data = task.finished

    return render_template('update.html', form=form, task=task)

#delete task route as per idtask
@app.route('/delete/<int:idtask>', methods=['GET', 'POST'])
@login_required
def delete(idtask):

    #get task
    task = Task.query.get(idtask)

    #delete task
    db.session.delete(task)
    db.session.commit()

    return redirect(url_for('dashboard'))

#logout route
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():

    #logout user
    logout_user()
    return redirect(url_for('home'))

#run app
if __name__ == "__main__":
    app.run(debug=True)