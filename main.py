from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
import uuid
from datetime import datetime
import os

# Initialize the Flask app and configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)  # Cryptographically secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class Voter(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_eligible = db.Column(db.Boolean, default=True)
    has_voted = db.Column(db.Boolean, default=False)

class Party(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    party_id = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    candidate_name = db.Column(db.String(100), nullable=False)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(36), nullable=False)
    party_id = db.Column(db.String(36), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    encrypted_vote = db.Column(db.String, nullable=True)
    vote_proof = db.Column(db.String, nullable=True)
# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email',
                        render_kw={"placeholder": "Enter your email"})
    password = PasswordField('Password',
                              render_kw={"placeholder": "Enter your password"})
    submit = SubmitField('Login')

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Voter.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler"""
    form = LoginForm()
    if form.validate_on_submit():
        voter = Voter.query.filter_by(email=form.email.data).first()
        
        if not voter or not check_password_hash(voter.password_hash, form.password.data):
            flash('Invalid email or password', 'error')
            return render_template('login.html', form=form)
        
        if not voter.is_eligible:
            flash('You are not eligible to vote', 'error')
            return render_template('login.html', form=form)
        
        if voter.has_voted:
            flash('You have already cast your vote', 'error')
            return render_template('login.html', form=form)
        
        login_user(voter)
        flash('Login successful', 'success')
        return redirect(url_for('vote'))
    
    return render_template('login.html', form=form)

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    """Voting page"""
    if current_user.has_voted:
        flash('You have already cast your vote', 'error')
        return redirect(url_for('results'))
    
    parties = Party.query.all()
    
    if request.method == 'POST':
        party_id = request.form.get('party_id')
        
        party = Party.query.filter_by(party_id=party_id).first()
        if not party:
            flash('Invalid party selected', 'error')
            return redirect(url_for('vote'))
        
        try:
            vote = Vote(voter_id=current_user.voter_id, party_id=party_id)
            current_user.has_voted = True
            
            db.session.add(vote)
            db.session.commit()
            
            flash('Vote cast successfully', 'success')
            return redirect(url_for('results'))
        except Exception as e:
            db.session.rollback()
            flash('Vote recording failed: {}'.format(e), 'error')
            return redirect(url_for('vote'))
    
    return render_template('vote.html', parties=parties)

@app.route('/results')
def results():
    """Election results page"""
    results = db.session.query(
        Party.name, 
        Party.candidate_name,
        db.func.count(Vote.id).label('vote_count')
    ).join(Vote, Party.party_id == Vote.party_id)\
     .group_by(Party.name, Party.candidate_name)\
     .order_by(db.func.count(Vote.id).desc())\
     .all()
    
    return render_template('results.html', results=results)

@app.route('/logout')
@login_required
def logout():
    """Logout route"""
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# Database Initialization
def init_database():
    """Initialize the database with predefined data"""
    with app.app_context():
        db.create_all()

        if not Party.query.first():
            parties = [
                Party(
                    party_id=str(uuid.uuid4()), 
                    name="Labor Party", 
                    description="Progressive labor-focused party",
                    candidate_name="Sarah Johnson"
                ),
                Party(
                    party_id=str(uuid.uuid4()), 
                    name="Conservative Party", 
                    description="Traditional conservative platform",
                    candidate_name="Michael Roberts"
                ),
                Party(
                    party_id=str(uuid.uuid4()), 
                    name="Green Party", 
                    description="Environmentally focused party",
                    candidate_name="Emily Chen"
                )
            ]
            db.session.bulk_save_objects(parties)

        if not Voter.query.first():
            voters = [
                Voter(
                    voter_id=str(uuid.uuid4()),
                    name="John Doe", 
                    email="john.doe@example.com",
                    password_hash=generate_password_hash("Voter@123"),
                    is_eligible=True
                ),
                Voter(
                    voter_id=str(uuid.uuid4()),
                    name="Emma Smith", 
                    email="emma.smith@example.com",
                    password_hash=generate_password_hash("Secure@456"),
                    is_eligible=True
                )
            ]
            db.session.bulk_save_objects(voters)

        db.session.commit()

# Main Execution
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_database()
    
    app.run(debug=False, host='0.0.0.0', port=3000)


