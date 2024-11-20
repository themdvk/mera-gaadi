from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from functools import wraps
import hashlib
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')  # Change this in production

# Initialize Supabase client
try:
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')
    
    if not supabase_url or not supabase_key:
        raise ValueError("Supabase URL or Key not found in environment variables")
    
    print(f"Initializing Supabase client with URL: {supabase_url}")
    supabase: Client = create_client(supabase_url, supabase_key)
    print("Supabase client initialized successfully")
except Exception as e:
    print(f"Error initializing Supabase client: {str(e)}")
    raise

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            # Hash the provided password
            hashed_password = hash_password(password)
            
            # Check user credentials
            user_query = supabase.table('users').select("*").eq('email', email).eq('password', hashed_password).execute()
            
            if user_query.data:
                user = user_query.data[0]
                # Set session
                session['user'] = {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name']
                }
                flash('Successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'error')
                return render_template('login.html')
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        
        print(f"Signup attempt - Email: {email}, Name: {name}")
        
        try:
            # Check if user already exists
            print("Checking for existing user...")
            existing_user = supabase.table('users').select("*").eq('email', email).execute()
            print(f"Existing user check result: {existing_user.data}")
            
            if existing_user.data:
                print(f"User already exists with email: {email}")
                flash('Email already registered. Please login.', 'error')
                return render_template('signup.html')
            
            # Hash the password
            print("Hashing password...")
            hashed_password = hash_password(password)
            print("Password hashed successfully")
            
            # Create new user
            print("Preparing user data...")
            
            # Generate a UUID for the user
            user_id = str(uuid.uuid4())
            
            user_data = {
                "id": user_id,  # Explicitly set the UUID
                "email": email,
                "password": hashed_password,
                "name": name
            }
            print(f"User data prepared: {user_data}")
            
            # Insert into users table with RLS bypass
            print("Attempting to insert user into database...")
            response = supabase.table('users').insert(user_data).execute()
            print(f"Database response: {response}")
            
            if response.data:
                user = response.data[0]
                print(f"User created successfully with ID: {user['id']}")
                
                # Set session
                session['user'] = {
                    'id': user['id'],
                    'email': email,
                    'name': name
                }
                print(f"Session set: {session['user']}")
                
                flash('Successfully signed up! Welcome!', 'success')
                return redirect(url_for('dashboard'))
            else:
                print("No data returned from database insert")
                flash('Error creating account. Please try again.', 'error')
                return render_template('signup.html')
                
        except Exception as e:
            print(f"Signup error (detailed):")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {str(e)}")
            if hasattr(e, 'code'):
                print(f"Error code: {e.code}")
            if hasattr(e, 'response'):
                print(f"Error response: {e.response}")
            flash('Error during signup. Please try again.', 'error')
            return render_template('signup.html')
            
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return redirect(url_for('login'))
            
        cars = supabase.table('cars').select("*").eq('user_id', user_id).execute()
        return render_template('dashboard.html', cars=cars.data)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/car/new', methods=['GET', 'POST'])
@login_required
def new_car():
    if request.method == 'POST':
        try:
            user = session.get('user', {})
            user_id = user.get('id')
            
            if not user_id:
                flash('Please log in again.', 'error')
                return redirect(url_for('login'))

            # Verify user exists in database
            user_exists = supabase.table('users').select("*").eq('id', user_id).execute()
            if not user_exists.data:
                flash('User profile not found. Please log out and sign in again.', 'error')
                return redirect(url_for('login'))

            name = request.form['name']
            price = request.form['price']
            image_url = request.form['image_url']
            
            car_data = {
                "name": name,
                "price": price,
                "image_url": image_url,
                "user_id": user_id
            }
            
            print(f"Attempting to create car with data: {car_data}")  # Debug print
            result = supabase.table('cars').insert(car_data).execute()
            print(f"Car creation result: {result}")  # Debug print
            
            flash('Car added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Error creating car: {str(e)}")  # Debug print
            flash(f'Error adding car: {str(e)}', 'error')
            return render_template('new_car.html')
            
    return render_template('new_car.html')

@app.route('/car/<car_id>')
@login_required
def view_car(car_id):
    try:
        user = session.get('user', {})
        user_id = user.get('id')
        
        if not user_id:
            flash('Please log in again.', 'error')
            return redirect(url_for('login'))
            
        car = supabase.table('cars').select("*").eq('id', car_id).single().execute()
        
        if not car.data:
            flash('Car not found.', 'error')
            return redirect(url_for('dashboard'))
            
        if car.data['user_id'] != user_id:
            flash('You do not have permission to view this car.', 'error')
            return redirect(url_for('dashboard'))
            
        return render_template('view_car.html', car=car.data)
    except Exception as e:
        print(f"Error viewing car: {str(e)}")
        flash('Error loading car details.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/car/<car_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_car(car_id):
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        image_url = request.form['image_url']
        
        supabase.table('cars').update({
            "name": name,
            "price": price,
            "image_url": image_url
        }).eq('id', car_id).execute()
        
        return redirect(url_for('dashboard'))
    
    car = supabase.table('cars').select("*").eq('id', car_id).single().execute()
    return render_template('edit_car.html', car=car.data)

@app.route('/car/<car_id>/delete', methods=['POST'])
@login_required
def delete_car(car_id):
    supabase.table('cars').delete().eq('id', car_id).execute()
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
