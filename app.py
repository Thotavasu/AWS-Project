from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
import pymysql
from werkzeug.utils import secure_filename
import bcrypt
from dotenv import load_dotenv
import os

# Load environment variables from the .env file
load_dotenv()


app = Flask(__name__)
app.secret_key = 'your_secret_key'


db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

# Configurations for file uploads
UPLOAD_FOLDER = os.path.join('static', 'uploads')  # Folder to save uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to get a database connection
def get_db_connection():
    try:
        connection = pymysql.connect(**db_config)
        print("Connected to the database")
        return connection
    except pymysql.MySQLError as e:
        print(f"Database connection failed: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

# User Login
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT id, password FROM users WHERE email = %s", (email,))
                result = cursor.fetchone()

                if result and bcrypt.checkpw(password, result[1].encode('utf-8')):
                    session['user_id'] = result[0]  # Store user ID in session
                    # flash('User login successful!', 'success')
                    return redirect(url_for('user'))
                else:
                    flash('Invalid credentials. Please try again.', 'error')
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error. Please try again later.', 'error')

    return render_template('user_login.html')

# User Signup
@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
                connection.commit()
                flash('User account created successfully!', 'success')
                return redirect(url_for('user_login'))
            except pymysql.MySQLError as e:
                flash('Error creating account. Email may already exist.', 'error')
                print(f"Error: {e}")
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error. Please try again later.', 'error')

    return render_template('user_signup.html')

# Agent Login
# Agent Login
@app.route('/agent/login', methods=['GET', 'POST'])
def agent_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT id, password FROM agents WHERE email = %s", (email,))
                result = cursor.fetchone()

                if result and bcrypt.checkpw(password, result[1].encode('utf-8')):
                    session['agent'] = result[0]  # Store agent ID in session
                    flash('Agent login successful!', 'success')
                    return redirect(url_for('agent_dashboard'))
                else:
                    flash('Invalid credentials. Please try again.', 'error')
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error. Please try again later.', 'error')

    return render_template('agent_login.html')


# Agent Signup
@app.route('/agent/signup', methods=['GET', 'POST'])
def agent_signup():
    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("INSERT INTO agents (name, role, email, password) VALUES (%s, %s, %s, %s)", (name, role, email, hashed_password))
                connection.commit()
                flash('Agent account created successfully!', 'success')
                return redirect(url_for('agent_login'))
            except pymysql.MySQLError as e:
                flash('Error creating account. Email may already exist.', 'error')
                print(f"Error: {e}")
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error. Please try again later.', 'error')

    return render_template('index.html')

# Admin Login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT password FROM admins WHERE email = %s", (email,))
                result = cursor.fetchone()

                if result and bcrypt.checkpw(password, result[0].encode('utf-8')):
                    session['admin'] = email  # Store admin email in session
                    flash('Admin login successful!', 'success')
                    return redirect(url_for('admin_dashboard'))  # Change 'index' to your desired route after login
                else:
                    flash('Invalid credentials. Please try again.', 'error')
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error. Please try again later.', 'error')

    return render_template('admin_login.html')

# Admin Signup
@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("INSERT INTO admins (name, email, password) VALUES (%s, %s, %s)", 
                               (name, email, hashed_password))
                connection.commit()
                flash('Admin account created successfully!', 'success')
                return redirect(url_for('admin_login'))  # Redirect to admin login after signup
            except pymysql.MySQLError as e:
                flash('Error creating account. Email may already exist.', 'error')
                print(f"Error: {e}")
            finally:
                cursor.close()
                connection.close()
        else:
            flash('Database connection error. Please try again later.', 'error')

    return render_template('index.html')  # Create this template for admin signup


@app.route('/assign-agent', methods=['POST'])
def assign_agent():
    data = request.get_json()
    user_id = data.get('userId')
    agent_name = data.get('agentName')

    # Here you would update your database or data structure with the assignment
    print(f"Assigned {agent_name} to user ID: {user_id}")
    
    return jsonify({"success": True})

# @app.route('/toggle-agent-status', methods=['POST'])
# def toggle_agent_status():
#     data = request.get_json()
#     agent_id = data.get('agentId')
#     new_status = data.get('newStatus')

#     # Here you would update your database or data structure with the new status
#     print(f"Toggled agent ID: {agent_id} to status: {new_status}")
    
#     return jsonify({"success": True})


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:  # Check if admin is logged in
        flash('You need to log in to access this page.', 'error')
        return redirect(url_for('admin_login'))

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT u.name AS user_name, c.issue_type, c.image_path 
            FROM users u 
            JOIN user_complaints c ON u.id = c.user_id;
        """)
        users = cursor.fetchall()
        print("Admin Dashboard",users)
        
        # Fetch agent names
        cursor.execute("SELECT name FROM agents;")
        agents = cursor.fetchall()
        print(agents)
        
        cursor.close()
        connection.close()
    else:
        users = []
        agents = []
    
    return render_template('admin_dashboard.html', users=users, agents=agents)

@app.route('/agent_dashboard')
def agent_dashboard():
    if 'agent' not in session:  # Check if agent is logged in
        flash('You need to log in to access this page.', 'error')
        return redirect(url_for('agent_login'))

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute(""" 
            SELECT u.name AS user_name, c.issue_type, c.image_path 
            FROM users u 
            JOIN user_complaints c ON u.id = c.user_id; 
        """)
        ag_dash = cursor.fetchall()
        print("Agent Dashboard",ag_dash)

        cursor.close()
        connection.close()
    else:
        ag_dash = []
    
    return render_template('agent_dashboard.html', ag_dash=ag_dash)




@app.route('/user', methods=['GET', 'POST'])
def user():
    if 'user_id' not in session:  # Check if user is logged in
        flash('You need to log in to access this page.', 'error')
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        # Handle file upload
        if 'image' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['image']
        
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Get other form data
            title = request.form.get('title')
            description = request.form.get('description')
            address = request.form.get('address')
            lat = request.form.get('lat')
            lon = request.form.get('lon')

            # Retrieve the user_id from session
            user_id = session.get('user_id')

            # Save the details in the database
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor()
                try:
                    cursor.execute("""
                        INSERT INTO user_complaints (issue_type, image_path, description, address, latitude, longitude, user_id) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s)""", 
                        (title, file_path, description, address, lat, lon, user_id))  # Include user_id here
                    connection.commit()
                    flash(f'Thanks for the {title} update!', 'success')  # Flash message with title
                except pymysql.MySQLError as e:
                    flash('Error submitting complaint. Please try again.', 'error')
                    print(f"Error: {e}")
                finally:
                    cursor.close()
                    connection.close()
            else:
                flash('Database connection error. Please try again later.', 'error')

            return redirect(url_for('index'))  # Redirect to the index page

        else:
            flash('Invalid file format. Please upload a valid image.', 'error')
            return redirect(request.url)  # Return to the same page on file upload error

    return render_template('user.html')




@app.route('/viewcomplaints', methods=['GET', 'POST'])
def viewcomplaints():
    if 'user_id' not in session:  # Check if user is logged in
        flash('You need to log in to access this page.', 'error')
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    
    user_id = session.get('user_id')  # Fetch the logged-in user's ID

    connection = get_db_connection()  # Establish DB connection
    if connection:
        cursor = connection.cursor()  # Use dictionary cursor for named access
        try:
            # SQL query to fetch complaints details
            query = """
                SELECT 
                    uc.complaint_id AS "Sr No", 
                    uc.image_path AS "Your Uploaded Image", 
                    'Image will be uploaded soon' AS "Image After Completion of work",
                    uc.issue_type AS "Title", 
                    uc.description AS "Description", 
                    IFNULL(a.name, 'Not Assigned') AS "Agent Name", 
                    st.status AS "Work Status", 
                    'Feedback Placeholder' AS "Feedback"
                FROM 
                    user_complaints uc
                LEFT JOIN 
                    status_track st ON uc.complaint_id = st.complaint_id
                LEFT JOIN 
                    agents a ON st.accepted_by = a.id
                WHERE 
                    uc.user_id = %s;  # Filter by the logged-in user's ID
            """

            cursor.execute(query, (user_id,))  # Execute the query with the user_id parameter
            rows = cursor.fetchall()  # Fetch all the rows
            cursor.close()  # Close the cursor
            connection.close()  # Close the connection
        except Exception as e:
            print(f"An error occurred: {e}")
            flash('An error occurred while fetching the complaints.', 'error')
            rows = []  # Fallback to empty rows if there's an error
    else:
        rows = []  # Fallback to empty rows if connection fails

    # Render the 'viewcomplaints.html' template and pass the fetched rows
    return render_template('viewcomplaints.html', rows=rows)


@app.route('/user/logout')
def user_logout():
    session.pop('user_id', None)  # Clear the user ID from the session
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/agent/logout')
def agent_logout():
    session.pop('agent_id', None)  # Clear the agent ID from the session
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)  # Clear the admin session
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
