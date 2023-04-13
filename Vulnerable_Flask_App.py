from flask import Flask,jsonify,render_template_string,request,Response,render_template
import subprocess
from werkzeug.datastructures import Headers
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER']="./vul_upload"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000

@app.route("/")
def main_page():
    return "REST API"

# SQL Injection
@app.route("/user/<string:name>")
def search_user(name):
    # Establish a connection to the SQLite database
    con = sqlite3.connect("login.db")

    # Create a cursor object to execute SQL queries
    cur = con.cursor()

    # Execute a SELECT query to retrieve data based on the provided username
    # Note that this is vulnerable to SQL injection attacks
    cur.execute("select * from users where username = '%s'" % name)

    # Fetch all the rows returned by the query and convert to a string
    data = str(cur.fetchall())

    # Close the database connection
    con.close()

    # Set up logging to write the results of the query to a file
    import logging
    logging.basicConfig(filename="restapi.log", filemode='w', level=logging.DEBUG)
    logging.debug(data)

    # Return the results of the query as a JSON object with a 200 status code
    return jsonify(data=data),200


# XSS/HTML Injection
@app.route("/welcome/<string:name>")
def welcome(name):
    data="Welcome "+name
    return jsonify(data=data),200

# SSTI
@app.route("/welcome2/<string:name>")
def welcome2(name):
    data="Welcome "+name
    return data

@app.route("/hello")
def hello_ssti():
    if request.args.get('name'):
        name = request.args.get('name')
        template = f'''<div>
        <h1>Hello</h1>
        {name}
</div>
'''
        import logging
        logging.basicConfig(filename="restapi.log", filemode='w', level=logging.DEBUG)
        logging.debug(str(template))
        return render_template_string(template)

# OS Command Injection
@app.route("/get_users")
def get_users():
    try:
        hostname = request.args.get('hostname')
        command = "dig " + hostname
        data = subprocess.check_output(command, shell=True)
        return data
    except:
        data = str(hostname) + " username didn't found"
        return data

# Information Disclosure
@app.route("/get_log/")
def get_log():
    try:
        command="cat restapi.log"
        data=subprocess.check_output(command,shell=True)
        return data
    except:
        return jsonify(data="Command didn't run"), 200

# Local File Inclusion
@app.route("/read_file")
def read_file():
    filename = request.args.get('filename')
    file = open(filename, "r")
    data = file.read()
    file.close()
    import logging
    logging.basicConfig(filename="restapi.log", filemode='w', level=logging.DEBUG)
    logging.debug(str(data))
    return jsonify(data=data),200

# Deserilization
@app.route("/deserialization/")
def deserialization():
    try:
        import socket, pickle
        HOST = "0.0.0.0"
        PORT = 8001
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            connection, address = s.accept()
            with connection:
                received_data = connection.recv(1024)
                data=pickle.loads(received_data)
                return str(data)
    except:
        return jsonify(data="You must connect 8001 port"), 200

# Infomation Disclosure
@app.route("/get_admin_mail/<string:control>")
def get_admin_mail(control):
    if control=="admin":
        data="admin@cybersecurity.intra"
        import logging
        logging.basicConfig(filename="restapi.log", filemode='w', level=logging.DEBUG)
        logging.debug(data)
        return jsonify(data=data),200
    else:
        return jsonify(data="Control didn't set admin"), 200

# File Upload and Download Vulnerability
@app.route("/run_file")
def run_file():
    try:
        filename=request.args.get("filename")
        command="/bin/bash "+filename
        data=subprocess.check_output(command,shell=True)
        return data
    except:
        return jsonify(data="File failed to run"), 200

# File Upload and Download Vulnerability
@app.route("/create_file")
def create_file():
    try:
        filename=request.args.get("filename")
        text=request.args.get("text")
        file=open(filename,"w")
        file.write(text)
        file.close()
        return jsonify(data="File created"), 200
    except:
        return jsonify(data="File didn't create"), 200


connection = {}
max_con = 50

def factorial(number):
    if number == 1:
        return 1
    else:
        return number * factorial(number - 1)


@app.route('/factorial/<int:n>')
def factroial(n:int):
    if request.remote_addr in connection:
        if connection[request.remote_addr] > 2:
            return jsonify(data="Too many req."), 403
        connection[request.remote_addr] += 1
    else:
        connection[request.remote_addr] = 1
    result=factorial(n)
    if connection[request.remote_addr] == 1:
        del connection[request.remote_addr]
    else:
        connection[request.remote_addr] -= 1
    return jsonify(data=result), 200

# Hardcoded Password
# This function handles the login request
@app.route('/login',methods=["GET"])
def login():
    # Get the username and password from the request parameters
    username=request.args.get("username")
    passwd=request.args.get("password")
    # Check if the username and password are valid
    # In this example, the password is hardcoded, which is a security vulnerability
    if "admin" in username and "qwerty" in passwd:
        # If the username and password are valid, return a successful login message with HTTP status code 200
        return jsonify(data="Login successful"), 200
    else:
        # If the username and password are invalid, return an unsuccessful login message with HTTP status code 403
        return jsonify(data="Login unsuccessful"), 403


@app.route('/route')
def route():
    content_type = request.args.get("Content-Type")
    response = Response()
    headers = Headers()
    headers.add("Content-Type", content_type)
    response.headers = headers
    return response

# Improper Output Neutralization for Logs
@app.route('/logs')
def ImproperOutputNeutralizationforLogs():
    data = request.args.get('data')
    import logging
    logging.basicConfig(filename="restapi.log", filemode='w', level=logging.DEBUG)
    logging.debug(data)
    return jsonify(data="Logging ok"), 200

# Denial of Service
@app.route("/user_pass_control")
def user_pass_control():
    import re
    username=request.form.get("username")
    password=request.form.get("password")
    if re.search(username,password):
        return jsonify(data="Password include username"), 200
    else:
        return jsonify(data="Password doesn't include username"), 200

# Unrestricted File Upload Vulnerability
# Define route for file upload
@app.route('/upload', methods = ['GET','POST'])
def uploadfile():
    # Check if the request method is POST
    if request.method == 'POST':
        # Get the uploaded file from the request object
        f = request.files['file']
        # Get a secure filename for the uploaded file
        filename=secure_filename(f.filename)
        # Save the uploaded file in the upload folder
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # Return a success message
        return 'File uploaded successfully'
    else:
        # If the request method is not POST, show a file upload form
        return '''
<html>
    <body>
    <form  method = "POST"  enctype = "multipart/form-data">
        <input type = "file" name = "file" />
        <input type = "submit"/>
    </form>   
</body>
</html>
'''


if __name__ == '__main__':
    app.run(host="0.0.0.0",port=8081)
