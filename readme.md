# Vulnerable Flask App
This README file lists 3 types of vulnerabilities that have been identified in the application hosted at http://127.0.0.1:8081/ and the vulnerabilities are fixed in the application hosted at http://127.0.0.1:8082/. It also provides sample URLs that can be used to test these vulnerabilities in both applications.

## Disclaimer
This application is for educational purposes only. Do not use this application to test or attack any system or network that you do not have explicit permission to do so. The authors of this application are not responsible for any damage or illegal activities caused by the use of this application.

## Installation
To run the vulnerable Flask app, follow these steps:

1. Clone the repository to your local machine.
    ```
    git clone https://github.com/J430N/ASC_Vulnerable_Flask_App.git
    ```

2. Navigate to the directory that contains the `Vulnerable_Flask_App.py` file.
    ```
    cd ASC_Vulnerable_Flask_App
    ```

3. Install the required dependencies by running the following command:
    ```
    pip install -r requirements.txt
    ```

4. Create a login database if it is not created
    ```
    python Create_Login_Db.py
    ```

5. Create a folder named "vul_upload" in the Vulnerable Flask App and a folder named "fix_upload" in the location /home/kali/Desktop:
    ```
    mkdir ./vul_upload
    ```
    ```
    mkdir /home/kali/Desktop/fix_upload
    ```
6. Run the app using the following command:

    **Vulnerable Flask Application**
    ```
    python Vulnerable_Flask_App.py
    ```
    **Fixed Flask Applicatrion**
    ```
    python Fixed_Flask_App.py
    ```

7. If the app runs successfully, you should see output similar to the following:

    **Vulnerable Flask Application**
    ```
    * Serving Flask app 'Vulnerable_Flask_App'
    * Debug mode: off
    WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
    * Running on all addresses (0.0.0.0)
    * Running on http://127.0.0.1:8081
    * Running on http://192.168.43.128:8081
    Press CTRL+C to quit
    ```
    **Fixed Flask Applicatrion**
    ```
    * Serving Flask app 'Fixed_Flask_App'
    * Debug mode: off
    WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
    * Running on all addresses (0.0.0.0)
    * Running on http://127.0.0.1:8082
    * Running on http://192.168.43.128:8082
    Press CTRL+C to quit
    ```

## Usage
--------
Once the app is running, you can open a web browser and navigate to http://127.0.0.1:8081/ and http://127.0.0.1:8082/ to access the Vulnerable Flask App and Fixed Flask App.

## IO Validation
-------------
### SQL Injection
A SQL injection vulnerability allows an attacker to execute arbitrary SQL queries on the database. The following URL can be used to test this vulnerability:

**Vulnerable Flask Application**
```
http://127.0.0.1:8081/user/' or 1=1 --'
```
**Fixed Flask Applicatrion**
```
http://127.0.0.1:8082/user/' or 1=1 --'
```

## Password Management
-------------------
### Hardcoded Password
A hardcoded password vulnerability refers to a situation where a password is hardcoded into the application's code or configuration files. The following URL can be used to test this vulnerability:

**Vulnerable Flask Application**
```
http://127.0.0.1:8081/login?username=admin&password=qwerty
```
**Fixed Flask Applicatrion**
```
http://127.0.0.1:8082/login?username=admin&password=qwerty
```


## File Uplaod and Download
-------------------------
### Unrestricted File Upload
An unrestricted file upload vulnerability refers to a situation where an attacker can upload arbitrary files to the server. The following URL can be used to test this vulnerability:

**Vulnerable Flask Application**
```
http://127.0.0.1:8081/upload
```
**Fixed Flask Applicatrion**
```
http://127.0.0.1:8082/upload
```