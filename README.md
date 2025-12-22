# SecureBank: A Full-Stack Banking Application

SecureBank is a production-ready, full-stack web application that simulates a modern, secure online banking portal. It is built with a strong emphasis on security best practices, including multi-factor authentication for all critical actions, and a full-featured admin panel for user management.


## Key Features

    ##User Features
        ->Secure Registration: New users must verify their account via an email One-Time Password (OTP).
        ->Two-Factor Authentication (2FA): All logins and fund transfers are protected by an emailbased OTP.
        ->Account Security: Accounts are automatically locked after 3 failed login attempts.
        ->Password Management: Users can securely reset forgotten passwords via an email link and change their password from their profile.
        ->Profile Management: Users can update their personal details, upload a profile picture, and set a 4-digit MPIN (which is securely hashed) for transfer authorization.
        ->Account Dashboard: View account balance, account number, and a list of recent transactions.
        ->Secure Transfers: Multi-step transfer process that verifies the recipient's name, requires the user's MPIN, and sends a final 2FA email OTP to authorize the transaction.
        ->Login History: Users can view a complete history of their logins, including IP address, device, and geographic location.
        ->Login Map: Provides a map view showing all geographic login locations.

    ##Admin Panel
        ->Secure Admin Registration: New admin accounts cannot be created directly; they must be "pending" and require approval from a master admin (via an email link) before being activated.
        ->User Management: Admins have a dashboard to view, lock, and unlock any user account.
        ->Admin Oversight: Admins can view the full profile, transaction history, and login map for any user in the system.
        ->Balance Correction: Admins have tools to credit a user's account (e.g., for a bonus) or set a new balance (for corrections), with all actions logged as transactions.
        ->Transaction Management: Admins can view a list of all failed transactions and issue refunds.
        ->Admin Login History: Admins can view a sortable and filterable history of all admin account logins.

## Tech Stack
    ->Backend: Python, Flask, Gunicorn
    ->Database: PostgreSQL (running on Google Cloud SQL)
    ->Frontend: HTML, Tailwind CSS, JavaScript
    ->ORM: SQLAlchemy

### How to run this project

check python version
if it is python 3.14.2

#### Follow these steps

# Step1 : Download the ZIP file
            -Extract the file and open into an editor
    
# Step2 : Backend setup
            - In editor terminal run this 
            1 python -m pip install --upgrade pip 
            2 pip install -r requirements.txt

                # google setup
                3 Go to your google acount and search for app
                    ->There give your project or app name and then create
                    ->Your Gmail will be your user name - paste it in app.py 
                        line38- app.config['MAIL_USERNAME'] = 'yyy@gmail.com'
                    ->you will get a password of 16 characters that has created - paste it in app.py 
                        line39 app.config['MAIL_PASSWORD'] = 'xxxx xxxx xxxx xxxx' 
                    ->in line 40 app.config['MAIL_DEFAULT_SENDER'] = ('xxxx', 'yyy@gmail.com') #xxxx->App name you have created, #yyyyyyy -> gmail in which app created

                    ->In line 51 MASTER_ADMIN_EMAIL = 'aaaaa' #aaaaa put the same gmail as mentioned above this will the main gmail for controlling all the users and admin for approval after signup

                    ->In line 65,66 for a default admin
                    admin_email = 'cccc@gmail.com' #Any gmail required while admin login
                    admin_pass = 'dddd'             #Any Password required while admin login

# Step 3 : DataBase setp
            ->download PostGreSQL from chrome 
            ->After Downloading do the setup and create a server of postgreSQL18, while creating the server you will asked for a password ,do the password setup, it is required for connecting the database.
            ->In line 31 app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:xxxxxx@localhost:5001/yyyyyy' 
             #xxxxxxx -> password created in database, #yyyyyy -> name of the database created in postgreSQl (eg: SecureBank)

# Step4 : Running the project
            -> After all the setup done Close everything

            then follow this 
            1 -> Connect the database by opening the pgadmin4 app by pressing the windows button and search for something like pgAdmin4 
                -After opening db(database) connect the server by entering the password where you will get the confirmation as connected
                after this go to next step

            2->open the project folder in an editor
                -In terminal of editor run this command
                    python app.py           #THIS command for running the backend
                -Add one more terminal or pwsh, where run this command
                    .\cloudflared-windows-amd64.exe tunnel --url http://localhost:5005      #THIS command for creating the tunnel,from local host to the web server




# FOR different version of python
1 Download the python version of 3.14.2   and do the setup ,while setup click the path check box
2 RUN this command
  py -3.14 -m venv venv          #for creating virtual environment
  venv\Scripts\activate          #for activating the virtual environment
  python -m pip install --upgrade pip                                                                                                
  pip install -r requirements.txt

3 Follow #Step 4
