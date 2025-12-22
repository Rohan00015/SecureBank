from flask_sqlalchemy import SQLAlchemy

# Create the SQLAlchemy instance without an app.
# It will be linked to the app in app.py
db = SQLAlchemy()