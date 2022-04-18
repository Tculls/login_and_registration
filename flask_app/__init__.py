from flask import Flask, session



app = Flask(__name__)

app.secret_key = "Triangle skateboard pete"

# flash messages get saved into session