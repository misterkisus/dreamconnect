from flask import Flask

app = Flask(__name__)

@app.before_first_request
def before_first_request_func():
    print("This function will run once before the first request.")

@app.route('/')
def home():
    return "Hello, Flask!"

if __name__ == '__main__':
    app.run(debug=True)
