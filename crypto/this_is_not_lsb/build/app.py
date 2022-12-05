from flask import Flask, request, send_file, make_response

app = Flask(__name__)


@app.route("/")
def index():
    return "SECCON{uouo_fish_life}"


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
