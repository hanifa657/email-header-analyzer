from flask import Flask, render_template, request
from analyzer.detector import check_phishing

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    result = ""

    if request.method == "POST":

        email_header = request.form["header"]

        headers = {}

        lines = email_header.split("\n")

        for line in lines:

            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        result = check_phishing(headers)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)