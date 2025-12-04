from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
        <head>
            <title>AlfaShop</title>
        </head>
        <body style='font-family: Arial; text-align: center;'>
            <h1>Welcome to AlfaShop</h1>
            <p>This is the home page.</p>
            <a href="/store">Go to Store</a>
        </body>
    </html>
    """

@app.route("/store")
def store():
    return """
    <html>
        <head>
            <title>Store</title>
        </head>
        <body style='font-family: Arial; text-align: center;'>
            <h1>Store Page</h1>
            <p>Products will be here soon...</p>
            <a href="/">Back Home</a>
        </body>
    </html>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
