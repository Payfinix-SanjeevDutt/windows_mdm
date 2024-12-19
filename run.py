from app import create_app
import os
from flask import Flask,jsonify,request

app = create_app()


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000, debug=True,ssl_context=("cert.pem", "key.pem"))
    port = int(os.getenv("PORT", 5000))  # Default to 5000 if PORT is not set
    app.run(host="0.0.0.0", port=port, debug=True)