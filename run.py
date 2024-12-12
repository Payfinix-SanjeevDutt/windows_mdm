from app import create_app
import os

app = create_app()

@app.route("/health")
def health():
    return "OK", 200


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000, debug=True,ssl_context=("cert.pem", "key.pem"))
    port = int(os.getenv("PORT", 5000))  # Default to 5000 if PORT is not set
    app.run(host="0.0.0.0", port=port)