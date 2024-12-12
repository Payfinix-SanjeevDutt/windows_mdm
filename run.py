from app import create_app

app = create_app()

if __name__ == '__main__':
    # app.run(debug=True, host='192.168.0.221')
    app.run(host='0.0.0.0', port=5000, debug=True,ssl_context=("cert.pem", "key.pem"))
    # app.run(ssl_context=('cert.pem','key.pem'),port=443)