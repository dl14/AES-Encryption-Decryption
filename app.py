from flask import Flask, render_template, request

import AES_Encrypt_Decrypt

app = Flask(__name__)
print("IN APP.PY")
@app.route('/mainpage', methods=['POST', 'GET'])
def hello_world():
    plaintext = request.form.get('plaintext')
    initialKey = request.form.get('initialKey')
    print("calling AES encryption")
    ciphertext = AES_Encrypt_Decrypt.AES_encryption(plaintext, initialKey)
    return render_template('main.html', plaintext=plaintext, initialKey=initialKey, ciphertext=ciphertext)
@app.route('/decrypt', methods=['POST', 'GET'])
def decrypt():
    ciphertext = request.form.get('ciphertext_d')
    initialKey = request.form.get('initialKey_d')
    print("calling AES decryption")
    plaintext = AES_Encrypt_Decrypt.AES_decryption(ciphertext, initialKey)
    return render_template('main.html', plaintext_d=plaintext, initialKey_d=initialKey, ciphertext_d=ciphertext)

if __name__ == "__main__":
    app.run()
