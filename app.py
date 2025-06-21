from flask import Flask, request, jsonify
import smtplib
import dns.resolver
import socket
import re

app = Flask(__name__)

def is_valid_syntax(email):
    regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return re.match(regex, email) is not None

def verify_smtp(email):
    if not is_valid_syntax(email):
        return {'email': email, 'status': False, 'reason': 'Invalid email syntax'}

    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_records])
    except Exception as e:
        return {'email': email, 'status': False, 'reason': f'MX lookup failed: {e}'}

    from_address = 'safeeraethon@gmail.com'
    helo_host = 'localhost'
    socket.setdefaulttimeout(5)

    for _, mailserver in mx_hosts:
        try:
            server = smtplib.SMTP(host=mailserver, port=25)
            server.helo(helo_host)
            server.mail(from_address)
            code, message = server.rcpt(email)
            server.quit()

            if code in [250, 251]:
                return {'email': email, 'status': True, 'reason': 'Valid mailbox'}
            elif code in [550, 551, 552, 553, 554]:
                return {'email': email, 'status': False, 'reason': f'SMTP rejected: {message.decode()}'}
            else:
                return {'email': email, 'status': False, 'reason': f'Unknown response: {code} {message.decode()}'}
        except Exception as e:
            continue

    return {'email': email, 'status': False, 'reason': 'All SMTP attempts failed'}

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    result = verify_smtp(email)
    return jsonify(result)