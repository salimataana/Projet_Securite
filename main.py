from flask import Flask, render_template, request, jsonify
from hsm_manager import HSMManager
import os
import time

app = Flask(__name__)
os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'
hsm_manager = HSMManager()
hsm_manager.connect('1234')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/keys')
def keys_page():
    return render_template('keys.html')


@app.route('/sign', methods=['POST'])
def sign_data():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        start_time = time.time()
        signature = hsm_manager.sign_data(data)
        end_time = time.time()

        if signature:
            return jsonify({
                'success': True,
                'signature': signature,
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec de la signature'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/verify', methods=['POST'])
def verify_signature():
    try:
        data = request.json.get('data')
        signature = request.json.get('signature')

        if not data or not signature:
            return jsonify({'success': False, 'error': 'Données ou signature manquantes'})

        start_time = time.time()
        is_valid = hsm_manager.verify_signature(data, signature)
        end_time = time.time()

        return jsonify({
            'success': True,
            'valid': is_valid,
            'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    try:
        start_time = time.time()
        public_key, private_key = hsm_manager.generate_key_pair()
        end_time = time.time()

        if public_key is not None and private_key is not None:
            return jsonify({
                'success': True,
                'message': 'Clés RSA générées avec succès',
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec de la génération des clés'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        start_time = time.time()
        encrypted_data = hsm_manager.encrypt_data(data)
        end_time = time.time()

        if encrypted_data:
            return jsonify({
                'success': True,
                'encrypted_data': encrypted_data,
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec du chiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    try:
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data:
            return jsonify({'success': False, 'error': 'Aucune donnée chiffrée fournie'})

        start_time = time.time()
        decrypted_data = hsm_manager.decrypt_data(encrypted_data)
        end_time = time.time()

        if decrypted_data:
            return jsonify({
                'success': True,
                'decrypted_data': decrypted_data,
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec du déchiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/debug', methods=['POST'])
def debug_keys():
    hsm_manager.debug_keys()
    return jsonify({'success': True, 'message': 'Debug exécuté - voir terminal'})


# Routes API
@app.route('/api/keys', methods=['GET'])
def get_all_keys():
    try:
        keys = hsm_manager.get_all_keys()
        return jsonify({
            'success': True,
            'keys': keys,
            'count': len(keys)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/generate-key', methods=['POST'])
def api_generate_key():
    try:
        key_label = request.json.get('key_label')

        start_time = time.time()
        public_key, private_key = hsm_manager.generate_key_pair(key_label)
        end_time = time.time()

        if public_key and private_key:
            return jsonify({
                'success': True,
                'message': f'Clé générée: {key_label}',
                'key_label': key_label,
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec génération clé'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/sign', methods=['POST'])
def api_sign_with_key():
    try:
        data = request.json.get('data')
        key_label = request.json.get('key_label')

        if not data:
            return jsonify({'success': False, 'error': 'Données manquantes'})

        start_time = time.time()
        signature = hsm_manager.sign_data(data, key_label)
        end_time = time.time()

        if signature:
            return jsonify({
                'success': True,
                'signature': signature,
                'key_used': key_label or 'default',
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec signature'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/verify', methods=['POST'])
def api_verify_with_key():
    try:
        data = request.json.get('data')
        signature = request.json.get('signature')
        key_label = request.json.get('key_label')

        if not data or not signature:
            return jsonify({'success': False, 'error': 'Données ou signature manquantes'})

        start_time = time.time()
        is_valid = hsm_manager.verify_signature(data, signature, key_label)
        end_time = time.time()

        return jsonify({
            'success': True,
            'valid': is_valid,
            'key_used': key_label or 'default',
            'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt_with_key():
    try:
        data = request.json.get('data')
        key_label = request.json.get('key_label')

        if not data:
            return jsonify({'success': False, 'error': 'Données manquantes'})

        start_time = time.time()
        encrypted_data = hsm_manager.encrypt_data(data, key_label)
        end_time = time.time()

        if encrypted_data:
            return jsonify({
                'success': True,
                'encrypted_data': encrypted_data,
                'key_used': key_label or 'default',
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec chiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt_with_key():
    try:
        encrypted_data = request.json.get('encrypted_data')
        key_label = request.json.get('key_label')

        if not encrypted_data:
            return jsonify({'success': False, 'error': 'Données chiffrées manquantes'})

        start_time = time.time()
        decrypted_data = hsm_manager.decrypt_data(encrypted_data, key_label)
        end_time = time.time()

        if decrypted_data:
            return jsonify({
                'success': True,
                'decrypted_data': decrypted_data,
                'key_used': key_label or 'default',
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec déchiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/operations', methods=['GET'])
def get_operations():
    return jsonify({'success': True, 'message': 'À implémenter'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)