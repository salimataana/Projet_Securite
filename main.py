from flask import Flask, render_template, request, jsonify
from extended_hsm_manager import ExtendedHSMManager
import os
import time

app = Flask(__name__)
os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'

# Initialisation HSM
hsm_manager = ExtendedHSMManager()
hsm_manager.connect('1234')


# ============================
# Pages HTML
# ============================
@app.route('/')
def index():
    return render_template('index_extended.html')


@app.route('/keys')
def keys_page():
    return render_template('keys.html')


# ============================
# Opérations cryptographiques
# ============================

# SIGNATURE
@app.route('/sign', methods=['POST'])
def sign_data_route():
    data = request.json.get('data')
    key_label = request.json.get('key_label')
    if not data:
        return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

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
    return jsonify({'success': False, 'error': 'Échec de la signature'})


# VERIFICATION SIGNATURE
@app.route('/verify-signature', methods=['POST'])
def verify_signature_route():
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


# CHIFFREMENT / DECHIFFREMENT
@app.route('/encrypt', methods=['POST'])
def encrypt_data_route():
    data = request.json.get('data')
    key_label = request.json.get('key_label')
    if not data:
        return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

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
    return jsonify({'success': False, 'error': 'Échec du chiffrement'})


@app.route('/decrypt', methods=['POST'])
def decrypt_data_route():
    encrypted_data = request.json.get('encrypted_data')
    key_label = request.json.get('key_label')
    if not encrypted_data:
        return jsonify({'success': False, 'error': 'Aucune donnée chiffrée fournie'})

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
    return jsonify({'success': False, 'error': 'Échec du déchiffrement'})


# HASH + SIGNATURE
@app.route('/hash-and-sign', methods=['POST'])
def hash_and_sign_route():
    data = request.json.get('data')
    algorithm = request.json.get('algorithm', 'sha256')
    key_label = request.json.get('key_label')

    if not data or not key_label:
        return jsonify({'success': False, 'error': 'Données ou clé manquantes'})

    result = hsm_manager.hash_and_sign(data, algorithm, key_label)
    return jsonify(result)


# ============================
# Gestion des clés via API
# ============================
@app.route('/api/keys', methods=['GET'])
def get_all_keys():
    keys = hsm_manager.get_all_keys()
    return jsonify({'success': True, 'keys': keys, 'count': len(keys)})


@app.route('/api/keys/active', methods=['GET'])
def get_active_keys():
    keys = hsm_manager.get_active_keys()
    return jsonify({'success': True, 'keys': keys, 'count': len(keys)})


@app.route('/api/keys/<key_label>/activate', methods=['POST'])
def activate_key(key_label):
    success = hsm_manager.activate_key(key_label)
    if success:
        return jsonify({'success': True, 'message': f'Clé {key_label} activée'})
    return jsonify({'success': False, 'error': f'Échec activation clé {key_label}'})


@app.route('/api/keys/<key_label>/deactivate', methods=['POST'])
def deactivate_key(key_label):
    success = hsm_manager.deactivate_key(key_label)
    if success:
        return jsonify({'success': True, 'message': f'Clé {key_label} désactivée'})
    return jsonify({'success': False, 'error': f'Échec désactivation clé {key_label}'})


@app.route('/api/generate-key', methods=['POST'])
def api_generate_key():
    key_label = request.json.get('key_label')
    public_key, private_key = hsm_manager.generate_key_pair(key_label)
    if public_key and private_key:
        return jsonify({'success': True, 'message': f'Clé générée: {key_label}', 'key_label': key_label})
    return jsonify({'success': False, 'error': 'Échec génération clé'})

# Vérification Hash + Signature
@app.route('/verify-hash-signature', methods=['POST'])
def verify_hash_sign():
    data = request.json.get('data')
    signature = request.json.get('signature')
    expected_hash = request.json.get('hash')
    algorithm = request.json.get('algorithm', 'sha256')
    key_label = request.json.get('key_label')

    if not data or not signature or not expected_hash or not key_label:
        return jsonify({'success': False, 'error': 'Données, signature, hash ou clé manquantes'})

    result = hsm_manager.verify_hash_and_signature(
        data=data,
        signature=signature,
        expected_hash=expected_hash,
        hash_algorithm=algorithm,
        key_label=key_label
    )
    return jsonify(result)

# ============================
# Debug et opérations
# ============================
@app.route('/debug', methods=['POST'])
def debug_keys():
    hsm_manager.debug_keys()
    return jsonify({'success': True, 'message': 'Debug exécuté - voir terminal'})


# ============================
# Lancement du serveur
# ============================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
