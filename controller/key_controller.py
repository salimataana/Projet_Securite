from flask import request, jsonify





from flask import Blueprint, render_template
from core.hsm_manager import HSMManager

key_controller = Blueprint('keys', __name__, template_folder='../templates')
hsm_manager = HSMManager()


@key_controller.route('/generate-keys', methods=['POST'])
def api_generate_key():
    """Génère une nouvelle clé avec stockage"""
    try:
        key_size = int(request.form.get('key_size', 2048))
        key_type = request.form.get('keyType', 2048)
        key_label = request.form.get('keyLabel')

        result = hsm_manager.generate_key_pair_with_storage(
            key_size=key_size,
            key_type=key_type,
            key_label=key_label
        )
        return render_template("operations_results_creating.html", result=result)
    except Exception as e:
        return render_template("operations_results_creating.html", result=str(e))




@key_controller.route('/api/keys/list', methods=['GET'])
def api_list_keys():
    """Récupère la liste des clés"""
    try:
        keys = hsm_manager.get_all_keys_public()
        #statistics = database.get_usage_statistics()
        return jsonify({
            'success': True,
            'keys': keys,
            #'statistics': statistics
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@key_controller.route('/encrypt-decrypt', methods=['POST'])
def api_encrypt_data():
    mode = request.form.get('mode')
    label_private = request.form.get('keyPrivateSelector')
    label_public = request.form.get('keyPublicSelector')

    data = request.form.get('simpleInput')
    if mode not in ['encrypt', 'decrypt']:
        return jsonify({'success': False})

    if mode == 'encrypt':
        data_encrypted =hsm_manager.encrypt_data(data, label_key=label_public)
        return  render_template('operations_results.html',data_encrypted=data_encrypted)

    elif mode == 'decrypt':
        data_decrypted = hsm_manager.decrypt_data(data, label_key=label_private)
        return  render_template('operations_results.html',data_encrypted=data_decrypted)


@key_controller.route('/sign-verify', methods=['POST'])
def api_sign_data():
    mode = request.form.get('mode')
    label_private = request.form.get('keyPrivateSelector')
    label_public = request.form.get('keyPublicSelector')
    signature = request.form.get('signature')

    data = request.form.get('simpleInput')

    if mode not in ['signer', 'designer']:
        return jsonify({'success': False})

    if mode == 'signer':
        data_encrypted = hsm_manager.sign_data(data=str(data), label_key=label_private)
        return  render_template('operations_results_signature.html',data_encrypted=data_encrypted)

    elif mode == 'designer':
        if signature is None:
            return jsonify({'success': False})
        verify_statut = hsm_manager.verify_signature(data, signature=signature,label_key=label_private)
        return  render_template('operations_results_signature.html',verify_statut=verify_statut)



@key_controller.route('/hash-sign', methods=['POST'])
def hash_sign_message():
    method_hash = request.form.get('hashAlgorithm')
    key_private = request.form.get('keyPrivateSelector')
    key_public = request.form.get('keyPublicSelector')
    data = request.form.get('hashSignInput')

    data_hash_sign = hsm_manager.hash_and_sign(data=data,hash_algorithm=method_hash,key_label=key_private)

    return render_template("operations_results_hash_signature.html", data_hash_sign=data_hash_sign)



@key_controller.route('/verify-hash-signature', methods=['POST'])
def verify_hash_signature():
    method_hash = request.form.get('hashAlgorithm')
    key_public = request.form.get('keyPublicSelector')
    data = request.form.get('hashSignInput')
    signature = request.form.get('signature')



    is_valid = hsm_manager.verify_hash_signature(data=data,signature=signature,hash_algorithm=method_hash,
                                                 label_key=key_public)
    print(is_valid)

    return render_template("operations_results_hash_signature.html", is_valid=is_valid)

