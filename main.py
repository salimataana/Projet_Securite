from flask import Flask, render_template, request, jsonify
from hsm_manager import HSMManager
import os
import time

# Initialisation de l'application Flask
app = Flask(__name__)

# Configuration de l'environnement pour SoftHSM
# Cette variable d'environnement indique à SoftHSM où trouver sa configuration
#os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'
os.environ['SOFTHSM2_CONF'] = './softhsm2.conf'

# Initialisation du gestionnaire HSM
# Création d'une instance unique qui gérera toutes les opérations cryptographiques
hsm_manager = HSMManager()

# Connexion initiale au HSM avec le PIN par défaut
# Cette connexion établit la session sécurisée avec le module HSM
hsm_manager.connect('1234')


@app.route('/')
def index():
    """
    Route principale - Page d'accueil de l'application
    Retourne l'interface web pour interagir avec le HSM
    """
    return render_template('index.html')


@app.route('/sign', methods=['POST'])
def sign_data():
    """
    Route pour signer des données avec le HSM
    Méthode: POST
    Attend: {'data': 'texte à signer'}
    Retourne: {'success': bool, 'signature': str, 'processing_time': str}
    """
    try:
        # Récupération des données depuis la requête JSON
        data = request.json.get('data')

        # Validation des données d'entrée
        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        # Mesure du temps d'exécution pour l'analyse des performances
        start_time = time.time()
        signature = hsm_manager.sign_data(data)
        end_time = time.time()

        # Vérification du résultat et construction de la réponse
        if signature:
            return jsonify({
                'success': True,
                'signature': signature,  # Signature en hexadécimal
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"  # Temps en millisecondes
            })
        else:
            return jsonify({'success': False, 'error': 'Échec de la signature'})

    except Exception as e:
        # Gestion des erreurs imprévues
        return jsonify({'success': False, 'error': str(e)})


@app.route('/verify', methods=['POST'])
def verify_signature():
    """
    Route pour vérifier une signature avec le HSM
    Méthode: POST
    Attend: {'data': 'texte original', 'signature': 'signature à vérifier'}
    Retourne: {'success': bool, 'valid': bool, 'processing_time': str}
    """
    try:
        # Récupération des données et signature depuis la requête
        data = request.json.get('data')
        signature = request.json.get('signature')

        # Validation des paramètres requis
        if not data or not signature:
            return jsonify({'success': False, 'error': 'Données ou signature manquantes'})

        # Mesure des performances de vérification
        start_time = time.time()
        is_valid = hsm_manager.verify_signature(data, signature)
        end_time = time.time()

        # Retour du résultat de vérification
        return jsonify({
            'success': True,
            'valid': is_valid,  # True si signature valide, False sinon
            'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """
    Route pour générer une nouvelle paire de clés RSA dans le HSM
    Méthode: POST
    Retourne: {'success': bool, 'message': str, 'processing_time': str}
    """
    try:
        # Mesure du temps de génération des clés (opération la plus longue)
        start_time = time.time()
        public_key, private_key = hsm_manager.generate_key_pair()
        end_time = time.time()

        # Vérification que les clés ont été générées avec succès
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
    """
    Route pour chiffrer des données avec la clé publique du HSM
    Méthode: POST
    Attend: {'data': 'texte à chiffrer'}
    Retourne: {'success': bool, 'encrypted_data': str, 'processing_time': str}
    """
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        # Mesure des performances de chiffrement
        start_time = time.time()
        encrypted_data = hsm_manager.encrypt_data(data)
        end_time = time.time()

        if encrypted_data:
            return jsonify({
                'success': True,
                'encrypted_data': encrypted_data,  # Données chiffrées en hexadécimal
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec du chiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    """
    Route pour déchiffrer des données avec la clé privée du HSM
    Méthode: POST
    Attend: {'encrypted_data': 'données chiffrées en hexadécimal'}
    Retourne: {'success': bool, 'decrypted_data': str, 'processing_time': str}
    """
    try:
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data:
            return jsonify({'success': False, 'error': 'Aucune donnée chiffrée fournie'})

        # Mesure des performances de déchiffrement
        start_time = time.time()
        decrypted_data = hsm_manager.decrypt_data(encrypted_data)
        end_time = time.time()

        if decrypted_data:
            return jsonify({
                'success': True,
                'decrypted_data': decrypted_data,  # Texte déchiffré
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec du déchiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/debug', methods=['POST'])
def debug_keys():
    """
    Route de débogage pour lister les clés disponibles dans le HSM
    Utile pour le développement et la résolution de problèmes
    Méthode: POST
    Retourne: {'success': bool, 'message': str}
    """
    hsm_manager.debug_keys()
    return jsonify({'success': True, 'message': 'Debug exécuté - voir terminal'})


if __name__ == '__main__':
    """
    Point d'entrée principal de l'application
    Lance le serveur Flask en mode debug sur toutes les interfaces
    """
    app.run(debug=True, host='0.0.0.0', port=5000)