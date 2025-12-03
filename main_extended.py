 # -*- coding: utf-8 -*-
import sqlite3
from flask import Flask, render_template, request, jsonify
from extended_hsm_manager import ExtendedHSMManager
from performance_analyzer import PerformanceAnalyzer
from hash_manager import HashManager
from database import KeyDatabase
import os
import time

# Initialisation de l'application Flask
app = Flask(__name__)
os.environ['SOFTHSM2_CONF'] = './softhsm2.conf'

# Initialisation de la base de données
database = KeyDatabase()

# Initialisation des managers
hsm_manager = ExtendedHSMManager()
hsm_manager.set_database(database)

# Connexion au HSM
hsm_manager.connect('1234')

# Initialiser les autres managers
performance_analyzer = PerformanceAnalyzer(hsm_manager)
hash_manager = HashManager()


@app.route('/')
def index():
    """Page principale"""
    return render_template('index_extended.html')


@app.route('/keys')
def keys_management():
    """Page de gestion des clés"""
    return render_template('keys_management.html')


# ==================== API DE GESTION DES CLÉS ====================

@app.route('/api/keys/generate', methods=['POST'])
def api_generate_key():
    """Génère une nouvelle clé avec stockage"""
    try:
        key_size = request.json.get('key_size', 2048)
        result = hsm_manager.generate_key_pair_with_storage(key_size)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/keys/list', methods=['GET'])
def api_list_keys():
    """Récupère la liste des clés"""
    try:
        keys = database.get_all_keys()
        statistics = database.get_usage_statistics()
        return jsonify({
            'success': True,
            'keys': keys,
            'statistics': statistics
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/keys/<key_id>/operations', methods=['GET'])
def api_key_operations(key_id):
    """Récupère les opérations d'une clé"""
    try:
        operations = database.get_key_operations(key_id)
        return jsonify({
            'success': True,
            'operations': operations
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/keys/statistics', methods=['GET'])
def api_keys_statistics():
    """Récupère les statistiques globales"""
    try:
        statistics = database.get_usage_statistics()
        return jsonify({
            'success': True,
            'statistics': statistics
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==================== API CRYPTOGRAPHIE DE BASE ====================

@app.route('/api/generate-keys', methods=['POST'])
def api_generate_keys():
    """Génération des clés RSA"""
    try:
        start_time = time.time()
        public_key, private_key = hsm_manager.generate_key_pair()
        end_time = time.time()

        if public_key and private_key:
            return jsonify({
                'success': True,
                'message': 'Clés RSA générées avec succès',
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec de la génération des clés'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/sign', methods=['POST'])
def api_sign_data():
    """Signature simple"""
    try:
        data = request.json.get('data')
        key_id = request.json.get('key_id')

        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        start_time = time.time()  # Démarrage du chronomètre

        if key_id:
            signature = hsm_manager.sign_data_with_tracking(data, key_id)
        else:
            signature = hsm_manager.sign_data(data)

        end_time = time.time()  # Fin du chronomètre

        if signature:
            return jsonify({
                'success': True,
                'signature': signature,
                'key_id': key_id,
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec de la signature'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/verify', methods=['POST'])
def api_verify_signature():
    """Vérification signature"""
    try:
        data = request.json.get('data')
        signature = request.json.get('signature')

        if not data or not signature:
            return jsonify({'success': False, 'error': 'Données ou signature manquantes'})

        start_time = time.time()  # Démarrage du chronomètre
        is_valid = hsm_manager.verify_signature(data, signature)
        end_time = time.time()  # Fin du chronomètre

        return jsonify({
            'success': True,
            'valid': is_valid,
            'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



@app.route('/api/encrypt', methods=['POST'])
def api_encrypt_data():
    """Chiffrement simple avec retour du key_label utilisé"""
    try:
        data = request.json.get('data')
        key_label = request.json.get('key_id')  # Ici key_id correspond au label

        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        start_time = time.time()  # Début chronomètre

        # Chiffrement en utilisant la clé publique correspondant au label
        if key_label:
            encrypted_data, used_label = hsm_manager.encrypt_data(data, key_label)
        else:
            encrypted_data, used_label = hsm_manager.encrypt_data(data)  # Utilise la première clé dispo

        end_time = time.time()  # Fin chronomètre

        if encrypted_data:
            return jsonify({
                'success': True,
                'encrypted_data': encrypted_data,
                'key_id': used_label,  # Retourne le label utilisé pour le déchiffrement
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec du chiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt_data():
    """Déchiffrement simple avec clé privée correspondant au key_label"""
    try:
        encrypted_data = request.json.get('encrypted_data')
        key_label = request.json.get('key_id')  # Obligatoire pour retrouver la clé privée

        if not encrypted_data or not key_label:
            return jsonify({'success': False, 'error': 'Données chiffrées ou key_label manquant'})

        start_time = time.time()  # Début chronomètre

        # Déchiffrement avec la clé privée correspondant au key_label
        decrypted_data = hsm_manager.decrypt_data(encrypted_data, key_label)

        end_time = time.time()  # Fin chronomètre

        if decrypted_data:
            return jsonify({
                'success': True,
                'decrypted_data': decrypted_data,
                'key_id': key_label,
                'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
            })
        else:
            return jsonify({'success': False, 'error': 'Échec du déchiffrement'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==================== API FONCTIONNALITÉS AVANCÉES ====================

@app.route('/api/hash-and-sign', methods=['POST'])
def api_hash_and_sign():
    """Hachage + Signature"""
    try:
        data = request.json.get('data')
        algorithm = request.json.get('algorithm', 'sha256')
        key_id = request.json.get('key_id')

        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        start_time = time.time()  # Début chronomètre
        result = hsm_manager.hash_and_sign(data, algorithm, key_id)
        end_time = time.time()  # Fin chronomètre

        # Ajouter le temps de traitement dans le résultat
        result['processing_time'] = f"{(end_time - start_time) * 1000:.2f} ms"

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



@app.route('/api/verify-hash-signature', methods=['POST'])
def api_verify_hash_signature():
    """Vérification hachage + signature"""
    try:
        data = request.json.get('data')
        signature = request.json.get('signature')
        expected_hash = request.json.get('expected_hash')
        algorithm = request.json.get('algorithm', 'sha256')

        if not all([data, signature, expected_hash]):
            return jsonify({'success': False, 'error': 'Paramètres manquants'})

        start_time = time.time()  # Début chronomètre
        result = hsm_manager.verify_hash_and_signature(data, signature, expected_hash, algorithm)
        end_time = time.time()  # Fin chronomètre

        # Ajouter le temps de traitement dans le résultat
        result['processing_time'] = f"{(end_time - start_time) * 1000:.2f} ms"

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/compute-hash', methods=['POST'])
def api_compute_hash():
    """Calcul de hash"""
    try:
        data = request.json.get('data')
        algorithm = request.json.get('algorithm', 'sha256')

        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})

        start_time = time.time()  # Début chronomètre
        hash_value = hash_manager.compute_hash(data, algorithm)
        end_time = time.time()  # Fin chronomètre

        return jsonify({
            'success': True,
            'hash': hash_value,
            'algorithm': algorithm,
            'processing_time': f"{(end_time - start_time) * 1000:.2f} ms"
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



# ==================== API BENCHMARK ET ANALYSE ====================

@app.route('/api/benchmark/performance', methods=['GET'])
def api_benchmark_performance():
    """Analyse des performances"""
    try:
        key_size_analysis = performance_analyzer.benchmark_rsa_key_sizes()
        hsm_vs_software = performance_analyzer.compare_hsm_vs_software()
        encryption_modes = performance_analyzer.analyze_encryption_modes()
        chart_data = performance_analyzer.generate_performance_chart(key_size_analysis)

        return jsonify({
            'success': True,
            'key_size_analysis': key_size_analysis,
            'hsm_vs_software': hsm_vs_software,
            'encryption_modes': encryption_modes,
            'performance_chart': chart_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/benchmark/hash-algorithms', methods=['POST'])
def api_benchmark_hash_algorithms():
    """Benchmark des algorithmes de hachage"""
    try:
        data = request.json.get('data', 'Test data for hashing benchmark')
        results = hash_manager.benchmark_hash_algorithms(data)

        return jsonify({
            'success': True,
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/demonstrate/concepts', methods=['GET'])
def api_demonstrate_concepts():
    """Démonstration des concepts cryptographiques"""
    try:
        concepts_demo = hsm_manager.demonstrate_cryptographic_concepts()

        return jsonify({
            'success': True,
            'concepts': concepts_demo
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/demonstrate/collision-resistance', methods=['GET'])
def api_demonstrate_collision_resistance():
    """Démonstration résistance aux collisions"""
    try:
        collision_demo = hash_manager.demonstrate_collision_resistance()

        return jsonify({
            'success': True,
            'demonstrations': collision_demo
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/debug', methods=['GET'])
def api_debug_keys():
    """Debug des clés HSM"""
    hsm_manager.debug_keys()
    return jsonify({'success': True, 'message': 'Debug exécuté - voir terminal'})


# ==================== ROUTES COMPATIBILITÉ (anciennes routes) ====================

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    return api_generate_keys()


@app.route('/sign', methods=['POST'])
def sign_data():
    return api_sign_data()


@app.route('/verify', methods=['POST'])
def verify_signature():
    return api_verify_signature()


@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    return api_encrypt_data()


@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    return api_decrypt_data()


@app.route('/hash-and-sign', methods=['POST'])
def hash_and_sign():
    return api_hash_and_sign()


@app.route('/verify-hash-signature', methods=['POST'])
def verify_hash_signature():
    return api_verify_hash_signature()


@app.route('/compute-hash', methods=['POST'])
def compute_hash():
    return api_compute_hash()


@app.route('/benchmark/performance', methods=['POST'])
def benchmark_performance():
    return api_benchmark_performance()


@app.route('/benchmark/hash-algorithms', methods=['POST'])
def benchmark_hash_algorithms():
    return api_benchmark_hash_algorithms()


@app.route('/demonstrate/concepts', methods=['POST'])
def demonstrate_concepts():
    return api_demonstrate_concepts()


@app.route('/demonstrate/collision-resistance', methods=['POST'])
def demonstrate_collision_resistance():
    return api_demonstrate_collision_resistance()


@app.route('/debug', methods=['POST'])
def debug_keys():
    return api_debug_keys()


@app.route('/test-crypto-cycle', methods=['POST'])
def test_crypto_cycle():
    """Test du cycle complet chiffrement/déchiffrement"""
    success = hsm_manager.test_encryption_cycle("Test123")
    return jsonify({'success': success, 'message': 'Test complet exécuté - voir console'})


@app.route('/clean-and-test', methods=['POST'])
def clean_and_test():
    """Nettoyer et tester avec une seule clé"""
    # Nettoyer le HSM (méthode temporaire)
    hsm_manager._clean_keys()

    # Générer une nouvelle clé
    hsm_manager.generate_key_pair()

    # Tester
    success = hsm_manager.test_encryption_cycle("Test123")
    return jsonify({'success': success})


@app.route('/api/keys/<key_id>/toggle-status', methods=['POST'])
def api_toggle_key_status(key_id):
    """Activer/désactiver une clé"""
    try:
        # Cette méthode va mettre à jour le statut dans la base de données
        # Pour l'instant, on simule avec une mise à jour directe
        conn = sqlite3.connect('keys_database.db')
        cursor = conn.cursor()

        # Récupérer le statut actuel
        cursor.execute('SELECT status FROM keys WHERE key_id = ?', (key_id,))
        result = cursor.fetchone()

        if not result:
            return jsonify({'success': False, 'error': 'Clé non trouvée'})

        current_status = result[0]
        new_status = 'inactive' if current_status == 'active' else 'active'

        # Mettre à jour le statut
        cursor.execute('UPDATE keys SET status = ? WHERE key_id = ?', (new_status, key_id))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'new_status': new_status,
            'message': f'Clé {"désactivée" if new_status == "inactive" else "activée"}'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)