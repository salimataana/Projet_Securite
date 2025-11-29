# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
from extended_hsm_manager import ExtendedHSMManager
from performance_analyzer import PerformanceAnalyzer
from hash_manager import HashManager
import os
import time

# Initialisation de l'application Flask
app = Flask(__name__)
os.environ['SOFTHSM2_CONF'] = './softhsm2.conf'

# Initialisation des managers
hsm_manager = ExtendedHSMManager()
# Connexion d'abord au HSM
hsm_manager.connect('1234')

# Puis initialiser les autres managers avec le HSM déjà connecté
performance_analyzer = PerformanceAnalyzer(hsm_manager)
hash_manager = HashManager()

@app.route('/')
def index():
    """Page principale complète"""
    return render_template('index_extended.html')

# ==================== ROUTES DE BASE (de main.py) ====================

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """Génération des clés RSA"""
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

@app.route('/sign', methods=['POST'])
def sign_data():
    """Signature simple"""
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
    """Vérification signature simple"""
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

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    """Chiffrement simple"""
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
    """Déchiffrement simple"""
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

# ==================== ROUTES ÉTENDUES (de main_extended.py) ====================

@app.route('/hash-and-sign', methods=['POST'])
def hash_and_sign():
    """Hachage + Signature (Chapitres 8 + 9)"""
    try:
        data = request.json.get('data')
        algorithm = request.json.get('algorithm', 'sha256')
        
        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})
        
        result = hsm_manager.hash_and_sign(data, algorithm)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/verify-hash-signature', methods=['POST'])
def verify_hash_signature():
    """Vérification hachage + signature (Chapitres 8 + 9)"""
    try:
        data = request.json.get('data')
        signature = request.json.get('signature')
        expected_hash = request.json.get('expected_hash')
        algorithm = request.json.get('algorithm', 'sha256')
        
        if not all([data, signature, expected_hash]):
            return jsonify({'success': False, 'error': 'Paramètres manquants'})
        
        result = hsm_manager.verify_hash_and_signature(data, signature, expected_hash, algorithm)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/compute-hash', methods=['POST'])
def compute_hash():
    """Calcul de hash simple (Chapitre 8)"""
    try:
        data = request.json.get('data')
        algorithm = request.json.get('algorithm', 'sha256')
        
        if not data:
            return jsonify({'success': False, 'error': 'Aucune donnée fournie'})
        
        start_time = time.time()
        hash_value = hash_manager.compute_hash(data, algorithm)
        end_time = time.time()
        
        return jsonify({
            'success': True,
            'hash': hash_value,
            'algorithm': algorithm,
            'processing_time': f"{(end_time - start_time) * 1000:.2f} ms",
            'concept': 'Fonction de hachage cryptographique - Chapitre 8'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/benchmark/performance', methods=['POST'])
def benchmark_performance():
    """Analyse des performances (Chapitres 4 et 7)"""
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
            'performance_chart': chart_data,
            'concepts': [
                'Analyse impact taille clés RSA - Chapitre 7',
                'Comparaison implémentations cryptographiques - Chapitre 4',
                'Performance modes chiffrement - Chapitre 6'
            ]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/benchmark/hash-algorithms', methods=['POST'])
def benchmark_hash_algorithms():
    """Benchmark des algorithmes de hachage (Chapitre 8)"""
    try:
        data = request.json.get('data', 'Test data for hashing benchmark')
        results = hash_manager.benchmark_hash_algorithms(data)
        
        return jsonify({
            'success': True,
            'results': results,
            'concept': 'Comparaison performances algorithmes de hachage - Chapitre 8'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/demonstrate/concepts', methods=['POST'])
def demonstrate_concepts():
    """Démonstration des concepts cryptographiques (Tous chapitres)"""
    try:
        concepts_demo = hsm_manager.demonstrate_cryptographic_concepts()
        
        return jsonify({
            'success': True,
            'concepts': concepts_demo,
            'explication': 'Démonstration pratique des concepts vus en cours'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/demonstrate/collision-resistance', methods=['POST'])
def demonstrate_collision_resistance():
    """Démonstration résistance aux collisions (Chapitre 8)"""
    try:
        collision_demo = hash_manager.demonstrate_collision_resistance()
        
        return jsonify({
            'success': True,
            'demonstrations': collision_demo,
            'concept': 'Propriétés cryptographiques des fonctions de hachage - Chapitre 8'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/debug', methods=['POST'])
def debug_keys():
    """Debug des clés HSM"""
    hsm_manager.debug_keys()
    return jsonify({'success': True, 'message': 'Debug exécuté - voir terminal'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
    