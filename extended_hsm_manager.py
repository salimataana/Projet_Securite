from hsm_manager import HSMManager
from hash_manager import HashManager
import pkcs11
from pkcs11 import Mechanism
import time

class ExtendedHSMManager(HSMManager):
    """
    Extension du gestionnaire HSM avec les fonctionnalités avancées
    Couvre les chapitres 8 et 9 : Hachage et Signature
    """
    
    def __init__(self):
        super().__init__()
        self.hash_manager = HashManager()
    
    def hash_and_sign(self, data, hash_algorithm='sha256'):
        """
        Hachage + Signature - Pattern sécurité complet
        Chapitre 8 + 9 : Intégrité + Authenticité
        """
        print(f"🔐 Hachage + Signature avec {hash_algorithm}...")
        
        # Étape 1: Hachage des données (Chapitre 8)
        start_hash = time.time()
        data_hash = self.hash_manager.compute_hash(data, hash_algorithm)
        hash_time = time.time() - start_hash
        
        print(f"✅ Hash calculé: {data_hash[:32]}...")
        
        # Étape 2: Signature du hash (Chapitre 9)
        start_sign = time.time()
        signature = self.sign_data(data_hash)  # On signe le hash, pas les données brutes
        sign_time = time.time() - start_sign
        
        if signature:
            return {
                'success': True,
                'hash': data_hash,
                'signature': signature,
                'hash_algorithm': hash_algorithm,
                'performance': {
                    'hash_time': f"{hash_time * 1000:.2f} ms",
                    'sign_time': f"{sign_time * 1000:.2f} ms",
                    'total_time': f"{(hash_time + sign_time) * 1000:.2f} ms"
                },
                'concept': "Intégrité (hachage) + Authenticité (signature) - Chapitres 8 et 9"
            }
        else:
            return {'success': False, 'error': 'Échec de la signature'}
    
    def verify_hash_and_signature(self, data, signature, expected_hash, hash_algorithm='sha256'):
        """
        Vérification complète hachage + signature
        Chapitre 8 + 9 : Vérification intégrité et authenticité
        """
        print("🔍 Vérification intégrité + authenticité...")
        
        # Étape 1: Vérifier l'intégrité via hachage (Chapitre 8)
        computed_hash = self.hash_manager.compute_hash(data, hash_algorithm)
        
        if computed_hash != expected_hash:
            return {
                'success': False,
                'valid': False,
                'error': 'INTÉGRITÉ COMPROMISE - Hash ne correspond pas',
                'details': {
                    'computed_hash': computed_hash,
                    'expected_hash': expected_hash
                }
            }
        
        print("✅ Intégrité vérifiée (hachage OK)")
        
        # Étape 2: Vérifier la signature (Chapitre 9)
        is_valid = self.verify_signature(expected_hash, signature)  # On vérifie la signature du hash
        
        if is_valid:
            return {
                'success': True,
                'valid': True,
                'message': '✅ Document authentique et intègre',
                'concept': 'Vérification complète Chapitres 8 et 9'
            }
        else:
            return {
                'success': True,
                'valid': False,
                'message': '❌ Signature invalide - Document modifié ou non authentique'
            }
    
    def demonstrate_cryptographic_concepts(self):
        """
        Démonstration pratique des concepts cryptographiques du cours
        """
        concepts = {
            'confidentialite': {
                'name': 'Confidentialité',
                'chapter': 'Chapitre 6',
                'description': 'Seul le destinataire peut lire le message',
                'demonstration': self._demo_confidentialite
            },
            'integrite': {
                'name': 'Intégrité', 
                'chapter': 'Chapitre 8',
                'description': 'Le message n\'a pas été modifié',
                'demonstration': self._demo_integrite
            },
            'authenticite': {
                'name': 'Authenticité',
                'chapter': 'Chapitre 9',
                'description': 'On peut vérifier l\'identité de l\'expéditeur',
                'demonstration': self._demo_authenticite
            },
            'non_repudiation': {
                'name': 'Non-répudiation',
                'chapter': 'Chapitre 9',
                'description': 'L\'expéditeur ne peut nier avoir envoyé le message',
                'demonstration': self._demo_non_repudiation
            }
        }
        
        results = {}
        for concept_key, concept_info in concepts.items():
            print(f"🎯 Démonstration: {concept_info['name']} ({concept_info['chapter']})")
            try:
                # Appeler la méthode de démonstration
                demo_result = concept_info['demonstration']()
                # S'assurer que le résultat contient les bonnes clés
                demo_result['name'] = concept_info['name']
                demo_result['chapter'] = concept_info['chapter']
                demo_result['description'] = concept_info['description']
                results[concept_key] = demo_result
            except Exception as e:
                print(f"❌ Erreur dans la démonstration {concept_key}: {e}")
                results[concept_key] = {
                    'name': concept_info['name'],
                    'chapter': concept_info['chapter'],
                    'description': concept_info['description'],
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def _demo_confidentialite(self):
        """Démonstration chiffrement/déchiffrement"""
        original = "Message secret pour la démo confidentialité"
        encrypted = self.encrypt_data(original)
        decrypted = self.decrypt_data(encrypted)
        
        return {
            'original': original,
            'encrypted': encrypted[:50] + '...' if encrypted else None,
            'decrypted': decrypted,
            'success': decrypted == original,
            'explanation': 'Chiffrement RSA assure que seul le détenteur de la clé privée peut déchiffrer'
        }
    
    def _demo_integrite(self):
        """Démonstration intégrité via hachage"""
        original = "Document important"
        modified = "Document important!"  # Un caractère changé
        
        hash_original = self.hash_manager.compute_hash(original)
        hash_modified = self.hash_manager.compute_hash(modified)
        
        return {
            'original': f"{original} → {hash_original}",
            'modified': f"{modified} → {hash_modified}",
            'hashes_different': hash_original != hash_modified,
            'explanation': 'Un changement minime change complètement le hash, détectant toute modification'
        }
    
    def _demo_authenticite(self):
        """Démonstration authenticité via signature"""
        document = "Contrat authentique"
        signature = self.sign_data(document)
        verification = self.verify_signature(document, signature) if signature else False
        
        return {
            'document': document,
            'signature_created': signature is not None,
            'verification_result': verification,
            'explanation': 'La signature prouve que le document vient bien du détenteur de la clé privée'
        }
    
    def _demo_non_repudiation(self):
        """Démonstration non-répudiation"""
        message = "Je m\'engage à payer 1000€"
        signature = self.sign_data(message)
        
        # Simulation: la personne ne peut nier avoir signé
        could_deny = not self.verify_signature(message, signature) if signature else True
        
        return {
            'engagement': message,
            'signature_exists': signature is not None,
            'can_deny': could_deny,
            'explanation': 'La signature avec clé privée HSM empêche de nier l\'engagement'
        }