from hsm_manager import HSMManager
from hash_manager import HashManager
import pkcs11
from pkcs11 import Mechanism
import time
import base64


class ExtendedHSMManager(HSMManager):
    """
    Extension du gestionnaire HSM avec les fonctionnalités avancées
    Couvre les chapitres 8 et 9 : Hachage et Signature
    """

    def __init__(self):
        super().__init__()
        self.hash_manager = HashManager()
        self.database = None

    def set_database(self, database):
        """Injecte la base de données"""
        self.database = database

    def _convert_public_key_to_string(self, public_key):
        """
        Convertit la clé publique en format string pour le stockage
        Version améliorée pour les objets PKCS11
        """
        try:
            if public_key is None:
                return "Clé publique non disponible"

            # Si c'est déjà une string
            if isinstance(public_key, str):
                return public_key

            # Si c'est un objet PKCS11 PublicKey, on extrait les informations importantes
            if hasattr(public_key, '__class__') and 'PublicKey' in str(public_key.__class__):
                key_info = {
                    'type': 'RSA PublicKey (PKCS11)',
                    'key_size': getattr(public_key, 'key_size', 'Inconnu'),
                    'label': getattr(public_key, 'label', 'Sans label'),
                    'id': getattr(public_key, 'id', 'Sans ID')
                }
                return f"PKCS11_PublicKey:{key_info['label']}_{key_info['key_size']}bits"

            # Si c'est des bytes, on encode en base64
            if isinstance(public_key, bytes):
                b64_key = base64.b64encode(public_key).decode('utf-8')
                return f"base64:{b64_key[:100]}..."  # Premiers 100 caractères

            # Fallback: conversion en string
            return f"PublicKey_object:{str(public_key)[:200]}"

        except Exception as e:
            print(f"⚠️ Erreur conversion clé publique: {e}")
            return f"Erreur_conversion:{str(e)}"

    def generate_key_pair_with_storage(self, key_size=2048):
        """Génère une paire de clés et les stocke en base"""
        try:
            print(f"🔑 Début génération clé {key_size} bits...")
            start_time = time.time()
            public_key, private_key = self.generate_key_pair()
            end_time = time.time()

            if public_key and private_key:
                # Génère un ID unique pour la clé
                key_id = f"rsa_key_{int(time.time())}_{key_size}"

                # DEBUG: Afficher le type de la clé publique
                print(f"🔍 DEBUG - Type public_key: {type(public_key)}")
                print(f"🔍 DEBUG - Repr public_key: {repr(public_key)}")

                # Convertit la clé publique en format stockable
                public_key_str = self._convert_public_key_to_string(public_key)
                print(f"✅ Clé publique convertie: {public_key_str[:100]}...")

                # Stocke en base de données si disponible
                stored_in_db = False
                if self.database:
                    success = self.database.add_key(
                        key_id=key_id,
                        key_type='RSA',
                        key_size=key_size,
                        public_key=public_key_str
                    )

                    if success:
                        # Enregistre l'opération
                        self.database.record_operation(
                            key_id=key_id,
                            operation_type='key_generation',
                            data_hash="N/A pour génération de clé",
                            signature="N/A pour génération de clé",
                            processing_time=(end_time - start_time) * 1000,
                            success=True
                        )
                        stored_in_db = True
                        print(f"✅ Clé {key_id} stockée en base de données")
                    else:
                        print("❌ Échec du stockage en base de données")
                else:
                    print("⚠️ Base de données non disponible")

                return {
                    'success': True,
                    'key_id': key_id,
                    'public_key': public_key_str,
                    'key_size': key_size,
                    'processing_time': f"{(end_time - start_time) * 1000:.2f} ms",
                    'stored_in_db': stored_in_db
                }
            else:
                error_msg = 'Échec de la génération des clés dans le HSM'
                print(f"❌ {error_msg}")
                return {'success': False, 'error': error_msg}

        except Exception as e:
            error_msg = f"Erreur lors de la génération avec stockage: {str(e)}"
            print(f"❌ {error_msg}")
            return {'success': False, 'error': error_msg}

    def sign_data_with_tracking(self, data, key_id=None):
        """Signe des données avec tracking en base"""
        try:
            start_time = time.time()
            signature = self.sign_data(data)
            end_time = time.time()

            if signature and key_id and self.database:
                # Calcule le hash des données pour le tracking
                data_hash = self.hash_manager.compute_hash(data, 'sha256')

                # Enregistre l'opération
                self.database.record_operation(
                    key_id=key_id,
                    operation_type='signature',
                    data_hash=data_hash,
                    signature=signature[:100] + '...' if len(signature) > 100 else signature,
                    processing_time=(end_time - start_time) * 1000,
                    success=True
                )
                print(f"✅ Signature tracée pour la clé {key_id}")

            return signature

        except Exception as e:
            print(f"⚠️ Erreur tracking signature: {e}")
            return self.sign_data(data)

    def encrypt_data_with_tracking(self, data, key_id=None):
        """Chiffre des données avec tracking en base"""
        try:
            start_time = time.time()
            encrypted_data = self.encrypt_data(data)
            end_time = time.time()

            if encrypted_data and key_id and self.database:
                # Enregistre l'opération
                self.database.record_operation(
                    key_id=key_id,
                    operation_type='encryption',
                    data_hash=self.hash_manager.compute_hash(data, 'sha256'),
                    signature="N/A pour chiffrement",
                    processing_time=(end_time - start_time) * 1000,
                    success=True
                )
                print(f"✅ Chiffrement tracé pour la clé {key_id}")

            return encrypted_data

        except Exception as e:
            print(f"⚠️ Erreur tracking chiffrement: {e}")
            return self.encrypt_data(data)

    def decrypt_data_with_tracking(self, encrypted_data, key_id=None):
        """Déchiffre des données avec tracking en base"""
        try:
            start_time = time.time()
            decrypted_data = self.decrypt_data(encrypted_data)
            end_time = time.time()

            if decrypted_data and key_id and self.database:
                # Enregistre l'opération
                self.database.record_operation(
                    key_id=key_id,
                    operation_type='decryption',
                    data_hash=self.hash_manager.compute_hash(decrypted_data, 'sha256'),
                    signature="N/A pour déchiffrement",
                    processing_time=(end_time - start_time) * 1000,
                    success=True
                )
                print(f"✅ Déchiffrement tracé pour la clé {key_id}")

            return decrypted_data

        except Exception as e:
            print(f"⚠️ Erreur tracking déchiffrement: {e}")
            return self.decrypt_data(encrypted_data)

    def hash_and_sign(self, data, hash_algorithm='sha256', key_id=None):
        """Hachage + Signature avec tracking"""
        try:
            print(f"🔐 Hachage + Signature avec {hash_algorithm}...")

            # Étape 1: Hachage des données
            start_hash = time.time()
            data_hash = self.hash_manager.compute_hash(data, hash_algorithm)
            hash_time = time.time() - start_hash

            # Étape 2: Signature du hash
            start_sign = time.time()
            signature = self.sign_data(data_hash)
            sign_time = time.time() - start_sign

            if signature:
                # Tracking si key_id fourni
                if key_id and self.database:
                    self.database.record_operation(
                        key_id=key_id,
                        operation_type='hash_and_sign',
                        data_hash=data_hash,
                        signature=signature[:100] + '...' if len(signature) > 100 else signature,
                        processing_time=(hash_time + sign_time) * 1000,
                        success=True
                    )
                    print(f"✅ Hachage+Signature tracé pour la clé {key_id}")

                return {
                    'success': True,
                    'hash': data_hash,
                    'signature': signature,
                    'hash_algorithm': hash_algorithm,
                    'key_id': key_id,
                    'performance': {
                        'hash_time': f"{hash_time * 1000:.2f} ms",
                        'sign_time': f"{sign_time * 1000:.2f} ms",
                        'total_time': f"{(hash_time + sign_time) * 1000:.2f} ms"
                    },
                    'concept': "Intégrité (hachage) + Authenticité (signature) - Chapitres 8 et 9"
                }
            else:
                return {'success': False, 'error': 'Échec de la signature'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def verify_hash_and_signature(self, data, signature, expected_hash, hash_algorithm='sha256'):
        """
        Vérification complète hachage + signature
        Chapitre 8 + 9 : Vérification intégrité et authenticité
        """
        try:
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

        except Exception as e:
            return {'success': False, 'error': str(e)}

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
        try:
            original = "Message secret pour la démo confidentialité"
            encrypted = self.encrypt_data(original)
            decrypted = self.decrypt_data(encrypted) if encrypted else None

            return {
                'original': original,
                'encrypted': encrypted[:50] + '...' if encrypted and len(encrypted) > 50 else encrypted,
                'decrypted': decrypted,
                'success': decrypted == original,
                'explanation': 'Chiffrement RSA assure que seul le détenteur de la clé privée peut déchiffrer'
            }
        except Exception as e:
            return {
                'original': "Erreur lors de la démonstration",
                'encrypted': None,
                'decrypted': None,
                'success': False,
                'explanation': f'Erreur: {str(e)}'
            }

    def _demo_integrite(self):
        """Démonstration intégrité via hachage"""
        try:
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
        except Exception as e:
            return {
                'original': "Erreur lors de la démonstration",
                'modified': "Erreur lors de la démonstration",
                'hashes_different': False,
                'explanation': f'Erreur: {str(e)}'
            }

    def _demo_authenticite(self):
        """Démonstration authenticité via signature"""
        try:
            document = "Contrat authentique"
            signature = self.sign_data(document)
            verification = self.verify_signature(document, signature) if signature else False

            return {
                'document': document,
                'signature_created': signature is not None,
                'verification_result': verification,
                'explanation': 'La signature prouve que le document vient bien du détenteur de la clé privée'
            }
        except Exception as e:
            return {
                'document': "Erreur lors de la démonstration",
                'signature_created': False,
                'verification_result': False,
                'explanation': f'Erreur: {str(e)}'
            }

    def _demo_non_repudiation(self):
        """Démonstration non-répudiation"""
        try:
            message = "Je m'engage à payer 1000€"
            signature = self.sign_data(message)

            # Simulation: la personne ne peut nier avoir signé
            could_deny = not self.verify_signature(message, signature) if signature else True

            return {
                'engagement': message,
                'signature_exists': signature is not None,
                'can_deny': could_deny,
                'explanation': 'La signature avec clé privée HSM empêche de nier l\'engagement'
            }
        except Exception as e:
            return {
                'engagement': "Erreur lors de la démonstration",
                'signature_exists': False,
                'can_deny': True,
                'explanation': f'Erreur: {str(e)}'
            }

    def _convert_public_key_to_string(self, public_key):
        if hasattr(public_key, 'key_size'):
            return f"PKCS11_RSA_Key_{public_key.key_size}bits"
        else:
            return f"PKCS11_Key_{hash(public_key)}"

    def debug_keys(self):
        """
        Méthode de débogage pour lister toutes les clés présentes dans le HSM
        """
        try:
            if not self.session:
                self.connect('1234')

            print("=== DÉBOGAGE DES CLÉS HSM ===")

            # Lister les clés privées
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))
            print(f"🔑 {len(private_keys)} clé(s) privée(s) trouvée(s)")

            # Lister les clés publiques
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))
            print(f"🔐 {len(public_keys)} clé(s) publique(s) trouvée(s)")

            # Afficher les détails des clés
            for i, key in enumerate(public_keys + private_keys):
                try:
                    key_type = "PUBLIQUE" if key.object_class == pkcs11.ObjectClass.PUBLIC_KEY else "PRIVÉE"
                    label = getattr(key, 'label', 'Sans label')
                    key_size = getattr(key, 'key_size', 'Inconnu')
                    print(f"  {i + 1}. {key_type} - Label: {label} - Taille: {key_size} bits")
                except Exception as key_error:
                    print(f"  {i + 1}. Clé (détails indisponibles: {key_error})")

            print("=== FIN DÉBOGAGE ===")

        except Exception as e:
            print(f"❌ Erreur débogage: {e}")

    def get_key_statistics(self):
        """
        Récupère les statistiques des clés depuis la base de données
        """
        try:
            if self.database:
                return self.database.get_usage_statistics()
            else:
                return {
                    'total_keys': 0,
                    'active_keys': 0,
                    'total_operations': 0,
                    'successful_operations': 0,
                    'success_rate': "N/A",
                    'avg_processing_time': "N/A"
                }
        except Exception as e:
            print(f"❌ Erreur récupération statistiques: {e}")
            return {
                'total_keys': 0,
                'active_keys': 0,
                'total_operations': 0,
                'successful_operations': 0,
                'success_rate': "N/A",
                'avg_processing_time': "N/A"
            }