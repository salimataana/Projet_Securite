import json

import pkcs11
from pkcs11 import KeyType, Mechanism
import os
import time

from core.hash_manager import HashManager
from utils.singleton_metaclass import SingletonMeta


class HSMManager(metaclass=SingletonMeta):
    """
    Gestionnaire pour interagir avec le HSM (Hardware Security Module)
    Cette classe permet de réaliser des opérations cryptographiques sécurisées
    """

    def __init__(self):
        self.lib_path = os.environ['lib_path']
        self.session = None
        self.pin = os.environ['pin']
        self.token_label = os.environ['token_label']
        self.database = None
        self.hash_manager = HashManager()

    def _resolve_key_type(self, key_type):
        if key_type == "AES":
            print("je suis la")
            return KeyType.AES
        if isinstance(key_type, KeyType):
            return key_type
        if isinstance(key_type, str):
            normalized = key_type.strip().upper()
            if normalized in ('RSA', 'RSA_PKCS'):
                return KeyType.RSA
            if normalized in ('EC', 'ECC', 'ECDSA') and hasattr(KeyType, 'EC'):
                return getattr(KeyType, 'EC')
        return KeyType.RSA

    def _sanitize_label(self, key_label, fallback):
        if isinstance(key_label, str):
            cleaned = key_label.strip()
            if cleaned:
                return cleaned
        return fallback

    def connect(self):
        """
        Établir une connexion sécurisée avec le HSM

        Args:
            pin (str): Code PIN pour accéder au token HSM

        Returns:
            object: Session HSM ouverte ou None en cas d'erreur
        """
        try:
            lib = pkcs11.lib(self.lib_path)
            token = lib.get_token(token_label=self.token_label)
            self.session = token.open(user_pin=self.pin, rw=True)
            print("HSM connecté")
            return self.session
        except Exception as e:
            print(f"Erreur connexion: {e}")
            return None

    def generate_key_pair(self, key_type=KeyType.RSA, key_size=None, key_label=None):
        """
        Générer une paire de clés RSA 2048 bits dans le HSM

        Returns:
            tuple: (clé_publique, clé_privée) ou (None, None) en cas d'erreur
        """
        try:
            resolved_type = self._resolve_key_type(key_type)
            resolved_size = int(key_size) if key_size is not None else int(os.environ.get("key_size", 2048))
            label = self._sanitize_label(key_label, f"{resolved_type.name.lower()}_key_{int(time.time())}")
            if not self.session:
                self.connect()
            public_key, private_key = self.session.generate_keypair(
                key_type=resolved_type,
                key_length=resolved_size,
                label=label,
                store=True
            )
            print("Clés générées et conservées dans le HSM, label : {}".format(label))
            return public_key, private_key
        except Exception as e:
            print(f"Erreur génération: {e}")
            return None, None

    def debug_keys(self):
        """
        Méthode de débogage pour lister toutes les clés présentes dans le HSM
        """
        try:
            if not self.session:
                self.connect()

            print("=== DÉBOGAGE DES CLÉS HSM ===")

            # Lister les clés privées
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))
            print(f"{len(private_keys)} clé(s) privée(s) trouvée(s)")

            # Lister les clés publiques
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))
            print(f"{len(public_keys)} clé(s) publique(s) trouvée(s)")

            # Afficher les détails des clés
            for i, key in enumerate(public_keys + private_keys):
                try:
                    key_type = "PUBLIQUE" if key.object_class == pkcs11.ObjectClass.PUBLIC_KEY else "PRIVÉE"
                    label = getattr(key, 'label', 'Sans label')
                    print(f"  {i + 1}. {key_type} - Label: {label}")
                except:
                    print(f"  {i + 1}. Clé (détails indisponibles)")

            print("=== FIN DÉBOGAGE ===")

        except Exception as e:
            print(f"Erreur débogage: {e}")

    def sign_data(self, data, label_key, mechanism=Mechanism.RSA_PKCS):
        """
        Signer des données avec la clé privée du HSM

        Args:
            data (str): Données à signer

        Returns:
            str: Signature en hexadécimal ou None en cas d'erreur
        """
        try:
            # Vérifier la connexion HSM
            if not self.session:
                self.connect()
            # Rechercher toutes les clés privées disponibles
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                pkcs11.Attribute.LABEL: label_key
            }))
            # Vérifier qu'au moins une clé privée existe
            if not private_keys:
                print("Aucune clé trouvée")
                return None

            # Prendre la première clé privée disponible
            private_key = private_keys[0]
            print("Clé trouvée, signature en cours...")

            # Créer la signature avec l'algorithme RSA-PKCS
            start_time = time.time()
            signature = private_key.sign(
                data.encode('utf-8'),
                mechanism=mechanism
            )
            end_time = time.time()

            duration = end_time - start_time

            self.write_to_json({"algorithm": mechanism,
                                "data_lenth": len(data),
                                "duration": duration,
                                "operation_type": "sign_data",
                                })
            print("Signature réussie")
            # Retourner la signature en format hexadécimal (plus facile à transmettre)
            return signature.hex()

        except Exception as e:
            print(f"Erreur signature: {e}")
            return None

    def verify_signature(self, data, signature, label_key,mechanism=Mechanism.RSA_PKCS):
        """
        Vérifier une signature avec la clé publique correspondante

        Args:
            data (str): Données originales qui ont été signées
            signature (str): Signature à vérifier (en hexadécimal)

        Returns:
            bool: True si la signature est valide, False sinon
        """
        try:
            print(f"Vérification de signature pour: '{data}'")
            print(f"Longueur signature: {len(signature)} caractères")

            if not self.session:
                self.connect()

            # Rechercher les clés publiques disponibles
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
                pkcs11.Attribute.LABEL: label_key
            }))

            print(f"{len(public_keys)} clé(s) publique(s) trouvée(s)")

            if not public_keys:
                print("Aucune clé publique trouvée")
                return False

            # Prendre la première clé publique disponible
            public_key = public_keys[0]
            key_label = getattr(public_key, 'label', 'Inconnu')
            print(f"Utilisation de la clé: {key_label}")

            # Convertir la signature d'hexadécimal vers bytes
            print("Conversion signature hex → bytes...")
            signature_bytes = bytes.fromhex(signature)
            print(f"Signature bytes: {len(signature_bytes)} bytes")

            # Vérifier la signature avec la clé publique
            print("Tentative de vérification...")
            statut= public_key.verify(
                data.encode('utf-8'),  # Données originales
                signature_bytes,  # Signature à vérifier
                mechanism=mechanism  # Même mécanisme que pour la signature
            )
            return statut

        except Exception as e:
            print(f"ERREUR vérification: {e}")
            import traceback
            traceback.print_exc()
            return False

    def encrypt_data(self, data, label_key, mechanism=Mechanism.RSA_PKCS):
        """Chiffrer des données avec une clé publique spécifique"""
        try:
            print(f"Tentative de chiffrement: '{data}'")

            if not self.session:
                self.connect()

            print(f"Je suis connecté {label_key}")
            # Rechercher les clés publiques
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
                pkcs11.Attribute.LABEL: label_key
            }))
            print("J'ai trouvé la clé")


            if not public_keys:
                print("Aucune clé publique trouvée")
                return None

            public_key = public_keys[0]
            print(f" Clé publique trouvée: {label_key}")

            # Convertir les données en bytes
            data_bytes = data.encode('utf-8')

            # Vérifier la taille des données (RSA 2048 bits = 245 bytes max)
            max_size = 245  # Pour RSA 2048 avec padding PKCS
            if len(data_bytes) > max_size:
                print(f" Données trop longues ({len(data_bytes)} > {max_size} bytes), tronquage automatique")
                data_bytes = data_bytes[:max_size]

            start_time = time.time()
            # Chiffrer les données avec RSA
            encrypted_data = public_key.encrypt(
                data_bytes,  # Données à chiffrer
                mechanism=mechanism # Mécanisme de chiffrement
            )
            end_time = time.time()
            print(" Données chiffrées avec succès")
            # Retourner les données chiffrées en hexadécimal

            duration = end_time - start_time


            self.write_to_json({"algorithm": public_key.key_type.name,
                                "data_lenth": len(data),
                                "duration": duration,
                                "operation_type": "encrypt_data"
                                })

            return encrypted_data.hex()

        except Exception as e:
            print(f" Erreur chiffrement: {e}")
            import traceback
            traceback.print_exc()
            return None

    def decrypt_data(self, encrypted_data_hex, label_key=None):
        """Déchiffrer des données avec une clé privée spécifique"""
        try:
            print(f"Tentative de déchiffrement")

            if not self.session:
                self.connect()

            # Rechercher les clés privées
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                pkcs11.Attribute.LABEL: label_key
            }))

            if not private_keys:
                print(" Aucune clé privée trouvée")
                return None

            private_key = private_keys[0]

            print(f"Clé privée trouvée: {label_key}")
            # Convertir les données chiffrées d'hexadécimal vers bytes
            encrypted_data = bytes.fromhex(encrypted_data_hex)

            # Déchiffrer les données avec la clé privée
            start_time = time.time()
            decrypted_data = private_key.decrypt(
                encrypted_data,  # Données chiffrées
                mechanism=Mechanism.RSA_PKCS  # Même mécanisme que pour le chiffrement
            )
            end_time = time.time()

            duration = end_time - start_time

            self.write_to_json({"data_lenth": len(encrypted_data_hex),
                                "duration": duration,
                                "operation_type": "decrypt_data"
                                })
            # Essayer de décoder en UTF-8, sinon retourner en hexadécimal
            try:

                result = decrypted_data.decode('utf-8')
                print(f" Données déchiffrées (UTF-8): '{result}'")

            except UnicodeDecodeError:
                # Si ce n'est pas du UTF-8 valide, retourner en hexadécimal
                result = decrypted_data.hex()
                print(f" Données déchiffrées (hexadécimal): {result[:50]}...")


            return result

        except Exception as e:
            print(f" Erreur déchiffrement: {e}")
            import traceback
            traceback.print_exc()
            return None

    def generate_key_pair_with_storage(self, key_size=2048, key_type='RSA', key_label=None):
        """Génère une paire de clés et retourne leurs métadonnées"""
        try:
            resolved_type = self._resolve_key_type(key_type)
            label = self._sanitize_label(key_label, f"{resolved_type.name.lower()}_key_{int(time.time())}")
            start_time = time.time()
            public_key, private_key = self.generate_key_pair(resolved_type, key_size, label)
            end_time = time.time()

            if public_key and private_key:
                stored_in_db = False
                if getattr(self, 'database', None):
                    try:
                        stored_in_db = bool(self.database.add_key(
                            key_id=label,
                            key_type=resolved_type.name,
                            key_size=int(key_size),
                            public_key=str(public_key)
                        ))
                    except Exception as db_error:
                        print(f"Erreur stockage base: {db_error}")

                return {
                    'success': True,
                    'key_id': label,
                    'key_label': label,
                    'key_type': resolved_type.name,
                    'key_size': int(key_size),
                    'processing_time': f"{(end_time - start_time) * 1000:.2f} ms",
                    'stored_in_db': stored_in_db
                }

            return {'success': False, 'error': 'Échec de la génération des clés dans le HSM'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_all_keys_public(self):
        if not self.session:
            self.connect()
        public_keys = list(self.session.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
        }))

        return [{"label": key.label, "key_id": key.id} for key in public_keys]

    def get_all_keys_private(self):
        if not self.session:
            self.connect()
        public_keys = list(self.session.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        }))

        return [{"label": key.label, "key_id": key.id} for key in public_keys]


    def hash_and_sign(self, data, hash_algorithm='sha256', key_label=None):
        """Hachage + Signature avec tracking"""
        try:
            start_hash = time.time()
            data_hash = self.hash_manager.compute_hash(data, hash_algorithm)
            hash_time = time.time() - start_hash

            start_sign = time.time()
            signature = self.sign_data(data_hash, key_label)
            sign_time = time.time() - start_sign
            data={
                    'success': True,
                    'hash': data_hash,
                    'signature': signature,
                    'hash_algorithm': hash_algorithm,
                    'key_label': key_label,
                    'performance': {
                        'hash_time': f"{hash_time * 1000:.2f} ms",
                        'sign_time': f"{sign_time * 1000:.2f} ms",
                        'total_time': f"{(hash_time + sign_time) * 1000:.2f} ms"
                    },
                    'concept': "Intégrité (hachage) + Authenticité (signature) - Chapitres 8 et 9"
            }
            return data["hash"]
        except Exception as e:
            return {'success': False, 'error': str(e)}


    def verify_hash_signature(self, data, signature, label_key,hash_algorithm,mechanism=Mechanism.RSA_PKCS):

        expected_hash = self.hash_manager.compute_hash(data, hash_algorithm)
        is_valid = self.verify_signature(expected_hash, signature,label_key=label_key)  # On vérifie la signature du hash
        return is_valid


    def write_to_json(self, data):
        with open(os.environ["data_file"], 'r+') as file:
            file_data = json.load(file)
            print(file_data)
            file_data["database"]["performances"].append(data)
            file.seek(0)
            json.dump(file_data, file, indent=4)
