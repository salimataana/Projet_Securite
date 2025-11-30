import pkcs11
from pkcs11 import KeyType, Mechanism, Attribute, ObjectClass
import os
from database import KeyDatabase


class HSMManager:
    """
    Gestionnaire pour interagir avec le HSM (Hardware Security Module)
    Version améliorée avec stockage en base de données
    """

    def __init__(self):
        self.lib_path = '/usr/lib/softhsm/libsofthsm2.so'
        self.session = None
        os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'
        self.db = KeyDatabase()

    def connect(self, pin='1234'):
        """Établir une connexion sécurisée avec le HSM"""
        try:
            lib = pkcs11.lib(self.lib_path)
            token = lib.get_token(token_label='MonHSM')
            self.session = token.open(user_pin=pin, rw=True)
            print("✅ HSM connecté")
            self._sync_keys_with_db()
            return self.session
        except Exception as e:
            print(f"❌ Erreur connexion: {e}")
            return None

    def _sync_keys_with_db(self):
        """Synchroniser les clés HSM avec la base de données"""
        try:
            public_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY
            }))

            private_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY
            }))

            print(f"🔍 Synchronisation: {len(public_keys)} clés publiques, {len(private_keys)} clés privées trouvées")

            for pub_key in public_keys:
                try:
                    label = pub_key[Attribute.LABEL]
                    key_type = "RSA"
                    key_size = pub_key[Attribute.MODULUS_BITS] if Attribute.MODULUS_BITS in pub_key else 2048
                    # CORRECTION : Désactiver les anciennes clés par défaut
                    self.db.add_key(label, key_type, key_size, f"RSA_{key_size}bits", is_active=False)
                except Exception as e:
                    print(f"⚠️  Erreur sync clé: {e}")

        except Exception as e:
            print(f"❌ Erreur synchronisation: {e}")

    def generate_key_pair(self, key_label=None):
        """Générer une paire de clés RSA 2048 bits dans le HSM"""
        try:
            if not self.session:
                self.connect('1234')

            if not key_label:
                key_label = f"key_{len(self.get_all_keys()) + 1}"

            public_key, private_key = self.session.generate_keypair(
                KeyType.RSA,
                2048,
                label=key_label,
                store=True
            )

            # CORRECTION : Nouvelle clé désactivée par défaut
            self.db.add_key(key_label, "RSA", 2048, f"RSA_2048bits", is_active=False)
            print(f"✅ Clés générées avec label: {key_label}")
            return public_key, private_key

        except Exception as e:
            print(f"❌ Erreur génération: {e}")
            return None, None

    def get_all_keys(self):
        """Récupérer la liste de toutes les clés"""
        return self.db.get_all_keys()

    def get_active_keys(self):
        """Récupérer uniquement les clés actives"""
        return self.db.get_active_keys()

    def activate_key(self, key_label):
        """Activer une clé spécifique"""
        try:
            success = self.db.update_key_status(key_label, True)
            if success:
                print(f"✅ Clé '{key_label}' activée")
            else:
                print(f"❌ Erreur activation clé '{key_label}'")
            return success
        except Exception as e:
            print(f"❌ Erreur activation: {e}")
            return False

    def deactivate_key(self, key_label):
        """Désactiver une clé spécifique"""
        try:
            success = self.db.update_key_status(key_label, False)
            if success:
                print(f"✅ Clé '{key_label}' désactivée")
            else:
                print(f"❌ Erreur désactivation clé '{key_label}'")
            return success
        except Exception as e:
            print(f"❌ Erreur désactivation: {e}")
            return False

    def sign_data(self, data, key_label=None):
        """Signer des données avec une clé spécifique"""
        try:
            if not self.session:
                self.connect('1234')

            private_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY
            }))

            if not private_keys:
                print("❌ Aucune clé privée trouvée")
                return None

            if key_label:
                for priv_key in private_keys:
                    if hasattr(priv_key, 'label') and priv_key.label == key_label:
                        private_key = priv_key
                        break
                else:
                    print(f"❌ Clé '{key_label}' non trouvée")
                    return None
            else:
                private_key = private_keys[0]
                key_label = getattr(private_key, 'label', 'default')

            # CORRECTION : Vérifier si la clé est active
            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                print(f"❌ Clé '{key_label}' n'est pas active")
                return None

            signature = private_key.sign(
                data.encode('utf-8'),
                mechanism=Mechanism.RSA_PKCS
            )

            self.db.log_operation(key_label, "SIGNATURE", len(data), True)
            self.db.update_key_usage(key_label)
            print(f"✅ Signature réussie avec clé: {key_label}")
            return signature.hex()

        except Exception as e:
            print(f"❌ Erreur signature: {e}")
            if key_label:
                self.db.log_operation(key_label, "SIGNATURE", len(data), False)
            return None

    def verify_signature(self, data, signature, key_label=None):
        """Vérifier une signature avec une clé spécifique"""
        try:
            if not self.session:
                self.connect('1234')

            public_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY
            }))

            if not public_keys:
                print("❌ Aucune clé publique trouvée")
                return False

            # CORRECTION : Toujours utiliser la clé spécifiée
            if key_label:
                key_found = False
                for pub_key in public_keys:
                    if hasattr(pub_key, 'label') and pub_key.label == key_label:
                        public_key = pub_key
                        key_found = True
                        break

                if not key_found:
                    print(f"❌ Clé publique '{key_label}' non trouvée pour vérification")
                    return False
            else:
                public_key = public_keys[0]
                key_label = getattr(public_key, 'label', 'default')
                print(f"🔑 Utilisation de la clé par défaut: {key_label}")

            # CORRECTION : Vérifier si la clé est active
            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                print(f"❌ Clé '{key_label}' n'est pas active")
                return False

            signature_bytes = bytes.fromhex(signature)

            # CORRECTION : Capturer l'exception de vérification
            try:
                public_key.verify(
                    data.encode('utf-8'),
                    signature_bytes,
                    mechanism=Mechanism.RSA_PKCS
                )
                # Si on arrive ici, la signature est VALIDE
                self.db.log_operation(key_label, "VERIFICATION", len(data), True)
                self.db.update_key_usage(key_label)
                print(f"✅ Signature VALIDE avec clé: {key_label}")
                return True

            except Exception as verify_error:
                # Signature INVALIDE
                print(f"❌ Signature INVALIDE avec clé {key_label}: {verify_error}")
                self.db.log_operation(key_label, "VERIFICATION", len(data), False)
                return False

        except Exception as e:
            print(f"❌ Erreur vérification: {e}")
            if key_label:
                self.db.log_operation(key_label, "VERIFICATION", len(data), False)
            return False

    def encrypt_data(self, data, key_label=None):
        """Chiffrer des données avec une clé spécifique"""
        try:
            if not self.session:
                self.connect('1234')

            public_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY
            }))

            if not public_keys:
                print("❌ Aucune clé publique trouvée")
                return None

            if key_label:
                for pub_key in public_keys:
                    if hasattr(pub_key, 'label') and pub_key.label == key_label:
                        public_key = pub_key
                        break
                else:
                    print(f"❌ Clé '{key_label}' non trouvée")
                    return None
            else:
                public_key = public_keys[0]
                key_label = getattr(public_key, 'label', 'default')

            # CORRECTION : Vérifier si la clé est active
            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                print(f"❌ Clé '{key_label}' n'est pas active")
                return None

            encrypted_data = public_key.encrypt(
                data.encode('utf-8'),
                mechanism=Mechanism.RSA_PKCS
            )

            self.db.log_operation(key_label, "ENCRYPTION", len(data), True)
            self.db.update_key_usage(key_label)
            print(f"✅ Chiffrement réussi avec clé: {key_label}")
            return encrypted_data.hex()

        except Exception as e:
            print(f"❌ Erreur chiffrement: {e}")
            if key_label:
                self.db.log_operation(key_label, "ENCRYPTION", len(data), False)
            return None

    def decrypt_data(self, encrypted_data_hex, key_label=None):
        """Déchiffrer des données avec une clé spécifique"""
        try:
            if not self.session:
                self.connect('1234')

            private_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY
            }))

            if not private_keys:
                print("❌ Aucune clé privée trouvée")
                return None

            if key_label:
                for priv_key in private_keys:
                    if hasattr(priv_key, 'label') and priv_key.label == key_label:
                        private_key = priv_key
                        break
                else:
                    print(f"❌ Clé '{key_label}' non trouvée")
                    return None
            else:
                private_key = private_keys[0]
                key_label = getattr(private_key, 'label', 'default')

            # CORRECTION : Vérifier si la clé est active
            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                print(f"❌ Clé '{key_label}' n'est pas active")
                return None

            encrypted_data = bytes.fromhex(encrypted_data_hex)
            decrypted_data = private_key.decrypt(
                encrypted_data,
                mechanism=Mechanism.RSA_PKCS
            )

            # Essayer de décoder en UTF-8, sinon retourner en hexadécimal
            try:
                result = decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                # Si ce n'est pas du texte UTF-8, retourner en hexadécimal
                result = decrypted_data.hex()
                print("⚠️  Données déchiffrées non-UTF8, retour en hexadécimal")

            self.db.log_operation(key_label, "DECRYPTION", len(encrypted_data_hex), True)
            self.db.update_key_usage(key_label)
            print(f"✅ Déchiffrement réussi avec clé: {key_label}")
            return result

        except Exception as e:
            print(f"❌ Erreur déchiffrement: {e}")
            if key_label:
                self.db.log_operation(key_label, "DECRYPTION", len(encrypted_data_hex), False)
            return None

    def debug_keys(self):
        """Afficher des informations de débogage sur les clés"""
        print("\n=== DEBUG HSM KEYS ===")

        if self.session:
            public_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY
            }))
            private_keys = list(self.session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY
            }))
            print(f"HSM - Clés publiques: {len(public_keys)}, Clés privées: {len(private_keys)}")

            for key in public_keys + private_keys:
                try:
                    label = getattr(key, 'label', 'N/A')
                    print(f"  - {label}")
                except:
                    pass

        db_keys = self.db.get_all_keys()
        print(f"DB - Clés enregistrées: {len(db_keys)}")
        for key in db_keys:
            print(f"  - {key['label']} ({key['type']}_{key['size']}bits) - Actif: {key.get('is_active', False)}")