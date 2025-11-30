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

            print(f"🔍 Synchronisation: {len(public_keys)} clés publiques trouvées")

            for pub_key in public_keys:
                try:
                    label = pub_key[Attribute.LABEL]
                    key_type = "RSA"
                    key_size = pub_key[Attribute.MODULUS_BITS] if Attribute.MODULUS_BITS in pub_key else 2048
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

            self.db.add_key(key_label, "RSA", 2048, f"RSA_2048bits", is_active=False)
            print(f"✅ Clés générées avec label: {key_label}")
            return public_key, private_key

        except Exception as e:
            print(f"❌ Erreur génération: {e}")
            return None, None

    def get_all_keys(self):
        return self.db.get_all_keys()

    def get_active_keys(self):
        return self.db.get_active_keys()

    def activate_key(self, key_label):
        return self.db.update_key_status(key_label, True)

    def deactivate_key(self, key_label):
        return self.db.update_key_status(key_label, False)

    def _get_private_key(self, key_label=None):
        """Récupérer une clé privée spécifique ou par défaut"""
        private_keys = list(self.session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))

        if not private_keys:
            print("❌ Aucune clé privée trouvée")
            return None, None

        if key_label:
            for priv_key in private_keys:
                if getattr(priv_key, 'label', None) == key_label:
                    return priv_key, key_label
            print(f"❌ Clé '{key_label}' non trouvée")
            return None, None
        else:
            default_key = private_keys[0]
            key_label = getattr(default_key, 'label', 'default')
            return default_key, key_label

    def _get_public_key(self, key_label=None):
        """Récupérer une clé publique spécifique ou par défaut"""
        public_keys = list(self.session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}))

        if not public_keys:
            print("❌ Aucune clé publique trouvée")
            return None, None

        if key_label:
            for pub_key in public_keys:
                if getattr(pub_key, 'label', None) == key_label:
                    return pub_key, key_label
            print(f"❌ Clé publique '{key_label}' non trouvée")
            return None, None
        else:
            default_key = public_keys[0]
            key_label = getattr(default_key, 'label', 'default')
            return default_key, key_label

    def sign_data(self, data, key_label=None):
        try:
            if not self.session:
                self.connect('1234')

            private_key, key_label = self._get_private_key(key_label)
            if not private_key:
                return None

            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                print(f"❌ Clé '{key_label}' n'est pas active")
                return None

            signature = private_key.sign(data.encode('utf-8'), mechanism=Mechanism.RSA_PKCS)
            self.db.log_operation(key_label, "SIGNATURE", len(data), True)
            self.db.update_key_usage(key_label)
            return signature.hex()
        except Exception as e:
            print(f"❌ Erreur signature: {e}")
            if key_label:
                self.db.log_operation(key_label, "SIGNATURE", len(data), False)
            return None

    def verify_signature(self, data, signature, key_label=None):
        try:
            if not self.session:
                self.connect('1234')

            public_key, key_label = self._get_public_key(key_label)
            if not public_key:
                return False

            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                print(f"❌ Clé '{key_label}' n'est pas active")
                return False

            try:
                public_key.verify(data.encode('utf-8'), bytes.fromhex(signature), mechanism=Mechanism.RSA_PKCS)
                self.db.log_operation(key_label, "VERIFICATION", len(data), True)
                self.db.update_key_usage(key_label)
                return True
            except:
                self.db.log_operation(key_label, "VERIFICATION", len(data), False)
                return False

        except Exception as e:
            print(f"❌ Erreur vérification: {e}")
            return False

    def encrypt_data(self, data, key_label=None):
        try:
            if not self.session:
                self.connect('1234')

            public_key, key_label = self._get_public_key(key_label)
            if not public_key:
                return None

            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                return None

            encrypted = public_key.encrypt(data.encode('utf-8'), mechanism=Mechanism.RSA_PKCS)
            self.db.log_operation(key_label, "ENCRYPTION", len(data), True)
            self.db.update_key_usage(key_label)
            return encrypted.hex()
        except Exception as e:
            print(f"❌ Erreur chiffrement: {e}")
            return None

    def decrypt_data(self, encrypted_hex, key_label=None):
        try:
            if not self.session:
                self.connect('1234')

            private_key, key_label = self._get_private_key(key_label)
            if not private_key:
                return None

            key_info = self.db.get_key(key_label)
            if not key_info or not key_info.get('is_active', False):
                return None

            decrypted = private_key.decrypt(bytes.fromhex(encrypted_hex), mechanism=Mechanism.RSA_PKCS)
            try:
                result = decrypted.decode('utf-8')
            except:
                result = decrypted.hex()
            self.db.log_operation(key_label, "DECRYPTION", len(encrypted_hex), True)
            self.db.update_key_usage(key_label)
            return result
        except Exception as e:
            print(f"❌ Erreur déchiffrement: {e}")
            return None

    def debug_keys(self):
        print("\n=== DEBUG HSM KEYS ===")
        if self.session:
            public_keys = list(self.session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}))
            private_keys = list(self.session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
            print(f"HSM - Pub: {len(public_keys)}, Priv: {len(private_keys)}")
            for k in public_keys + private_keys:
                print(f" - {getattr(k, 'label', 'N/A')}")
        db_keys = self.db.get_all_keys()
        print(f"DB - Clés: {len(db_keys)}")
        for k in db_keys:
            print(f" - {k['label']} (Actif: {k.get('is_active', False)})")
