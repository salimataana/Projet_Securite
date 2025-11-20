import pkcs11
from pkcs11 import KeyType, Mechanism
import os


class HSMManager:
    def __init__(self):
        self.lib_path = '/usr/lib/softhsm/libsofthsm2.so'
        self.session = None
        os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'

    def connect(self, pin='1234'):
        try:
            lib = pkcs11.lib(self.lib_path)
            token = lib.get_token(token_label='MonHSM')
            self.session = token.open(user_pin=pin, rw=True)
            print("✅ HSM connecté")
            return self.session
        except Exception as e:
            print(f"❌ Erreur connexion: {e}")
            return None

    def generate_key_pair(self):
        try:
            if not self.session:
                self.connect('1234')

            # Nettoyer avant de générer
            self._clean_keys()

            # Générer UNE seule paire de clés
            public_key, private_key = self.session.generate_keypair(
                KeyType.RSA, 2048, label="main_key", store=True
            )
            print("✅ Clés générées")
            return public_key, private_key
        except Exception as e:
            print(f"❌ Erreur génération: {e}")
            return None, None

    def _clean_keys(self):
        """Supprimer toutes les clés existantes"""
        try:
            objects = list(self.session.get_objects())
            for obj in objects:
                try:
                    obj.destroy()
                except:
                    pass
            print("🧹 Anciennes clés nettoyées")
        except:
            pass

    def sign_data(self, data):
        try:
            if not self.session:
                self.connect('1234')

            # Prendre la première clé privée disponible
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))

            if not private_keys:
                print("❌ Aucune clé trouvée")
                return None

            private_key = private_keys[0]
            print("✅ Clé trouvée, signature en cours...")

            # Signature SIMPLE
            signature = private_key.sign(
                data.encode('utf-8'),
                mechanism=Mechanism.RSA_PKCS
            )

            print("✅ Signature réussie")
            return signature.hex()

        except Exception as e:
            print(f"❌ Erreur signature: {e}")
            return None

    def verify_signature(self, data, signature):
        """Vérifier une signature"""
        try:
            print(f"🔄 Vérification de signature pour: '{data}'")
            print(f"📏 Longueur signature: {len(signature)} caractères")

            if not self.session:
                print("❌ Session HSM non active - reconnexion...")
                self.connect('1234')
                if not self.session:
                    return False

            # Prendre la première clé publique disponible
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))

            print(f"🔍 {len(public_keys)} clé(s) publique(s) trouvée(s)")

            if not public_keys:
                print("❌ Aucune clé publique trouvée")
                return False

            public_key = public_keys[0]
            key_label = getattr(public_key, 'label', 'Inconnu')
            print(f"✅ Utilisation de la clé: {key_label}")

            # Conversion hex → bytes
            print("🔄 Conversion signature hex → bytes...")
            signature_bytes = bytes.fromhex(signature)
            print(f"📏 Signature bytes: {len(signature_bytes)} bytes")

            # Vérification
            print("🔐 Tentative de vérification...")
            public_key.verify(
                data.encode('utf-8'),
                signature_bytes,
                mechanism=Mechanism.RSA_PKCS
            )
            print("🎉 ✅ Signature VALIDE")
            return True

        except Exception as e:
            print(f"💥 ❌ ERREUR vérification: {e}")
            import traceback
            traceback.print_exc()
            return False

    def encrypt_data(self, data):
        """Chiffrer des données avec la clé publique"""
        try:
            print(f"🔒 Tentative de chiffrement: '{data}'")

            if not self.session:
                self.connect('1234')

            # Prendre la première clé publique disponible
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))

            if not public_keys:
                print("❌ Aucune clé publique trouvée pour le chiffrement")
                return None

            public_key = public_keys[0]
            key_label = getattr(public_key, 'label', 'Inconnu')
            print(f"✅ Clé publique trouvée: {key_label}")

            # Chiffrement RSA
            encrypted_data = public_key.encrypt(
                data.encode('utf-8'),
                mechanism=Mechanism.RSA_PKCS
            )

            print("✅ Données chiffrées avec succès")
            return encrypted_data.hex()

        except Exception as e:
            print(f"❌ Erreur chiffrement: {e}")
            import traceback
            traceback.print_exc()
            return None

    def decrypt_data(self, encrypted_data_hex):
        """Déchiffrer des données avec la clé privée"""
        try:
            print(f"🔓 Tentative de déchiffrement")

            if not self.session:
                self.connect('1234')

            # Prendre la première clé privée disponible
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))

            if not private_keys:
                print("❌ Aucune clé privée trouvée pour le déchiffrement")
                return None

            private_key = private_keys[0]
            key_label = getattr(private_key, 'label', 'Inconnu')
            print(f"✅ Clé privée trouvée: {key_label}")

            # Convertir hexadécimal → bytes
            encrypted_data = bytes.fromhex(encrypted_data_hex)

            # Déchiffrement RSA
            decrypted_data = private_key.decrypt(
                encrypted_data,
                mechanism=Mechanism.RSA_PKCS
            )

            result = decrypted_data.decode('utf-8')
            print(f"✅ Données déchiffrées: '{result}'")
            return result

        except Exception as e:
            print(f"❌ Erreur déchiffrement: {e}")
            import traceback
            traceback.print_exc()
            return None