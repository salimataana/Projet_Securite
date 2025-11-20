import pkcs11
from pkcs11 import KeyType, Mechanism
import os


class HSMManager:
    """
    Gestionnaire pour interagir avec le HSM (Hardware Security Module)
    Cette classe permet de réaliser des opérations cryptographiques sécurisées
    """

    def __init__(self):
        # Chemin vers la bibliothèque SoftHSM2
        self.lib_path = '/usr/lib/softhsm/libsofthsm2.so'
        # Session HSM (sera initialisée lors de la connexion)
        self.session = None
        # Configuration de l'environnement pour SoftHSM
        os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'

    def connect(self, pin='1234'):
        """
        Établir une connexion sécurisée avec le HSM

        Args:
            pin (str): Code PIN pour accéder au token HSM

        Returns:
            object: Session HSM ouverte ou None en cas d'erreur
        """
        try:
            # Charger la bibliothèque PKCS#11 de SoftHSM
            lib = pkcs11.lib(self.lib_path)
            # Récupérer le token HSM par son label
            token = lib.get_token(token_label='MonHSM')
            # Ouvrir une session en mode lecture/écriture
            self.session = token.open(user_pin=pin, rw=True)
            print("✅ HSM connecté")
            return self.session
        except Exception as e:
            print(f"❌ Erreur connexion: {e}")
            return None

    def generate_key_pair(self):
        """
        Générer une paire de clés RSA 2048 bits dans le HSM

        Returns:
            tuple: (clé_publique, clé_privée) ou (None, None) en cas d'erreur
        """
        try:
            # Vérifier si une session est active
            if not self.session:
                self.connect('1234')

            # Nettoyer les anciennes clés avant de générer de nouvelles
            self._clean_keys()

            # Générer une paire de clés RSA 2048 bits dans le HSM
            public_key, private_key = self.session.generate_keypair(
                KeyType.RSA,  # Type d'algorithme: RSA
                2048,  # Taille de la clé: 2048 bits (sécurisé)
                label="main_key",  # Identifiant de la clé dans le HSM
                store=True  # Stocker la clé de manière persistante
            )
            print("✅ Clés générées")
            return public_key, private_key
        except Exception as e:
            print(f"❌ Erreur génération: {e}")
            return None, None

    def _clean_keys(self):
        """
        Méthode interne pour supprimer toutes les clés existantes
        Évite les conflits avec d'anciennes clés
        """
        try:
            # Récupérer tous les objets (clés) dans le HSM
            objects = list(self.session.get_objects())
            # Parcourir et détruire chaque objet
            for obj in objects:
                try:
                    obj.destroy()
                except:
                    pass  # Ignorer les erreurs de destruction
            print("🧹 Anciennes clés nettoyées")
        except:
            pass  # Ignorer si aucune clé n'existe

    def sign_data(self, data):
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
                self.connect('1234')

            # Rechercher toutes les clés privées disponibles
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))

            # Vérifier qu'au moins une clé privée existe
            if not private_keys:
                print("❌ Aucune clé trouvée")
                return None

            # Prendre la première clé privée disponible
            private_key = private_keys[0]
            print("✅ Clé trouvée, signature en cours...")

            # Créer la signature avec l'algorithme RSA-PKCS
            signature = private_key.sign(
                data.encode('utf-8'),  # Convertir les données en bytes
                mechanism=Mechanism.RSA_PKCS  # Mécanisme de signature
            )

            print("✅ Signature réussie")
            # Retourner la signature en format hexadécimal (plus facile à transmettre)
            return signature.hex()

        except Exception as e:
            print(f"❌ Erreur signature: {e}")
            return None

    def verify_signature(self, data, signature):
        """
        Vérifier une signature avec la clé publique correspondante

        Args:
            data (str): Données originales qui ont été signées
            signature (str): Signature à vérifier (en hexadécimal)

        Returns:
            bool: True si la signature est valide, False sinon
        """
        try:
            print(f"🔄 Vérification de signature pour: '{data}'")
            print(f"📏 Longueur signature: {len(signature)} caractères")

            # Vérifier et établir la connexion HSM si nécessaire
            if not self.session:
                print("❌ Session HSM non active - reconnexion...")
                self.connect('1234')
                if not self.session:
                    return False

            # Rechercher les clés publiques disponibles
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))

            print(f"🔍 {len(public_keys)} clé(s) publique(s) trouvée(s)")

            # Vérifier qu'une clé publique existe
            if not public_keys:
                print("❌ Aucune clé publique trouvée")
                return False

            # Prendre la première clé publique disponible
            public_key = public_keys[0]
            key_label = getattr(public_key, 'label', 'Inconnu')
            print(f"✅ Utilisation de la clé: {key_label}")

            # Convertir la signature d'hexadécimal vers bytes
            print("🔄 Conversion signature hex → bytes...")
            signature_bytes = bytes.fromhex(signature)
            print(f"📏 Signature bytes: {len(signature_bytes)} bytes")

            # Vérifier la signature avec la clé publique
            print("🔐 Tentative de vérification...")
            public_key.verify(
                data.encode('utf-8'),  # Données originales
                signature_bytes,  # Signature à vérifier
                mechanism=Mechanism.RSA_PKCS  # Même mécanisme que pour la signature
            )
            print("🎉 ✅ Signature VALIDE")
            return True

        except Exception as e:
            print(f"💥 ❌ ERREUR vérification: {e}")
            import traceback
            traceback.print_exc()
            return False

    def encrypt_data(self, data):
        """
        Chiffrer des données avec la clé publique du HSM

        Args:
            data (str): Données à chiffrer

        Returns:
            str: Données chiffrées en hexadécimal ou None en cas d'erreur
        """
        try:
            print(f"🔒 Tentative de chiffrement: '{data}'")

            # Vérifier la connexion HSM
            if not self.session:
                self.connect('1234')

            # Rechercher les clés publiques disponibles
            public_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
            }))

            # Vérifier qu'une clé publique existe
            if not public_keys:
                print("❌ Aucune clé publique trouvée pour le chiffrement")
                return None

            # Prendre la première clé publique disponible
            public_key = public_keys[0]
            key_label = getattr(public_key, 'label', 'Inconnu')
            print(f"✅ Clé publique trouvée: {key_label}")

            # Chiffrer les données avec RSA
            encrypted_data = public_key.encrypt(
                data.encode('utf-8'),  # Données à chiffrer
                mechanism=Mechanism.RSA_PKCS  # Mécanisme de chiffrement
            )

            print("✅ Données chiffrées avec succès")
            # Retourner les données chiffrées en hexadécimal
            return encrypted_data.hex()

        except Exception as e:
            print(f"❌ Erreur chiffrement: {e}")
            import traceback
            traceback.print_exc()
            return None

    def decrypt_data(self, encrypted_data_hex):
        """
        Déchiffrer des données avec la clé privée du HSM

        Args:
            encrypted_data_hex (str): Données chiffrées en hexadécimal

        Returns:
            str: Données déchiffrées ou None en cas d'erreur
        """
        try:
            print(f"🔓 Tentative de déchiffrement")

            # Vérifier la connexion HSM
            if not self.session:
                self.connect('1234')

            # Rechercher les clés privées disponibles
            private_keys = list(self.session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
            }))

            # Vérifier qu'une clé privée existe
            if not private_keys:
                print("❌ Aucune clé privée trouvée pour le déchiffrement")
                return None

            # Prendre la première clé privée disponible
            private_key = private_keys[0]
            key_label = getattr(private_key, 'label', 'Inconnu')
            print(f"✅ Clé privée trouvée: {key_label}")

            # Convertir les données chiffrées d'hexadécimal vers bytes
            encrypted_data = bytes.fromhex(encrypted_data_hex)

            # Déchiffrer les données avec la clé privée
            decrypted_data = private_key.decrypt(
                encrypted_data,  # Données chiffrées
                mechanism=Mechanism.RSA_PKCS  # Même mécanisme que pour le chiffrement
            )

            # Convertir les bytes déchiffrés en texte
            result = decrypted_data.decode('utf-8')
            print(f"✅ Données déchiffrées: '{result}'")
            return result

        except Exception as e:
            print(f"❌ Erreur déchiffrement: {e}")
            import traceback
            traceback.print_exc()
            return None