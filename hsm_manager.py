import pkcs11
from pkcs11 import KeyType, Mechanism
import os
import time

# Stocke la dernière clé utilisée pour le chiffrement
LAST_ENCRYPTION_KEY_ID = None


class HSMManager:
    """
    Gestionnaire pour interagir avec le HSM (Hardware Security Module)
    Cette classe permet de réaliser des opérations cryptographiques sécurisées
    """

    def __init__(self):
        # Chemin vers la bibliothèque SoftHSM2
        # self.lib_path = '/usr/lib/softhsm/libsofthsm2.so'
        self.lib_path = '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so'
        # Session HSM (sera initialisée lors de la connexion)
        self.session = None
        # Configuration de l'environnement pour SoftHSM
        # os.environ['SOFTHSM2_CONF'] = '/home/salimata/PycharmProjects/Projet_Securite/softhsm2.conf'
        os.environ['SOFTHSM2_CONF'] = './softhsm2.conf'  # Chemin relatif!

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

            # NE PLUS NETTOYER LES ANCIENNES CLÉS - CONSERVER TOUTES LES CLÉS
            # self._clean_keys()  # LIGNE COMMENTÉE POUR CONSERVER LES CLÉS

            # Générer une paire de clés RSA 2048 bits dans le HSM
            public_key, private_key = self.session.generate_keypair(
                KeyType.RSA,  # Type d'algorithme: RSA
                2048,  # Taille de la clé: 2048 bits (sécurisé)
                label=f"key_{int(time.time())}",  # Identifiant unique avec timestamp
                store=True  # Stocker la clé de manière persistante
            )
            print("✅ Clés générées et CONSERVÉES dans le HSM")
            return public_key, private_key
        except Exception as e:
            print(f"❌ Erreur génération: {e}")
            return None, None

    def _clean_keys(self):
        """
        MÉTHODE DÉSACTIVÉE - NE PLUS NETTOYER LES ANCIENNES CLÉS
        Cette méthode est conservée mais ne fait plus rien pour préserver toutes les clés
        """
        print("⚠️ Méthode _clean_keys désactivée - TOUTES LES CLÉS SONT CONSERVÉES")
        # Ne rien faire - conserver toutes les clés
        return

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
                    print(f"  {i + 1}. {key_type} - Label: {label}")
                except:
                    print(f"  {i + 1}. Clé (détails indisponibles)")

            print("=== FIN DÉBOGAGE ===")

        except Exception as e:
            print(f"❌ Erreur débogage: {e}")

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

    def encrypt_data(self, data, key_label=None):
        """Chiffrer des données avec une clé publique spécifique"""
        if not self.session:
            self.connect('1234')

        # Rechercher les clés publiques
        public_keys = list(self.session.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY
        }))

        if key_label:
            # Prendre la clé publique correspondant au label
            for key in public_keys:
                if getattr(key, 'label', '') == key_label:
                    public_key = key
                    break
            else:
                print(f"❌ Clé publique avec label '{key_label}' non trouvée")
                return None
        else:
            # Si pas de label fourni, prendre la première (moins sûr si plusieurs clés)
            public_key = public_keys[0]
            key_label = getattr(public_key, 'label', 'Inconnu')

        # Chiffrement
        encrypted_data = public_key.encrypt(
            data.encode('utf-8'),
            mechanism=Mechanism.RSA_PKCS
        )
        return encrypted_data.hex(), key_label  # Retourner aussi le label utilisé

    def decrypt_data(self, encrypted_data_hex, key_label):
        """Déchiffrer des données avec la clé privée correspondante"""
        if not self.session:
            self.connect('1234')

        # Rechercher les clés privées
        private_keys = list(self.session.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY
        }))

        # Chercher la clé privée correspondant au label
        for key in private_keys:
            if getattr(key, 'label', '') == key_label:
                private_key = key
                break
        else:
            print(f"❌ Clé privée avec label '{key_label}' non trouvée")
            return None

        # Déchiffrement
        decrypted_data = private_key.decrypt(
            bytes.fromhex(encrypted_data_hex),
            mechanism=Mechanism.RSA_PKCS
        )
        return decrypted_data.decode('utf-8')  # Retourner le texte clair


def test_encryption_cycle(self, test_data="Test123"):
    """Test complet chiffrement/déchiffrement avec debug"""
    print(f"=== TEST COMPLET ===")
    print(f"1. Données originales: '{test_data}'")

    # Chiffrer
    encrypted_hex = self.encrypt_data(test_data)
    print(f"2. Chiffré (hex): {encrypted_hex[:50]}...")

    if not encrypted_hex:
        print("❌ Échec du chiffrement")
        return False

    # Déchiffrer
    decrypted_result = self.decrypt_data(encrypted_hex)
    print(f"3. Déchiffré: '{decrypted_result}'")
    print(f"4. Type: {type(decrypted_result)}")

    # Vérifier
    success = (decrypted_result == test_data)
    print(f"5. Résultat: {'✅ SUCCÈS' if success else '❌ ÉCHEC'}")
    print(f"=== FIN TEST ===")
    return success