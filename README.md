# 🔐 HSM Local - Gestion Sécurisée des Clés Cryptographiques

Autor : Ana Salimata SANOU

## 📋 Description
Application Python/Flask permettant d'interagir avec un HSM (Hardware Security Module) local via SoftHSM pour la gestion sécurisée des clés cryptographiques.

## 🎯 Fonctionnalités
- 🗝️ **Génération de clés RSA 2048 bits**
- ✍️ **Signature numérique de données**
- ✅ **Vérification de signatures**
- 🔐 **Chiffrement de données**
- 🔓 **Déchiffrement de données**

## 🛠️ Installation

### Prérequis
```bash
sudo apt-get install softhsm2 opensc
pip install -r requirements.txt
```

### Configuration SoftHSM
```bash
# Créer le dossier des tokens
mkdir tokens

# Configuration
echo "directories.tokendir = $(pwd)/tokens" > softhsm2.conf

# Initialiser le token
SOFTHSM2_CONF=./softhsm2.conf softhsm2-util --init-token --slot 0 --label "MonHSM" --pin 1234 --so-pin 5678
```

## 🚀 Utilisation

### Lancement de l'application
```bash
python main.py
```
Ouvrir http://localhost:5000

### Ordre d'utilisation dans l'interface :
1. **Générer les clés RSA** (une seule fois)
2. **Signer/Vérifier** des données
3. **Chiffrer/Déchiffrer** des messages

## 📁 Structure du Projet
```
Projet_Securite/
├── main.py                 # Application Flask principale
├── hsm_manager.py          # Gestionnaire HSM
├── requirements.txt        # Dépendances Python
├── softhsm2.conf          # Configuration SoftHSM
├── tokens/                # Stockage sécurisé des clés
└── templates/
    └── index.html         # Interface web
```

## 🔧 Dépendances
- Flask==2.3.3
- python-pkcs11==0.7.0
- cryptography==41.0.3

## 🎮 Commandes Utiles

### Lister les clés dans le HSM
```bash
SOFTHSM2_CONF=./softhsm2.conf pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects
```

### Réinitialiser le token
```bash
SOFTHSM2_CONF=./softhsm2.conf softhsm2-util --delete-token --token "MonHSM"
SOFTHSM2_CONF=./softhsm2.conf softhsm2-util --init-token --slot 0 --label "MonHSM" --pin 1234 --so-pin 5678
```

## 📊 Performances Typiques
- Génération de clés : ~400-500 ms
- Signature : ~10-15 ms
- Vérification : ~3-5 ms
- Chiffrement : ~8-12 ms
- Déchiffrement : ~10-15 ms

## 🔒 Sécurité
- Clés privées **jamais exposées**
- Toutes les opérations cryptographiques effectuées **dans le HSM**
- Stockage sécurisé dans le token SoftHSM

## 📝 Auteur 
Projet réalisé dans le cadre de la gestion sécurisée des clés cryptographiques avec HSM open-source.


## Commande to set up 

