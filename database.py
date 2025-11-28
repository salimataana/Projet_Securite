import sqlite3
import json
from datetime import datetime


class KeyDatabase:
    """
    Gestionnaire de base de données pour stocker les métadonnées des clés HSM
    """

    def __init__(self, db_path='hsm_keys.db'):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialiser la structure de la base de données"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Table pour stocker les métadonnées des clés
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_label TEXT UNIQUE NOT NULL,
                key_type TEXT NOT NULL,
                key_size INTEGER NOT NULL,
                public_key_info TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')

        # Table pour l'historique des opérations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER,
                operation_type TEXT NOT NULL,
                data_size INTEGER,
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (key_id) REFERENCES keys (id)
            )
        ''')

        conn.commit()
        conn.close()
        print("✅ Base de données initialisée")

    def add_key(self, key_label, key_type, key_size, public_key_info=None):
        """Ajouter une nouvelle clé à la base de données"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO keys (key_label, key_type, key_size, public_key_info)
                VALUES (?, ?, ?, ?)
            ''', (key_label, key_type, key_size, public_key_info))

            conn.commit()
            conn.close()
            print(f"✅ Clé '{key_label}' ajoutée à la base de données")
            return True
        except sqlite3.IntegrityError:
            print(f"⚠️  Clé '{key_label}' existe déjà")
            return False
        except Exception as e:
            print(f"❌ Erreur ajout clé: {e}")
            return False

    def get_all_keys(self):
        """Récupérer toutes les clés de la base de données"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, key_label, key_type, key_size, public_key_info, 
                       created_at, last_used, is_active
                FROM keys
                ORDER BY created_at DESC
            ''')

            keys = cursor.fetchall()
            conn.close()

            # Convertir en format plus lisible
            result = []
            for key in keys:
                result.append({
                    'id': key[0],
                    'label': key[1],
                    'type': key[2],
                    'size': key[3],
                    'public_info': key[4],
                    'created_at': key[5],
                    'last_used': key[6],
                    'is_active': key[7]
                })

            return result
        except Exception as e:
            print(f"❌ Erreur récupération clés: {e}")
            return []

    def update_key_usage(self, key_label):
        """Mettre à jour la date d'utilisation d'une clé"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Si key_label est 'default', trouver le vrai label
            if key_label == 'default':
                cursor.execute('SELECT key_label FROM keys ORDER BY created_at DESC LIMIT 1')
                result = cursor.fetchone()
                if result:
                    key_label = result[0]
                else:
                    return False  # Aucune clé trouvée

            cursor.execute('''
                UPDATE keys 
                SET last_used = CURRENT_TIMESTAMP
                WHERE key_label = ?
            ''', (key_label,))

            conn.commit()
            conn.close()
            print(f"✅ Usage mis à jour pour la clé: {key_label}")
            return True
        except Exception as e:
            print(f"❌ Erreur mise à jour usage: {e}")
            return False

    def log_operation(self, key_label, operation_type, data_size, success):
        """Logger une opération cryptographique"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Si key_label est 'default', trouver le vrai label
            if key_label == 'default':
                cursor.execute('SELECT id, key_label FROM keys ORDER BY created_at DESC LIMIT 1')
                result = cursor.fetchone()
                if result:
                    key_id = result[0]
                    key_label = result[1]
                else:
                    return False  # Aucune clé trouvée
            else:
                # Récupérer l'ID de la clé
                cursor.execute('SELECT id FROM keys WHERE key_label = ?', (key_label,))
                key_row = cursor.fetchone()
                if key_row:
                    key_id = key_row[0]
                else:
                    return False  # Clé non trouvée

            cursor.execute('''
                INSERT INTO operations (key_id, operation_type, data_size, success)
                VALUES (?, ?, ?, ?)
            ''', (key_id, operation_type, data_size, success))

            conn.commit()
            conn.close()
            print(f"✅ Opération loggée pour la clé: {key_label}")
            return True
        except Exception as e:
            print(f"❌ Erreur log opération: {e}")
            return False