# -*- coding: utf-8 -*-
import sqlite3
import json
from datetime import datetime


class KeyDatabase:
    def __init__(self, db_path='keys_database.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialise la base de données avec les tables nécessaires"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Table des clés
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                key_type TEXT NOT NULL,
                key_size INTEGER,
                public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        ''')

        # Table des opérations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT,
                operation_type TEXT NOT NULL,
                data_hash TEXT,
                signature TEXT,
                processing_time REAL,
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (key_id) REFERENCES keys (key_id)
            )
        ''')

        conn.commit()
        conn.close()
        print("✅ Base de données initialisée - TOUTES LES CLÉS SONT CONSERVÉES")

    def add_key(self, key_id, key_type, key_size, public_key=None):
        """Ajoute une nouvelle clé à la base de données - CONSERVE TOUTES LES CLÉS"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Convertit la clé publique en string si nécessaire
            public_key_str = self._ensure_string(public_key)

            # Utilise INSERT OR REPLACE pour mettre à jour si la clé existe déjà
            cursor.execute('''
                INSERT OR REPLACE INTO keys (key_id, key_type, key_size, public_key, status)
                VALUES (?, ?, ?, ?, 'active')
            ''', (key_id, key_type, key_size, public_key_str))

            conn.commit()
            print(f"✅ Clé {key_id} AJOUTÉE/MISE À JOUR - TOUTES LES CLÉS SONT CONSERVÉES")
            return True

        except sqlite3.Error as e:
            print(f"❌ Erreur SQLite lors de l'ajout de la clé: {e}")
            return False
        except Exception as e:
            print(f"❌ Erreur inattendue lors de l'ajout de la clé: {e}")
            return False
        finally:
            conn.close()

    def _ensure_string(self, value):
        """Convertit une valeur en string de manière sécurisée"""
        if value is None:
            return "Aucune clé publique stockée"
        if isinstance(value, str):
            return value
        try:
            return str(value)
        except:
            return f"Objet de type: {type(value)}"

    def record_operation(self, key_id, operation_type, data_hash=None, signature=None, processing_time=0, success=True):
        """Enregistre une opération cryptographique"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Convertit les valeurs en format stockable
            data_hash_str = self._ensure_string(data_hash)
            signature_str = self._ensure_string(signature)

            cursor.execute('''
                INSERT INTO operations (key_id, operation_type, data_hash, signature, processing_time, success)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (key_id, operation_type, data_hash_str, signature_str, processing_time, success))

            # Met à jour le compteur d'utilisation et la date de dernière utilisation
            cursor.execute('''
                UPDATE keys 
                SET usage_count = usage_count + 1, last_used = CURRENT_TIMESTAMP
                WHERE key_id = ?
            ''', (key_id,))

            conn.commit()
            print(f"✅ Opération {operation_type} enregistrée pour la clé {key_id}")
        except Exception as e:
            print(f"❌ Erreur lors de l'enregistrement d'opération: {e}")
        finally:
            conn.close()

    def get_all_keys(self):
        """Récupère TOUTES les clés avec leurs statistiques - AUCUNE SUPPRESSION"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT k.*, 
                       COUNT(o.id) as total_operations,
                       AVG(o.processing_time) as avg_processing_time
                FROM keys k
                LEFT JOIN operations o ON k.key_id = o.key_id
                GROUP BY k.id
                ORDER BY k.created_at DESC
            ''')

            keys = []
            for row in cursor.fetchall():
                public_key = row[4]
                public_key_preview = public_key[:100] + '...' if public_key and len(public_key) > 100 else public_key

                keys.append({
                    'id': row[0],
                    'key_id': row[1],
                    'key_type': row[2],
                    'key_size': row[3],
                    'public_key_preview': public_key_preview,
                    'created_at': row[5],
                    'last_used': row[6],
                    'usage_count': row[7],
                    'status': row[8],
                    'total_operations': row[9],
                    'avg_processing_time': f"{row[10]:.2f} ms" if row[10] else "N/A"
                })

            print(f"✅ {len(keys)} clés récupérées depuis la base de données - TOUTES CONSERVÉES")
            return keys

        except Exception as e:
            print(f"❌ Erreur lors de la récupération des clés: {e}")
            return []
        finally:
            conn.close()

    def get_key_operations(self, key_id, limit=20):
        """Récupère les opérations d'une clé spécifique"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM operations 
                WHERE key_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (key_id, limit))

            operations = []
            for row in cursor.fetchall():
                signature = row[4]
                signature_preview = signature[:50] + '...' if signature and len(signature) > 50 else signature

                operations.append({
                    'id': row[0],
                    'key_id': row[1],
                    'operation_type': row[2],
                    'data_hash': row[3],
                    'signature_preview': signature_preview,
                    'processing_time': f"{row[5]:.2f} ms",
                    'success': bool(row[6]),
                    'timestamp': row[7]
                })

            return operations
        except Exception as e:
            print(f"❌ Erreur lors de la récupération des opérations: {e}")
            return []
        finally:
            conn.close()

    def get_usage_statistics(self):
        """Récupère les statistiques d'utilisation globales"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Statistiques des clés
            cursor.execute('SELECT COUNT(*) FROM keys')
            total_keys = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM keys WHERE status = "active"')
            active_keys = cursor.fetchone()[0]

            # Statistiques des opérations
            cursor.execute('SELECT COUNT(*) FROM operations')
            total_operations_result = cursor.fetchone()
            total_operations = total_operations_result[0] if total_operations_result else 0

            cursor.execute('SELECT COUNT(*) FROM operations WHERE success = 1')
            successful_operations_result = cursor.fetchone()
            successful_operations = successful_operations_result[0] if successful_operations_result else 0

            cursor.execute('SELECT AVG(processing_time) FROM operations WHERE processing_time > 0')
            avg_processing_time_result = cursor.fetchone()[0]
            avg_processing_time = avg_processing_time_result if avg_processing_time_result else 0

            success_rate = "N/A"
            if total_operations > 0:
                success_rate = f"{(successful_operations / total_operations * 100):.1f}%"

            stats = {
                'total_keys': total_keys,
                'active_keys': active_keys,
                'total_operations': total_operations,
                'successful_operations': successful_operations,
                'success_rate': success_rate,
                'avg_processing_time': f"{avg_processing_time:.2f} ms"
            }

            print(f"✅ Statistiques récupérées: {total_keys} clés totales, {total_operations} opérations")
            return stats

        except Exception as e:
            print(f"❌ Erreur lors de la récupération des statistiques: {e}")
            return {
                'total_keys': 0,
                'active_keys': 0,
                'total_operations': 0,
                'successful_operations': 0,
                'success_rate': "N/A",
                'avg_processing_time': "N/A"
            }
        finally:
            conn.close()

    def get_key(self, key_id):
        """Récupère une clé spécifique par son ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT * FROM keys WHERE key_id = ?
            ''', (key_id,))
            
            row = cursor.fetchone()
            
            if row:
                # Adaptez les index selon votre schéma de table
                return {
                    'id': row[0],
                    'key_id': row[1],
                    'key_type': row[2],
                    'key_size': row[3],
                    'public_key': row[4],
                    'created_at': row[5],
                    'last_used': row[6],
                    'usage_count': row[7],
                    'status': row[8]
                }
            return None
        except Exception as e:
            print(f"Erreur get_key: {e}")
            return None
        finally:
            conn.close()