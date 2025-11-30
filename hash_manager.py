import hashlib
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.backends import default_backend


class HashManager:
    """
    Gestionnaire de fonctions de hachage
    Couvre le chapitre 8 : Hachage
    """

    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha3_256': hashlib.sha3_256,
            'sha3_512': hashlib.sha3_512
        }

    def compute_hash(self, data, algorithm='sha256'):
        """
        Calcule le hash des données avec l'algorithme spécifié
        Chapitre 8 : Fonctions de hachage cryptographiques
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Algorithme non supporté: {algorithm}")

        data_bytes = data.encode('utf-8') if isinstance(data, str) else data

        if algorithm in ['sha256', 'sha512']:
            # Utilisation de cryptography pour certains algorithmes
            digest = crypto_hashes.Hash(
                getattr(crypto_hashes, algorithm.upper())(),
                backend=default_backend()
            )
            digest.update(data_bytes)
            return digest.finalize().hex()
        else:
            # Utilisation de hashlib pour les autres
            hash_func = self.supported_algorithms[algorithm]()
            hash_func.update(data_bytes)
            return hash_func.hexdigest()

    def verify_integrity(self, data, expected_hash, algorithm='sha256'):
        """
        Vérifie l'intégrité des données en comparant les hash
        Chapitre 8 : Intégrité des données
        """
        computed_hash = self.compute_hash(data, algorithm)
        return computed_hash == expected_hash

    def benchmark_hash_algorithms(self, data):
        """
        Compare les performances des différents algorithmes de hachage
        Chapitre 8 : Analyse des fonctions de hachage
        """
        import time

        results = {}
        test_data = data * 1000  # Données plus importantes pour le test

        for algo_name in self.supported_algorithms.keys():
            try:
                start_time = time.time()

                # Calcul multiple pour une meilleure mesure
                for _ in range(100):
                    hash_value = self.compute_hash(test_data, algo_name)

                end_time = time.time()
                results[algo_name] = {
                    'time_per_operation': (end_time - start_time) / 100,
                    'hash_length': len(hash_value),
                    'hash_sample': hash_value[:16] + '...'  # Extrait pour affichage
                }

            except Exception as e:
                results[algo_name] = {'error': str(e)}

        return results

    def demonstrate_collision_resistance(self):
        """
        Démontre le concept de résistance aux collisions
        Chapitre 8 : Propriétés cryptographiques du hachage
        """
        # Recherche de collisions simples (pour la démonstration)
        examples = []

        # Exemple 1 : Changer un seul caractère
        original = "Hello World"
        modified = "Hello World!"

        hash_original = self.compute_hash(original)
        hash_modified = self.compute_hash(modified)

        examples.append({
            'concept': 'Avalanche Effect',
            'description': 'Un petit changement change complètement le hash',
            'original': f"{original} → {hash_original}",
            'modified': f"{modified} → {hash_modified}",
            'changed': hash_original != hash_modified
        })

        # Exemple 2 : Taille fixe du hash
        data_various = ["a", "a" * 100, "a" * 1000]
        hash_sizes = {}

        for data in data_various:
            hash_value = self.compute_hash(data)
            hash_sizes[data[:10] + '...'] = len(hash_value)

        examples.append({
            'concept': 'Taille fixe',
            'description': 'Le hash a toujours la même taille quelle que soit l\'entrée',
            'sizes': hash_sizes
        })

        return examples