import json
import os


class AnalysisManager:
    def __init__(self):
        with open(os.environ["data_file"], "r") as f:
            self.file_data = json.load(f)
        self.performances = self.file_data["database"]["performances"]

    def _get_durations(self, filt):
        durations = []
        for item in self.performances:
            if filt(item):
                durations.append(item["duration"])  # champ "duration" dans ton JSON
        return durations

    # ======== CHIFFREMENT / DÉCHIFFREMENT =========

    def compute_average_encrypt_algorithm_operation(self):
        durations = self._get_durations(
            lambda item: item["operation_type"] == "encrypt_data"
        )
        return sum(durations) / len(durations) if durations else 0

    def compute_average_decrypt_algorithm_operation(self):
        durations = self._get_durations(
            lambda item: item["operation_type"] == "decrypt_data"
        )
        return sum(durations) / len(durations) if durations else 0

    def compute_average_encryption_algorithm_operation(self, kind: str):
        durations = self._get_durations(
            lambda item: item["operation_type"] == "encrypt_data"
                        and item.get("algorithm") == kind
        )
        return sum(durations) / len(durations) if durations else 0

    def compute_average_by_algorithm(self):
        """
        Retourne un dict: { "RSA_PKCS": moyenne_duration, ... }
        pour les opérations encrypt_data avec un algorithm défini.
        """
        buckets = {}
        for item in self.performances:
            if item["operation_type"] == "encrypt_data" and "algorithm" in item:
                algo = item["algorithm"]
                buckets.setdefault(algo, []).append(item["duration"])

        return {
            algo: sum(durs) / len(durs)
            for algo, durs in buckets.items()
        }

    # ======== HASHAGE =========

    def compute_average_hash_operation(self):
        """
        Durée moyenne de TOUTES les opérations de hash (tous algos confondus).
        """
        durations = self._get_durations(
            lambda item: item["operation_type"] == "hash"
        )
        return sum(durations) / len(durations) if durations else 0

    def compute_average_hash_by_algorithm(self):
        """
        Retourne un dict: { "md5": moyenne_duration, "sha256": ..., ... }
        pour les opérations de hash.
        """
        buckets = {}
        for item in self.performances:
            if item["operation_type"] == "hash" and "algorithm" in item:
                algo = item["algorithm"]
                buckets.setdefault(algo, []).append(item["duration"])

        return {
            algo: sum(durs) / len(durs)
            for algo, durs in buckets.items()
        }
