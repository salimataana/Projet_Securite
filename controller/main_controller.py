from flask import Blueprint, render_template

from core.analysis_manager import AnalysisManager
from core.hsm_manager import HSMManager

hsm_manager = HSMManager()
# Le nom 'pages' doit être utilisé dans url_for côté templates
main_controller = Blueprint(
    'pages',
    __name__,
    template_folder='../templates'
)

@main_controller.route('/')
def index():
    """Page d'accueil / hub HSM Crypto Manager"""
    return render_template('index.html')


@main_controller.route('/operations_creation')
def operations():
    """Page des opérations cryptographiques (signature, chiffrement, hash, etc.)"""
    keys = hsm_manager.get_all_keys_public()
    return render_template('operations_creation.html', keys=keys)

@main_controller.route('/operations_listing')
def operations_listing():
    """Page des opérations cryptographiques (signature, chiffrement, hash, etc.)"""
    public_keys = hsm_manager.get_all_keys_public()
    private_keys = hsm_manager.get_all_keys_private()
    return render_template('operations_listing.html', public_keys=public_keys, private_keys=private_keys)


@main_controller.route('/operations_chiffrement')
def operations_chiffrement():
    """Page des opérations cryptographiques (signature, chiffrement, hash, etc.)"""
    keys_publics = hsm_manager.get_all_keys_public()
    keys_privates = hsm_manager.get_all_keys_private()

    return render_template('operations_chiffrement.html',
                           keys_publics=keys_publics, keys_privates=keys_privates)



@main_controller.route('/operations_signature')
def operations_signature():
    """Page des opérations cryptographiques (signature, chiffrement, hash, etc.)"""
    keys_privates = hsm_manager.get_all_keys_private()
    keys_publics = hsm_manager.get_all_keys_public()
    return render_template('operations_signature.html',
                           keys_privates=keys_privates, keys_publics=keys_publics)


@main_controller.route('/operations_hashage')
def operations_hashage():
    """Page des opérations cryptographiques (signature, chiffrement, hash, etc.)"""
    keys = hsm_manager.get_all_keys_public()
    return render_template('operations_hashage.html', keys=keys)

@main_controller.route('/operations_signature_hashage')
def operations_signature_hashage():
    """Page des opérations cryptographiques (signature, chiffrement, hash, etc.)"""
    keys_privates = hsm_manager.get_all_keys_private()
    keys_publics = hsm_manager.get_all_keys_public()
    return render_template('operations_signature_hashage.html',keys_privates=keys_privates, keys_publics=keys_publics)

@main_controller.route("/operations_analysis")
def operations_analysis():
    manager = AnalysisManager()

    # Moyennes globales encrypt / decrypt (en secondes)
    avg_encrypt = manager.compute_average_encrypt_algorithm_operation()
    avg_decrypt = manager.compute_average_decrypt_algorithm_operation()

    # Moyennes par algorithme de chiffrement (encrypt)
    encrypt_stats = manager.compute_average_by_algorithm()  # dict: {algo: avg_duration}
    algo_labels = list(encrypt_stats.keys())
    algo_values = list(encrypt_stats.values())

    # Stats de hashage
    hash_stats = manager.compute_average_hash_by_algorithm()  # dict: {algo: avg_duration_sec}
    avg_hash_sec = manager.compute_average_hash_operation()
    avg_hash = avg_hash_sec * 1000 if avg_hash_sec else 0  # conversion en ms

    hash_labels = list(hash_stats.keys())
    hash_values = [v * 1000 for v in hash_stats.values()]  # conversion en ms pour l'histogramme

    return render_template(
        "operations_analysis.html",
        # Encrypt / decrypt
        avg_encrypt=avg_encrypt,
        avg_decrypt=avg_decrypt,
        encrypt_stats=encrypt_stats,
        algo_labels=algo_labels,
        algo_values=algo_values,

        # Hash
        hash_stats=hash_stats,
        hash_labels=hash_labels,
        hash_values=hash_values,
        avg_hash=avg_hash,
    )

@main_controller.route('/keys')
def keys_management():
    """Page de gestion des clés"""
    return render_template('keys_management.html')
