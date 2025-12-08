


from flask import request, jsonify
from flask import Blueprint, render_template
from core.hash_manager import HashManager

hash_controller = Blueprint('hash', __name__, template_folder='../templates')
hash_manager = HashManager()




@hash_controller.route('/hash', methods=['POST'])
def hash_message():
    method_hash = request.form.get('methodHash')
    data = request.form.get('hashInput')
    if method_hash == '':
        return jsonify({"success": False})
    data_hashed = hash_manager.compute_hash(data, method_hash)

    return render_template("operations_results_hash.html", data_hashed=data_hashed)

