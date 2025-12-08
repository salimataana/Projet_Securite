// Charger les données au démarrage
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    loadKeys();
});

function loadStatistics() {
    fetch('/api/keys/statistics')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const stats = data.statistics;
                document.getElementById('globalStats').innerHTML = `
                    <div class="col-md-2 mb-3">
                        <div class="card stats-card">
                            <div class="card-body text-center">
                                <h3>${stats.total_keys}</h3>
                                <small>Clés Total</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-2 mb-3">
                        <div class="card stats-card">
                            <div class="card-body text-center">
                                <h3>${stats.active_keys}</h3>
                                <small>Clés Actives</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-2 mb-3">
                        <div class="card stats-card">
                            <div class="card-body text-center">
                                <h3>${stats.total_operations}</h3>
                                <small>Opérations</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card stats-card">
                            <div class="card-body text-center">
                                <h3>${stats.success_rate}</h3>
                                <small>Taux de Réussite</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card stats-card">
                            <div class="card-body text-center">
                                <h3>${stats.avg_processing_time}</h3>
                                <small>Temps Moyen</small>
                            </div>
                        </div>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Erreur lors du chargement des statistiques:', error);
        });
}

function loadKeys() {
    const keysList = document.getElementById('keysList');
    keysList.innerHTML = `
        <div class="empty-state">
            <div class="loader"></div>
            <p>Chargement des clés...</p>
        </div>
    `;

    fetch('/api/keys/list')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayKeys(data.keys);
                const countLabel = data.keys.length > 1 ? 'clés' : 'clé';
                document.getElementById('keysCount').textContent = `${data.keys.length} ${countLabel}`;
                updateTestKeySelect(data.keys);
            } else {
                keysList.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Erreur lors du chargement des clés: ${data.error}
                    </div>
                `;
            }
        })
        .catch(error => {
            keysList.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Erreur de connexion: ${error}
                </div>
            `;
        });
}

function displayKeys(keys) {
    if (keys.length === 0) {
        document.getElementById('keysList').innerHTML = `
            <div class="empty-state">
                <i class="fas fa-key fa-3x"></i>
                <h4>Aucune clé disponible</h4>
                <p class="text-muted">Générez votre première clé pour commencer à travailler avec le HSM.</p>
            </div>
        `;
        return;
    }

    let html = '<div class="key-grid">';
    keys.forEach(key => {
        const created = new Date(key.created_at).toLocaleString('fr-FR');
        const lastUsed = key.last_used ? new Date(key.last_used).toLocaleString('fr-FR') : 'Jamais';
        const statusClass = key.status === 'active' ? 'status-active' : 'status-inactive';
        const statusText = key.status === 'active' ? 'Active' : 'Inactive';

        html += `
            <div class="key-card">
                <div class="key-card-header">
                    <div>
                        <p class="key-title"><i class="fas fa-key me-2"></i>${key.key_id}</p>
                        <p class="key-meta">${key.key_type} · ${key.key_size} bits</p>
                    </div>
                    <span class="status-badge ${statusClass}">${statusText}</span>
                </div>

                <div class="key-card-body">
                    <div class="key-stat">
                        <span>Utilisations</span>
                        <strong>${key.usage_count}</strong>
                    </div>
                    <div class="key-stat">
                        <span>Créée le</span>
                        <strong>${created}</strong>
                    </div>
                    <div class="key-stat">
                        <span>Dernière utilisation</span>
                        <strong>${lastUsed}</strong>
                    </div>
                    <div class="key-public-key">
                        <span>Clé publique</span>
                        <code>${key.public_key_preview || 'Non disponible'}</code>
                    </div>
                </div>

                <div class="key-card-actions">
                    <button class="btn ghost btn-small" onclick="showOperations('${key.key_id}')" title="Voir l'historique">
                        <i class="fas fa-history me-1"></i>Historique
                    </button>
                    <button class="btn btn-small" onclick="useKeyForTest('${key.key_id}')" title="Tester cette clé">
                        <i class="fas fa-flask me-1"></i>Tester
                    </button>
                    <button class="btn btn-small ${key.status === 'active' ? 'btn-warning' : 'btn-success'}" onclick="toggleKeyStatus('${key.key_id}')">
                        <i class="fas ${key.status === 'active' ? 'fa-pause' : 'fa-play'} me-1"></i>
                        ${key.status === 'active' ? 'Désactiver' : 'Activer'}
                    </button>
                </div>
            </div>
        `;
    });
    html += '</div>';
    document.getElementById('keysList').innerHTML = html;
}

function toggleKeyStatus(keyId) {
    if (!confirm('Voulez-vous vraiment changer le statut de cette clé ?')) {
        return;
    }

    fetch(`/api/keys/${keyId}/toggle-status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadKeys();
            loadStatistics();
            showTemporaryMessage(`Clé ${data.new_status === 'active' ? 'activée' : 'désactivée'} avec succès`, 'success');
        } else {
            showTemporaryMessage(`Erreur: ${data.error}`, 'error');
        }
    })
    .catch(error => {
        showTemporaryMessage(`Erreur réseau: ${error}`, 'error');
    });
}

function showTemporaryMessage(message, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `alert alert-${type === 'success' ? 'success' : 'danger'} alert-dismissible fade show`;
    messageDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

    const container = document.querySelector('.keys-page');
    container.insertBefore(messageDiv, container.firstChild);

    setTimeout(() => {
        if (messageDiv.parentNode) {
            messageDiv.remove();
        }
    }, 3000);
}

function generateNewKey() {
    const keySize = document.getElementById('keySize').value;
    const resultDiv = document.getElementById('keyGenerationResult');
    const generateButton = document.getElementById('generateButton');

    generateButton.disabled = true;
    generateButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Génération en cours...';

    resultDiv.innerHTML = `
        <div class="alert alert-info">
            <div class="d-flex align-items-center">
                <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                <div>
                    <strong>Génération de la clé RSA ${keySize} bits en cours...</strong>
                    <div class="small">Cette opération peut prendre quelques secondes</div>
                </div>
            </div>
        </div>
    `;

    fetch('/api/keys/generate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({ key_size: parseInt(keySize) })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h6><i class="fas fa-check-circle me-2"></i>Clé générée avec succès!</h6>
                    <div class="mt-2">
                        <p class="mb-1"><strong>ID de la clé:</strong> <code>${data.key_id}</code></p>
                        <p class="mb-1"><strong>Taille:</strong> ${data.key_size} bits</p>
                        <p class="mb-1"><strong>Temps de génération:</strong> ${data.processing_time}</p>
                        <p class="mb-0"><strong>Stockage:</strong> ${data.stored_in_db ? 'Base de données' : 'Non stockée'}</p>
                    </div>
                </div>
            `;

            setTimeout(() => {
                loadStatistics();
                loadKeys();
            }, 500);

        } else {
            resultDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>Erreur lors de la génération:</strong> ${data.error}
                </div>
            `;
        }
    })
    .catch(error => {
        console.error('Erreur:', error);
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Erreur de connexion:</strong> ${error.message}
            </div>
        `;
    })
    .finally(() => {
        generateButton.disabled = false;
        generateButton.innerHTML = '<i class="fas fa-key me-2"></i>Générer la Clé';
    });
}

function showOperations(keyId) {
    document.getElementById('modalKeyId').textContent = keyId;
    const operationsList = document.getElementById('operationsList');

    operationsList.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Chargement...</span>
            </div>
            <p class="mt-2 text-muted">Chargement des opérations...</p>
        </div>
    `;

    fetch(`/api/keys/${keyId}/operations`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.operations.length > 0) {
                let html = '<div class="table-responsive"><table class="table table-sm table-hover">';
                html += `
                    <thead class="table-light">
                        <tr>
                            <th>Type</th>
                            <th>Hash des données</th>
                            <th>Signature</th>
                            <th>Temps</th>
                            <th>Date</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                `;

                data.operations.forEach(op => {
                    const successBadge = op.success ?
                        '<span class="badge bg-success operation-badge">Succès</span>' :
                        '<span class="badge bg-danger operation-badge">Échec</span>';

                    const operationTypeBadge = getOperationTypeBadge(op.operation_type);

                    html += `
                        <tr>
                            <td>${operationTypeBadge}</td>
                            <td><small class="font-monospace">${op.data_hash || 'N/A'}</small></td>
                            <td><small class="font-monospace">${op.signature_preview || 'N/A'}</small></td>
                            <td>${op.processing_time}</td>
                            <td><small>${new Date(op.timestamp).toLocaleString('fr-FR')}</small></td>
                            <td>${successBadge}</td>
                        </tr>
                    `;
                });

                html += '</tbody></table></div>';
                operationsList.innerHTML = html;
            } else {
                operationsList.innerHTML = `
                    <div class="text-center py-4">
                        <i class="fas fa-history fa-2x text-muted mb-3"></i>
                        <p class="text-muted">Aucune opération enregistrée pour cette clé</p>
                    </div>
                `;
            }

            new bootstrap.Modal(document.getElementById('operationsModal')).show();
        })
        .catch(error => {
            operationsList.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Erreur lors du chargement des opérations: ${error}
                </div>
            `;
        });
}

function getOperationTypeBadge(type) {
    const badges = {
        'key_generation': { class: 'bg-primary', text: 'Génération' },
        'signature': { class: 'bg-success', text: 'Signature' },
        'encryption': { class: 'bg-warning', text: 'Chiffrement' },
        'decryption': { class: 'bg-info', text: 'Déchiffrement' },
        'hash_and_sign': { class: 'bg-dark', text: 'Hachage+Sign' }
    };

    const badge = badges[type] || { class: 'bg-secondary', text: type };
    return `<span class="badge ${badge.class} operation-badge">${badge.text}</span>`;
}

function testKeyOperations() {
    fetch('/api/keys/list')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.keys.length > 0) {
                updateTestKeySelect(data.keys);
                new bootstrap.Modal(document.getElementById('testKeyModal')).show();
            } else {
                alert('Aucune clé disponible pour les tests. Veuillez d\'abord générer une clé.');
            }
        });
}

function updateTestKeySelect(keys) {
    const select = document.getElementById('testKeySelect');
    select.innerHTML = '<option value="">Sélectionner une clé...</option>';

    keys.forEach(key => {
        if (key.status === 'active') {
            const option = document.createElement('option');
            option.value = key.key_id;
            option.textContent = `${key.key_id} (${key.key_size} bits) - ${key.usage_count} utilisations`;
            select.appendChild(option);
        }
    });
}

function useKeyForTest(keyId) {
    const select = document.getElementById('testKeySelect');
    const option = Array.from(select.options).find(opt => opt.value === keyId);
    if (option) {
        select.value = keyId;
        new bootstrap.Modal(document.getElementById('testKeyModal')).show();
    }
}

function testSignature() {
    const keyId = document.getElementById('testKeySelect').value;
    const testData = document.getElementById('testData').value;

    if (!keyId) {
        alert('Veuillez sélectionner une clé');
        return;
    }

    performTestOperation('/sign', { data: testData, key_id: keyId }, 'Signature');
}

function testEncryption() {
    const keyId = document.getElementById('testKeySelect').value;
    const testData = document.getElementById('testData').value;

    if (!keyId) {
        alert('Veuillez sélectionner une clé');
        return;
    }

    performTestOperation('/encrypt', { data: testData, key_id: keyId }, 'Chiffrement');
}

function testHashAndSign() {
    const keyId = document.getElementById('testKeySelect').value;
    const testData = document.getElementById('testData').value;

    if (!keyId) {
        alert('Veuillez sélectionner une clé');
        return;
    }

    performTestOperation('/hash-and-sign', { data: testData, key_id: keyId }, 'Hachage + Signature');
}

function performTestOperation(url, data, operationName) {
    const resultsDiv = document.getElementById('testResults');
    resultsDiv.innerHTML = `
        <div class="alert alert-info">
            <div class="d-flex align-items-center">
                <div class="spinner-border spinner-border-sm me-2"></div>
                <span>${operationName} en cours...</span>
            </div>
        </div>
    `;

    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            resultsDiv.innerHTML = `
                <div class="alert alert-success">
                    <h6><i class="fas fa-check-circle me-2"></i>${operationName} réussie!</h6>
                    <div class="mt-2">
                        ${result.signature ? `<p><strong>Signature:</strong> <code class="small">${result.signature.substring(0, 50)}...</code></p>` : ''}
                        ${result.hash ? `<p><strong>Hash:</strong> <code class="small">${result.hash}</code></p>` : ''}
                        ${result.encrypted_data ? `<p><strong>Données chiffrées:</strong> <code class="small">${result.encrypted_data.substring(0, 50)}...</code></p>` : ''}

                        <!--
                        ${result.encrypted_data ? 
                            `<p><strong>Données chiffrées:</strong> <code class="small">${
                                typeof result.encrypted_data === 'string' ? 
                                result.encrypted_data.substring(0, 50) + '...' : 
                                'Format invalide: ' + typeof result.encrypted_data
                            }</code></p>` 
                        : ''}
                        -->

                        ${result.performance ? `<p><strong>Temps:</strong> ${result.performance.total_time || result.processing_time}</p>` : ''}
                    </div>
                </div>
            `;

            setTimeout(() => {
                loadStatistics();
                loadKeys();
            }, 1000);

        } else {
            resultsDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>Erreur lors de ${operationName}:</strong> ${result.error}
                </div>
            `;
        }
    })
    .catch(error => {
        resultsDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Erreur de connexion:</strong> ${error}
            </div>
        `;
    });
}
