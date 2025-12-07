
        // Gestion des onglets
        function switchTab(tabName) {
            // Désactiver tous les onglets
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Activer l'onglet sélectionné
            document.querySelector(`.tab[onclick="switchTab('${tabName}')"]`).classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        // Fonctions JavaScript principales
        async function hashAndSign() {
            const data = document.getElementById('hashSignInput').value;
            const algorithm = document.getElementById('hashAlgorithm').value;
            
            if (!data) {
                showResult(' Veuillez entrer des données', 'error');
                return;
            }

            showResult("⏳ Hachage et signature en cours...", 'info');
            try {
                const response = await fetch('/hash-and-sign', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data, algorithm})
                });
                const result = await response.json();
                displayHashSignResult(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        async function verifyHashSignature() {
            const data = document.getElementById('hashSignInput').value;
            const signature = prompt('Signature à vérifier:');
            const expectedHash = prompt('Hash attendu:');
            const algorithm = document.getElementById('hashAlgorithm').value;
            
            if (!data || !signature || !expectedHash) {
                showResult(' Données manquantes', 'error');
                return;
            }

            showResult("⏳ Vérification intégrité + authenticité...", 'info');
            try {
                const response = await fetch('/verify-hash-signature', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data, signature, expected_hash: expectedHash, algorithm})
                });
                const result = await response.json();
                displayVerificationResult(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        async function computeHash() {
            const data = document.getElementById('hashInput').value;
            const algorithm = document.getElementById('hashAlgorithm').value;
            
            if (!data) {
                showResult(' Veuillez entrer des données', 'error');
                return;
            }

            showResult("⏳ Calcul du hash...", 'info');
            try {
                const response = await fetch('/compute-hash', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data, algorithm})
                });
                const result = await response.json();
                displayHashResult(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        async function benchmarkPerformance() {
            showResult("⏳ Analyse des performances cryptographiques...", 'info');
            try {
                const response = await fetch('/benchmark/performance', {method: 'POST'});
                const result = await response.json();
                displayPerformanceResults(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        async function benchmarkHashAlgorithms() {
            const data = document.getElementById('hashInput').value || "Test data for hashing benchmark";
            
            showResult("⏳ Benchmark des algorithmes de hachage...", 'info');
            try {
                const response = await fetch('/benchmark/hash-algorithms', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data})
                });
                const result = await response.json();
                displayHashBenchmarkResults(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        async function demonstrateConcepts() {
            showResult("⏳ Démonstration des concepts cryptographiques...", 'info');
            try {
                const response = await fetch('/demonstrate/concepts', {method: 'POST'});
                const result = await response.json();
                displayConceptsDemo(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        async function demonstrateCollisionResistance() {
            showResult("⏳ Démonstration résistance aux collisions...", 'info');
            try {
                const response = await fetch('/demonstrate/collision-resistance', {method: 'POST'});
                const result = await response.json();
                displayCollisionDemo(result);
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }

        // Fonctions d'affichage des résultats
        function displayHashSignResult(result) {
            if (result.success) {
                let html = ` <strong>Hachage + Signature réussis!</strong><br><br>`;
                html += `<strong>Hash (${result.hash_algorithm}):</strong><br><div class="code-block">${result.hash}</div><br>`;
                html += `<strong>Signature:</strong><br><div class="code-block">${result.signature}</div><br>`;
                html += `<strong>Performance:</strong><br>`;
                html += `<div class="code-block">${JSON.stringify(result.performance, null, 2)}</div>`;
                showResult(html, 'success');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

function displayPerformanceResults(result) {
    if (result.success) {
        let html = `📊 <strong>Analyse des Performances</strong><br><br>`;

        // Affichage du graphique si présent
        if (result.performance_chart) {
            html += `
                <div style="width: 100%; max-width: 600px; margin: 15px auto;
                            background: white; border-radius: 10px; padding: 10px;">
                    <img src="${result.performance_chart}"
                         style="width: 100%; border-radius: 8px;">
                </div><br>`;
        }

        // Affichage des données envoyées par l'API
        html += `<strong>Résultats détaillés :</strong><br><br>`;

        if (result.key_size_analysis) {
            html += `<div class="concept-item">
                        🔑 <strong>Analyse tailles de clés :</strong><br>
                        ${JSON.stringify(result.key_size_analysis, null, 2)}
                     </div><br>`;
        }

        if (result.hsm_vs_software) {
            html += `<div class="concept-item">
                        ⚙️ <strong>HSM vs Logiciel :</strong><br>
                        ${JSON.stringify(result.hsm_vs_software, null, 2)}
                     </div><br>`;
        }

        if (result.encryption_modes) {
            html += `<div class="concept-item">
                        🔐 <strong>Modes de chiffrement :</strong><br>
                        ${JSON.stringify(result.encryption_modes, null, 2)}
                     </div><br>`;
        }

        showResult(html, 'info');
    } else {
        showResult(` Erreur: ${result.error}`, 'error');
    }
}


        function displayConceptsDemo(result) {
            if (result.success) {
                let html = `🎓 <strong>Concepts Cryptographiques</strong><br><br>`;
                html += `<div class="concept-grid">`;
                
                for (const [key, concept] of Object.entries(result.concepts)) {
                    html += `<div class="concept-item">`;
                    html += `<h4>${concept.name}</h4>`;
                    html += `<div>${concept.explanation}</div>`;
                    html += `<div style="margin-top: 8px; font-size: 0.8rem; color: ${concept.success ? '#10b981' : '#ef4444'}">`;
                    html += `✓ Démonstration: ${concept.success !== undefined ? (concept.success ? 'SUCCÈS' : 'ÉCHEC') : 'N/A'}`;
                    html += `</div></div>`;
                }
                
                html += `</div>`;
                showResult(html, 'info');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

        function displayHashResult(result) {
            if (result.success) {
                let html = `🗳️ <strong>Hash calculé</strong><br><br>`;
                html += `<strong>Algorithme:</strong> ${result.algorithm}<br>`;
                html += `<strong>Hash:</strong><br><div class="code-block">${result.hash}</div><br>`;
                html += `<strong>Temps:</strong> ${result.processing_time}<br>`;
                showResult(html, 'success');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

        function displayVerificationResult(result) {
            if (result.success) {
                const isValid = result.valid;
                let html = isValid ? 
                    ` <strong>VÉRIFICATION RÉUSSIE</strong><br>` :
                    ` <strong>VÉRIFICATION ÉCHOUÉE</strong><br>`;
                html += `<div>${result.message}</div>`;
                showResult(html, isValid ? 'success' : 'error');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

        function displayHashBenchmarkResults(result) {
            if (result.success) {
                let html = `🔍 <strong>Benchmark Algorithmes de Hachage</strong><br><br>`;
                
                for (const [algo, data] of Object.entries(result.results)) {
                    if (!data.error) {
                        html += `<div class="concept-item">`;
                        html += `<strong>${algo.toUpperCase()}:</strong><br>`;
                        html += `Temps: ${(data.time_per_operation * 1000).toFixed(3)} ms/op<br>`;
                        html += `Taille hash: ${data.hash_length} caractères<br>`;
                        html += `Exemple: ${data.hash_sample}<br>`;
                        html += `</div>`;
                    }
                }
                
                showResult(html, 'info');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

        function displayCollisionDemo(result) {
            if (result.success) {
                let html = `🛡️ <strong>Résistance aux Collisions</strong><br><br>`;
                
                result.demonstrations.forEach(demo => {
                    html += `<div class="concept-item">`;
                    html += `<h4>${demo.concept}</h4>`;
                    html += `<div>${demo.description}</div><br>`;
                    if (demo.original) html += `<div>Original: ${demo.original}</div>`;
                    if (demo.modified) html += `<div>Modifié: ${demo.modified}</div>`;
                    if (demo.changed !== undefined) {
                        html += `<div style="color: ${demo.changed ? '#10b981' : '#ef4444'}">`;
                        html += `Hash changé: ${demo.changed ? 'OUI ✓' : 'NON ✗'}</div>`;
                    }
                    html += `</div>`;
                });
                
                showResult(html, 'info');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

        function showResult(message, type = "info") {
            const resultDiv = document.getElementById('results');
            resultDiv.innerHTML = `
                <div class="card">
                    <div class="result ${type}">
                        ${message}
                    </div>
                </div>
            `;
            resultDiv.scrollIntoView({ behavior: 'smooth' });
        }


// Variables globales
let availableKeys = [];

// Charger la liste des clés
async function loadKeys() {
    try {
        const response = await fetch('/api/keys/list');
        const result = await response.json();

        if (result.success) {
            availableKeys = result.keys;
            updateKeySelector(availableKeys);
            showResult(` ${result.keys.length} clé(s) chargée(s)`, 'success');
        } else {
            showResult(` Erreur: ${result.error}`, 'error');
        }
    } catch (error) {
        showResult(` Erreur réseau: ${error.message}`, 'error');
    }
}

// Mettre à jour le sélecteur de clés
function updateKeySelector(keys) {
    const selector = document.getElementById('keySelector');
    selector.innerHTML = '';

    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.disabled = true;
    placeholder.selected = true;

    if (!keys || keys.length === 0) {
        placeholder.textContent = 'Aucune clé disponible';
        selector.appendChild(placeholder);
        selector.disabled = true;
        hideKeyInfo();
        return;
    }

    const normalizeStatus = status => (status || 'active').toLowerCase();
    const activeKeys = keys.filter(key => normalizeStatus(key.status) === 'active');

    placeholder.textContent = activeKeys.length
        ? 'Sélectionner une clé...'
        : 'Toutes les clés sont désactivées';
    selector.appendChild(placeholder);
    selector.disabled = false;

    keys.forEach(key => {
        const option = document.createElement('option');
        option.value = key.key_id;
        const usageCount = typeof key.usage_count === 'number' ? key.usage_count : 0;
        const keySize = key.key_size || '—';
        const status = normalizeStatus(key.status);
        const statusSuffix = status !== 'active'
            ? ` • ${status === 'inactive' ? 'désactivée' : status}`
            : '';

        option.textContent = `${key.key_id} (${keySize} bits) - ${usageCount} utilisations${statusSuffix}`;
        option.dataset.status = status;
        selector.appendChild(option);
    });

    // Afficher les infos quand une clé est sélectionnée
    selector.onchange = function() {
        const selectedKeyId = this.value;
        if (selectedKeyId) {
            showKeyInfo(selectedKeyId);
        } else {
            hideKeyInfo();
        }
    };
}

// Afficher les informations d'une clé
function showKeyInfo(keyId) {
    const key = availableKeys.find(k => k.key_id === keyId);
    if (!key) return;

    const status = (key.status || 'active').toLowerCase();
    const statusLabel = status === 'active' ? '🟢 Active' : '⛔ Désactivée';

    const keyInfoDiv = document.getElementById('keyInfo');
    const keyDetailsDiv = document.getElementById('keyDetails');

    keyDetailsDiv.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div><strong>ID:</strong></div>
            <div>${key.key_id}</div>

            <div><strong>Type:</strong></div>
            <div>${key.key_type}</div>

            <div><strong>Taille:</strong></div>
            <div>${key.key_size} bits</div>

            <div><strong>Statut:</strong></div>
            <div>${statusLabel}</div>

            <div><strong>Créée le:</strong></div>
            <div>${new Date(key.created_at).toLocaleString('fr-FR')}</div>

            <div><strong>Utilisations:</strong></div>
            <div>${key.usage_count}</div>

            <div><strong>Dernière utilisation:</strong></div>
            <div>${key.last_used ? new Date(key.last_used).toLocaleString('fr-FR') : 'Jamais'}</div>
        </div>

        <div style="margin-top: 15px;">
            <button class="btn btn-success" onclick="useSelectedKeyForOperation('sign')">
                ✍️ Utiliser pour Signature
            </button>
            <button class="btn" onclick="useSelectedKeyForOperation('encrypt')">
                🔐 Utiliser pour Chiffrement
            </button>
            <button class="btn" onclick="useSelectedKeyForOperation('hash-sign')">
                🔐 Utiliser pour Hachage+Signature
            </button>
        </div>

        ${status !== 'active' ? `
            <div style="margin-top: 12px; padding: 10px; border-radius: 10px; background: rgba(239, 68, 68, 0.12); color: #fca5a5;">
                Cette clé est désactivée. Activez-la depuis l'onglet \"Gestion des clés\" avant de l'utiliser pour une opération.
            </div>` : ''}
    `;

    keyInfoDiv.style.display = 'block';
}

// Cacher les informations de clé
function hideKeyInfo() {
    document.getElementById('keyInfo').style.display = 'none';
}

// Utiliser la clé sélectionnée pour une opération
function useSelectedKeyForOperation(operationType) {
    const keySelector = document.getElementById('keySelector');
    const selectedKeyId = keySelector.value;
    const selectedKey = availableKeys.find(k => k.key_id === selectedKeyId);

    if (!selectedKeyId) {
        showResult(' Veuillez sélectionner une clé', 'error');
        return;
    }

    if (selectedKey && (selectedKey.status || '').toLowerCase() !== 'active') {
        showResult(' Cette clé est désactivée. Réactivez-la dans la gestion des clés pour l\'utiliser.', 'error');
        return;
    }

    switch(operationType) {
        case 'sign':
            document.getElementById('simpleDataInput').focus();
            showResult(` Clé ${selectedKeyId} sélectionnée pour signature. Remplissez les données et cliquez sur "Signer".`, 'success');
            break;
        case 'encrypt':
            document.getElementById('simpleEncryptInput').focus();
            showResult(` Clé ${selectedKeyId} sélectionnée pour chiffrement. Remplissez les données et cliquez sur "Chiffrer".`, 'success');
            break;
        case 'hash-sign':
            document.getElementById('hashSignInput').focus();
            showResult(` Clé ${selectedKeyId} sélectionnée pour hachage+signature. Remplissez les données et cliquez sur "Hacher+Signer".`, 'success');
            break;
    }
}

// Modifier les fonctions existantes pour utiliser la clé sélectionnée
async function simpleSignData() {
    const data = document.getElementById('simpleDataInput').value;
    const keyId = document.getElementById('keySelector').value;

    if (!data) {
        showResult(' Veuillez entrer des données à signer', "error");
        return;
    }

    showResult("⏳ Signature cryptographique en cours...", "warning");
    try {
        const response = await fetch('/sign', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({data, key_id: keyId || null})
        });
        const result = await response.json();
        if (result.success) {
            let html = ` <strong>Signature créée avec succès!</strong><br><br>`;
            if (keyId) html += `<strong>Clé utilisée:</strong> ${keyId}<br>`;
            html += `<strong>Signature numérique:</strong>
                    <div class="code-block">${result.signature}</div>
                    <div class="performance">⏱️ ${result.processing_time}</div>`;
            showResult(html, "success");

            // Recharger la liste pour mettre à jour les compteurs
            setTimeout(loadKeys, 1000);
        } else {
            showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
        }
    } catch (error) {
        showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
    }
}

async function simpleEncryptData() {
    const data = document.getElementById('simpleEncryptInput').value;
    const keyId = document.getElementById('keySelector').value;

    if (!data) {
        showResult(' Veuillez entrer des données à chiffrer', "error");
        return;
    }

    showResult("⏳ Chiffrement RSA en cours...", "warning");
    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({data, key_id: keyId || null})
        });
        const result = await response.json();
        if (result.success) {
            let html = ` <strong>Données chiffrées avec succès!</strong><br><br>`;
            if (keyId) html += `<strong>Clé utilisée:</strong> ${keyId}<br>`;
            html += `<strong>Message chiffré:</strong>
                    <div class="code-block">${result.encrypted_data}</div>`;

            // Afficher le temps seulement s'il est disponible
            if (result.processing_time) {
                html += `<div class="performance">⏱️ ${result.processing_time}</div>`;
            }

            showResult(html, "success");

            // Recharger la liste pour mettre à jour les compteurs
            setTimeout(loadKeys, 1000);
        } else {
            showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
        }
    } catch (error) {
        showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
    }
}

async function hashAndSign() {
    const data = document.getElementById('hashSignInput').value;
    const algorithm = document.getElementById('hashAlgorithm').value;
    const keyId = document.getElementById('keySelector').value;

    if (!data) {
        showResult(' Veuillez entrer des données', 'error');
        return;
    }

    showResult("⏳ Hachage et signature en cours...", 'info');
    try {
        const response = await fetch('/hash-and-sign', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({data, algorithm, key_id: keyId || null})
        });
        const result = await response.json();
        displayHashSignResult(result);

        // Recharger la liste pour mettre à jour les compteurs
        if (result.success) {
            setTimeout(loadKeys, 1000);
        }
    } catch (error) {
        showResult(` Erreur: ${error.message}`, 'error');
    }
}

// Charger les clés au démarrage
document.addEventListener('DOMContentLoaded', function() {
    loadKeys();
});



        // Fonctions pour les opérations simples
        async function generateKeys() {
    const keyTypeField = document.getElementById('keyTypeSelect');
    const keyLabelField = document.getElementById('keyLabelInput');
    const selectedType = keyTypeField ? keyTypeField.value : 'RSA';
    const keyLabel = keyLabelField ? keyLabelField.value.trim() : '';

    if (keyLabelField && !keyLabel) {
        showResult(' Veuillez saisir un label pour la clé', 'error');
        return;
    }

    showResult(`⏳ Génération de la clé ${selectedType} 2048 bits en cours...`, "warning");
    try {
        const payload = { key_size: 2048, key_type: selectedType };
        if (keyLabel) {
            payload.key_label = keyLabel;
        }

        const response = await fetch('/api/keys/generate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (result.success) {
            let html = ` <strong>Clé générée avec succès!</strong><br>`;
            html += `<strong>ID de la clé:</strong> ${result.key_id || keyLabel || '—'}<br>`;
            html += `<strong>Type:</strong> ${result.key_type || selectedType}<br>`;
            html += `<strong>Taille:</strong> ${result.key_size} bits<br>`;
            if (result.key_label || keyLabel) {
                html += `<strong>Label:</strong> ${result.key_label || keyLabel}<br>`;
            }
            html += `<strong>Stockage:</strong> ${result.stored_in_db ? ' Base de données' : ' Non stockée'}<br>`;
            html += `<div class="performance">⏱️ ${result.processing_time}</div>`;

            html += `<br><div style="margin-top: 15px;">
                <a href="/keys" style="display: inline-block; background: var(--primary); color: white; padding: 10px 15px; border-radius: 8px; text-decoration: none; font-weight: 600;">
                    📋 Voir toutes les clés
                </a>
            </div>`;

            showResult(html, "success");
        } else {
            showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
        }
    } catch (error) {
        showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
    }
}
        async function simpleSignData() {
            const data = document.getElementById('simpleDataInput').value;
            if (!data) {
                showResult(' Veuillez entrer des données à signer', "error");
                return;
            }

            showResult("⏳ Signature cryptographique en cours...", "warning");
            try {
                const response = await fetch('/sign', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data})
                });
                const result = await response.json();
                if (result.success) {
                    showResult(` <strong>Signature créée avec succès!</strong><br><br>
                            <strong>Signature numérique:</strong>
                            <div class="code-block">${result.signature}</div>
                            <div class="performance">⏱️ ${result.processing_time}</div>`, "success");
                } else {
                    showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
                }
            } catch (error) {
                showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
            }
        }

        async function simpleVerifyData() {
            const data = document.getElementById('simpleDataInput').value;
            if (!data) {
                showResult(' Veuillez entrer des données à vérifier', "error");
                return;
            }

            const signature = prompt('Collez la signature à vérifier:');
            if (signature) {
                showResult("⏳ Vérification de l'authenticité...", "warning");
                try {
                    const response = await fetch('/verify', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({data, signature})
                    });
                    const result = await response.json();
                    if (result.success) {
                        const isValid = result.valid;
                        showResult(isValid ?
                            ` <strong>Signature VALIDE</strong> - Document authentique<br>
                            <div class="performance">⏱️ ${result.processing_time}</div>` :
                            ` <strong>Signature INVALIDE</strong> - Document corrompu<br>
                            <div class="performance">⏱️ ${result.processing_time}</div>`,
                            isValid ? "success" : "error"
                        );
                    } else {
                        showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
                    }
                } catch (error) {
                    showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
                }
            }
        }

        async function simpleEncryptData() {
            const data = document.getElementById('simpleEncryptInput').value;
            if (!data) {
                showResult(' Veuillez entrer des données à chiffrer', "error");
                return;
            }

            showResult("⏳ Chiffrement RSA en cours...", "warning");
            try {
                const response = await fetch('/encrypt', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({data})
                });
                const result = await response.json();
                if (result.success) {
                    showResult(` <strong>Données chiffrées avec succès!</strong><br><br>
                            <strong>Message chiffré:</strong>
                            <div class="code-block">${result.encrypted_data}</div>
                            <div class="performance">⏱️ ${result.processing_time}</div>`, "success");
                } else {
                    showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
                }
            } catch (error) {
                showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
            }
        }

        async function simpleDecryptData() {
    const encrypted_data = prompt('Collez les données chiffrées:');
    if (encrypted_data) {
        showResult("Déchiffrement sécurisé en cours...", "warning");
        try {
            const response = await fetch('/decrypt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({encrypted_data})
            });
            const result = await response.json();
            if (result.success) {
                let html = ` <strong>Données déchiffrées avec succès!</strong><br><br>`;
                html += `<strong>Message original:</strong>`;
                html += `<div class="code-block">${result.decrypted_data}</div>`;

                // Afficher le temps de traitement seulement s'il est disponible
                if (result.processing_time) {
                    html += `<div class="performance">⏱️ ${result.processing_time}</div>`;
                }

                showResult(html, "success");
            } else {
                showResult(` <strong>Erreur:</strong> ${result.error}`, "error");
            }
        } catch (error) {
            showResult(` <strong>Erreur réseau:</strong> ${error.message}`, "error");
        }
    }
}


        // Stockage du dernier résultat
        let lastHashSignResult = null;

        // Gestion de l'affichage de la section de vérification
        function showVerificationSection() {
            document.getElementById('verificationSection').style.display = 'block';
            // Faire défiler jusqu'à la section de vérification
            document.getElementById('verificationSection').scrollIntoView({ behavior: 'smooth' });
        }

        function hideVerificationSection() {
            document.getElementById('verificationSection').style.display = 'none';
            // Vider les champs
            document.getElementById('verificationSignature').value = '';
            document.getElementById('verificationHash').value = '';
        }

        // Remplissage automatique si des résultats sont disponibles
        function autoFillVerification() {
            const lastResult = getLastHashSignResult();
            if (lastResult) {
                document.getElementById('verificationSignature').value = lastResult.signature || '';
                document.getElementById('verificationHash').value = lastResult.hash || '';
                showResult(" Données remplies automatiquement depuis la dernière opération", "success");
            } else {
                showResult(" Aucune donnée disponible pour le remplissage automatique", "error");
            }
        }

        // Fonction pour récupérer le dernier résultat
        function getLastHashSignResult() {
            return lastHashSignResult;
        }

        // Fonction de copie dans le presse-papier
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Afficher une notification temporaire
                const notification = document.createElement('div');
                notification.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: var(--success);
                    color: white;
                    padding: 10px 15px;
                    border-radius: 5px;
                    z-index: 1000;
                    font-weight: 600;
                `;
                notification.textContent = ' Copié !';
                document.body.appendChild(notification);
                
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 2000);
            }).catch(err => {
                console.error('Erreur de copie:', err);
            });
        }

        // Fonction pour afficher les résultats de hachage + signature (SANS le bouton "Vérifier Maintenant")
        function displayHashSignResult(result) {
            if (result.success) {
                // Stocker le résultat pour remplissage automatique
                lastHashSignResult = {
                    signature: result.signature,
                    hash: result.hash,
                    algorithm: result.hash_algorithm
                };
                
                let html = ` <strong>Hachage + Signature réussis!</strong><br><br>`;
                html += `<strong>Hash (${result.hash_algorithm}):</strong><br>`;
                html += `<div class="code-block" onclick="copyToClipboard('${result.hash}')" style="cursor: pointer;" title="Cliquer pour copier">${result.hash}</div><br>`;
                html += `<strong>Signature:</strong><br>`;
                html += `<div class="code-block" onclick="copyToClipboard('${result.signature}')" style="cursor: pointer;" title="Cliquer pour copier">${result.signature}</div><br>`;
                html += `<strong>Performance:</strong><br>`;
                html += `<div class="code-block">${JSON.stringify(result.performance, null, 2)}</div>`;
                
                // NOTE: Le bouton "Vérifier Maintenant" a été supprimé ici
                showResult(html, 'success');
            } else {
                showResult(` Erreur: ${result.error}`, 'error');
            }
        }

        // Version modifiée de verifyHashSignature
        async function verifyHashSignature() {
            const data = document.getElementById('hashSignInput').value;
            const signature = document.getElementById('verificationSignature').value;
            const expectedHash = document.getElementById('verificationHash').value;
            const algorithm = document.getElementById('hashAlgorithm').value;
            
            if (!data) {
                showResult(' Veuillez entrer des données dans la zone principale', 'error');
                return;
            }
            
            if (!signature || !expectedHash) {
                showResult(' Veuillez remplir tous les champs de vérification', 'error');
                return;
            }

            showResult("⏳ Vérification intégrité + authenticité...", 'info');
            try {
                const response = await fetch('/verify-hash-signature', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        data, 
                        signature, 
                        expected_hash: expectedHash, 
                        algorithm
                    })
                });
                const result = await response.json();
                displayVerificationResult(result);
                
                // Cacher la section de vérification après un succès
                if (result.success && result.valid) {
                    setTimeout(() => {
                        hideVerificationSection();
                    }, 2000);
                }
            } catch (error) {
                showResult(` Erreur: ${error.message}`, 'error');
            }
        }
