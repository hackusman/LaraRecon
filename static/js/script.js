// Script principal de l'interface

document.addEventListener('DOMContentLoaded', function() {
    const startScanBtn = document.getElementById('startScan');
    const targetUrlInput = document.getElementById('targetUrl');
    const scanModal = document.getElementById('scanModal');
    const closeModal = document.querySelector('.close');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const currentSection = document.getElementById('currentSection');

    // Démarrer le scan
    startScanBtn.addEventListener('click', function() {
        const targetUrl = targetUrlInput.value.trim();
        
        if (!targetUrl) {
            alert('Veuillez entrer une URL à scanner');
            return;
        }

        // Afficher le modal
        scanModal.style.display = 'block';

        // Désactiver le bouton pendant le scan
        startScanBtn.disabled = true;
        startScanBtn.textContent = 'Scan en cours...';

        // Envoyer la requête au backend
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: targetUrl })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert(data.error);
                closeModalHandler();
                return;
            }

            const scanId = data.scan_id;
            
            // Polling pour suivre la progression
            const pollInterval = setInterval(() => {
                fetch(`/scan/status/${scanId}`)
                    .then(response => response.json())
                    .then(status => {
                        // Mettre à jour la barre de progression
                        if (status.progress !== undefined) {
                            progressBar.style.setProperty('--progress', status.progress);
                            progressText.textContent = `${status.progress}%`;
                        }

                        // Mettre à jour la section en cours
                        if (status.current_section) {
                            currentSection.textContent = status.current_section;
                        }

                        // Vérifier si le scan est terminé
                        if (status.status === 'completed') {
                            clearInterval(pollInterval);
                            window.location.href = `/scan/results/${scanId}`;
                        } else if (status.status === 'error') {
                            clearInterval(pollInterval);
                            alert(`Erreur lors du scan : ${status.error}`);
                            closeModalHandler();
                        }
                    })
                    .catch(error => {
                        console.error('Erreur:', error);
                    });
            }, 1000);
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert('Une erreur est survenue lors du démarrage du scan');
            closeModalHandler();
        });
    });

    // Fermer le modal
    closeModal.addEventListener('click', closeModalHandler);

    function closeModalHandler() {
        scanModal.style.display = 'none';
        startScanBtn.disabled = false;
        startScanBtn.textContent = 'Démarrer le scan';
        progressBar.style.setProperty('--progress', '0');
        progressText.textContent = '0%';
        currentSection.textContent = 'Initialisation...';
    }

    // Fermer le modal en cliquant en dehors
    window.addEventListener('click', function(event) {
        if (event.target === scanModal) {
            // Ne pas fermer automatiquement si le scan est en cours
            const scanBtn = document.getElementById('startScan');
            if (!scanBtn.disabled) {
                closeModalHandler();
            }
        }
    });

    // Focus automatique sur l'input au chargement
    targetUrlInput.focus();
});
