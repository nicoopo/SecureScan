import { Controller } from '@hotwired/stimulus';

/*
 * Pilote le bouton "Pousser vers GitHub" du rapport : pousse la branche de
 * corrections du scan et ouvre une pull request via ReportController::pushFixes().
 */
export default class extends Controller {
    static targets = ['button', 'toast'];
    static values = { scanId: Number, csrfToken: String };

    push() {
        this.buttonTarget.disabled = true;
        const originalText = this.buttonTarget.textContent;
        this.buttonTarget.textContent = 'Envoi...';

        fetch(`/report/${this.scanIdValue}/push-fixes`, {
            method: 'POST',
            headers: { 'X-CSRF-Token': this.csrfTokenValue },
        })
            .then((response) => response.json())
            .then((data) => {
                this.showToast(data.success ? 'success' : 'error', data.message);
                if (data.prUrl) {
                    window.open(data.prUrl, '_blank', 'noopener');
                }
            })
            .catch(() => {
                this.showToast('error', "Échec de l'envoi vers GitHub.");
            })
            .finally(() => {
                this.buttonTarget.disabled = false;
                this.buttonTarget.textContent = originalText;
            });
    }

    showToast(kind, message) {
        if (!this.hasToastTarget || !message) return;

        const styles = {
            success: 'bg-emerald-600 text-white',
            error:   'bg-red-600 text-white',
        };

        this.toastTarget.className =
            `fixed bottom-6 right-6 max-w-sm px-4 py-3 rounded-lg shadow-lg text-sm z-50 transition-opacity duration-200 ${styles[kind]}`;
        this.toastTarget.textContent = message;
        this.toastTarget.classList.remove('hidden', 'opacity-0');

        clearTimeout(this.toastTimeout);
        this.toastTimeout = setTimeout(() => {
            this.toastTarget.classList.add('opacity-0');
            setTimeout(() => this.toastTarget.classList.add('hidden'), 200);
        }, 4000);
    }
}