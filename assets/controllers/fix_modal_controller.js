import { Controller } from '@hotwired/stimulus';

/*
 * Pilote la modale d'affichage/décision d'une correction (Fix) proposée
 * pour un finding : ouverture depuis le bouton "Voir fix", accept/reject
 * via fetch vers ReportController::acceptFix()/rejectFix().
 */
export default class extends Controller {
    static targets = [
        'overlay', 'panel', 'badge', 'title', 'location',
        'explanation', 'originalWrap', 'original', 'proposed', 'actions', 'toast',
    ];
    static values = { csrfToken: String };

    connect() {
        this.current = null;
    }

    open(event) {
        this.current = event.currentTarget;
        const d = this.current.dataset;

        this.badgeTarget.textContent = d.owasp || '';
        this.titleTarget.textContent = d.title;
        this.locationTarget.textContent = d.file
            ? `${d.file}${d.line ? ' · ligne ' + d.line : ''}`
            : '';
        this.explanationTarget.textContent = d.explanation || 'Aucune explication disponible.';
        this.proposedTarget.textContent = d.proposed || '';

        if (d.original) {
            this.originalWrapTarget.classList.remove('hidden');
            this.originalTarget.textContent = d.original;
        } else {
            this.originalWrapTarget.classList.add('hidden');
        }

        this.actionsTarget.classList.toggle('hidden', d.fixStatus !== 'pending');

        this.overlayTarget.classList.remove('hidden');
        requestAnimationFrame(() => {
            this.overlayTarget.classList.remove('opacity-0');
            this.panelTarget.classList.remove('opacity-0', 'scale-95');
        });
        document.addEventListener('keydown', this.onKeydown);
    }

    close() {
        this.overlayTarget.classList.add('opacity-0');
        this.panelTarget.classList.add('opacity-0', 'scale-95');
        document.removeEventListener('keydown', this.onKeydown);
        setTimeout(() => this.overlayTarget.classList.add('hidden'), 150);
        this.current = null;
    }

    backdropClose(event) {
        if (event.target === this.overlayTarget) this.close();
    }

    onKeydown = (event) => {
        if (event.key === 'Escape') this.close();
    };

    accept() { this.decide('accept'); }
    reject() { this.decide('reject'); }

    decide(action) {
        if (!this.current) return;
        const button = this.current;
        const fixId  = button.dataset.fixId;

        this.actionsTarget.querySelectorAll('button').forEach((b) => (b.disabled = true));

        fetch(`/report/fix/${fixId}/${action}`, {
            method: 'POST',
            headers: { 'X-CSRF-Token': this.csrfTokenValue },
        })
            .then((response) => {
                if (!response.ok) throw new Error('Échec de la requête');
                return response.json();
            })
            .then((data) => {
                button.dataset.fixStatus = data.status;
                button.textContent = data.status === 'accepted' ? 'Appliqué' : 'Rejeté';
                this.close();

                if (data.status === 'accepted') {
                    this.showToast(data.applied ? 'success' : 'warning', data.message);
                }
            })
            .catch(() => {
                this.showToast('error', 'Une erreur est survenue lors de la mise à jour du fix.');
            })
            .finally(() => {
                this.actionsTarget.querySelectorAll('button').forEach((b) => (b.disabled = false));
            });
    }

    showToast(kind, message) {
        if (!this.hasToastTarget || !message) return;

        const styles = {
            success: 'bg-emerald-600 text-white',
            warning: 'bg-amber-500 text-white',
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
