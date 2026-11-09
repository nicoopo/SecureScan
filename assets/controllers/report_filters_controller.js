import { Controller } from '@hotwired/stimulus';

/*
 * Filtre les lignes de la table de findings par sévérité / catégorie OWASP / outil,
 * sans recharger la page, et persiste le filtre actif dans l'URL.
 */
export default class extends Controller {
    static targets = ['severity', 'owasp', 'tool', 'row', 'count'];

    connect() {
        this.apply();
    }

    apply() {
        const severity = this.severityTarget.value;
        const owasp    = this.owaspTarget.value;
        const tool     = this.toolTarget.value;

        let visible = 0;
        this.rowTargets.forEach((row) => {
            const show =
                (!severity || row.dataset.severity === severity) &&
                (!owasp    || row.dataset.owasp    === owasp) &&
                (!tool     || row.dataset.tool      === tool);
            row.classList.toggle('hidden', !show);
            if (show) visible++;
        });

        this.countTarget.textContent = `${visible} / ${this.rowTargets.length}`;
        this.updateUrl(severity, owasp, tool);
    }

    updateUrl(severity, owasp, tool) {
        const params = new URLSearchParams();
        if (severity) params.set('severity', severity);
        if (owasp)    params.set('owasp', owasp);
        if (tool)     params.set('tool', tool);

        const newUrl = params.toString()
            ? `${window.location.pathname}?${params.toString()}`
            : window.location.pathname;
        history.replaceState(null, '', newUrl);
    }
}
