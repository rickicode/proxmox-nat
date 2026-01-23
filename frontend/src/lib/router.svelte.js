// Simple router for Svelte 5
// Using a class to manage state reactively

class RouterState {
    path = $state(typeof window !== 'undefined' ? window.location.pathname : '/');

    constructor() {
        if (typeof window !== 'undefined') {
            window.addEventListener('popstate', () => {
                this.path = window.location.pathname;
            });
        }
    }

    navigate(to, options = {}) {
        if (typeof window === 'undefined') return;

        if (options.replace) {
            window.history.replaceState({}, '', to);
        } else {
            window.history.pushState({}, '', to);
        }
        this.path = to;
    }
}

export const router = new RouterState();

export function navigate(to, options = {}) {
    router.navigate(to, options);
}

export function getCurrentPath() {
    return router.path;
}
