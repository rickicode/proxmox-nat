export class AppState {
    darkMode = $state(true);
    sidebarOpen = $state(false);
    prefillRule = $state(null);

    toggleSidebar() {
        this.sidebarOpen = !this.sidebarOpen;
    }

    setSidebar(value) {
        this.sidebarOpen = value;
    }

    toggleTheme() {
        this.darkMode = !this.darkMode;
        if (this.darkMode) {
            document.documentElement.classList.add('dark');
            localStorage.theme = 'dark';
        } else {
            document.documentElement.classList.remove('dark');
            localStorage.theme = 'light';
        }
    }
}

export const appState = new AppState();
