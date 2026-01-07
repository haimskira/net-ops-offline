/**
 * Theme Manager
 * Handles toggling between Dark and Light modes and persisting preference.
 */

const ThemeManager = {
    init() {
        // 1. Initial Load
        const storedTheme = localStorage.getItem('theme');
        const isLight = storedTheme === 'light';
        this.applyTheme(isLight);

        // 2. Listen for storage changes (Cross-tab)
        window.addEventListener('storage', (e) => {
            if (e.key === 'theme') {
                this.applyTheme(e.newValue === 'light');
            }
        });

        // 3. Listen for direct messages (iframe communication)
        window.addEventListener('message', (e) => {
            if (e.data && e.data.type === 'THEME_CHANGE') {
                this.applyTheme(e.data.isLight);
            }
        });
    },

    applyTheme(isLight) {
        if (isLight) {
            document.documentElement.classList.add('light-mode');
        } else {
            document.documentElement.classList.remove('light-mode');
        }
    },

    toggle() {
        const isLight = document.documentElement.classList.toggle('light-mode');
        localStorage.setItem('theme', isLight ? 'light' : 'dark');

        // Update button icon if it exists
        const btn = document.getElementById('theme-toggle-btn');
        if (btn) {
            btn.innerHTML = isLight ? '🌙' : '☀️';
            btn.title = isLight ? 'עבור למצב לילה' : 'עבור למצב יום';
        }

        // Broadcast to all iframes
        const iframes = document.querySelectorAll('iframe');
        iframes.forEach(iframe => {
            try {
                iframe.contentWindow.postMessage({ type: 'THEME_CHANGE', isLight }, '*');
            } catch (e) {
                // Ignore cross-origin issues if any
            }
        });
    }
};

// Initialize on load
ThemeManager.init();

// Expose to window
window.ThemeManager = ThemeManager;
