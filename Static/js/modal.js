class AppModal {
    constructor() {
        this.modal = document.getElementById('app-modal');
        this.modalTitle = document.getElementById('modal-title');
        this.appContainer = document.getElementById('app-container');
        this.closeBtn = document.querySelector('.close-modal');
        this.currentApp = null;
        
        this.appScripts = {
            'notes': { path: '/static/js/notes.js' },
            'upload': { path: '/static/files.js' },
            'admin': { path: '/static/js/admin.js' },
            'chat': { path: '/static/js/chat.js' },
            'api': { path: '/static/js/api.js' },
            '401k': { path: '/static/js/401k.js' }
        };
        
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        this.closeBtn.addEventListener('click', () => this.closeModal());
        
        window.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.closeModal();
            }
        });

        document.querySelectorAll('.app-card').forEach(card => {
            card.addEventListener('click', (e) => {
                e.preventDefault();
                const appTitle = card.querySelector('h3').textContent;
                const appPath = card.getAttribute('data-app');
                this.openApp(appTitle, appPath);
            });
        });
    }

    async loadAppScript(appName) {
        const scriptInfo = this.appScripts[appName];
        const scriptPath = scriptInfo ? scriptInfo.path : `/static/js/${appName}.js`;
        
        const existingScripts = document.querySelectorAll(`script[data-app-name="${appName}"]`);
        existingScripts.forEach(script => script.remove());
        
        console.log(`Loading script: ${scriptPath}`);
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = scriptPath;
            script.onload = () => resolve();
            script.onerror = () => reject();
            script.dataset.appName = appName; // Tags script for removal
            document.head.appendChild(script);
        });
    }

    async openApp(title, appPath) {
        console.log(`Opening app: ${appPath}`);
        this.modalTitle.textContent = title;
        this.currentApp = appPath;
        
        try {
            this.cleanupPreviousApp();
            
            const response = await fetch(`/apps/${appPath}`);
            if(!response.ok) throw new Error(`Failed to load ${appPath}`);
            const appContent = await response.text();
            this.appContainer.innerHTML = appContent;
            
            this.appContainer.dataset.currentApp = appPath;
            
            this.modal.style.display = 'block';
            
            try {
                await this.loadAppScript(appPath);
                console.log(`Loaded ${appPath} script successfully`);
                
                if (typeof window.initializeApp === "function") {
                    console.log("Calling initializeApp function");
                    try {
                        window.initializeApp();
                    } catch (error) {
                        console.error('Error in initializeApp:', error);
                    }
                } else {
                    console.log("No initializeApp function found");
                }
            } catch (error) {
                console.log(`Error loading script for ${appPath}:`, error);
            }
        } catch (error) {
            console.error('Error loading app:', error);
            this.appContainer.innerHTML = '<p>Error loading application</p>';
        }
    }

    closeModal() {
        console.log(`Closing modal for app: ${this.currentApp}`);

        this.cleanupPreviousApp();
        
        this.modal.style.display = 'none';
        this.appContainer.innerHTML = '';
        this.appContainer.dataset.currentApp = '';
        this.currentApp = null;
    }
    
    cleanupPreviousApp() {
        console.log("Cleaning up previous app...");

        if (typeof window.cleanupApp === "function") {
            try {
                console.log("Executing cleanupApp...");
                window.cleanupApp();
            } catch (error) {
                console.error('Error in cleanupApp:', error);
            }
        }
        
        window.initializeApp = undefined;
        window.cleanupApp = undefined;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing AppModal');
    window.appModal = new AppModal();
});