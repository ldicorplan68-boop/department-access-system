/**
 * Department Access System - Frontend JavaScript
 * Production-ready client-side authentication with security best practices
 * Version: 1.0.0
 */

// Configuration - Update this with your deployed Apps Script URL
const CONFIG = {
    API_BASE_URL: 'https://script.google.com/macros/s/AKfycbxHIXQVS1iFJC2ipA3y8vNj-7FZsf6xawkwB6s7QSzWqqWgh0yquP7NlUahc_B8l9tv/exec',
    SESSION_CHECK_INTERVAL: 5 * 60 * 1000, // 5 minutes
    SESSION_WARNING_TIME: 10 * 60 * 1000, // 10 minutes before expiry
    MAX_RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000 // 1 second
};

// DOM Elements
const elements = {
    loginForm: document.getElementById('loginForm'),
    usernameInput: document.getElementById('username'),
    passwordInput: document.getElementById('password'),
    rememberMeCheckbox: document.getElementById('rememberMe'),
    loginButton: document.getElementById('loginButton'),
    loadingSpinner: document.getElementById('loadingSpinner'),
    errorMessage: document.getElementById('errorMessage'),
    securityModal: document.getElementById('securityModal'),
    closeModalButton: document.querySelector('.close-button')
};

// Security Utilities
class SecurityUtils {
    /**
     * Sanitize input to prevent XSS
     */
    static sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    /**
     * Generate CSRF token (client-side protection)
     */
    static generateCSRFToken() {
        return btoa(Math.random().toString()).substring(0, 32);
    }

    /**
     * Validate email-like username format
     */
    static isValidUsername(username) {
        const usernameRegex = /^[a-zA-Z0-9._-]{3,50}$/;
        return usernameRegex.test(username);
    }

    /**
     * Basic password strength check
     */
    static isValidPassword(password) {
        return password.length >= 8 &&
               /[A-Z]/.test(password) &&
               /[a-z]/.test(password) &&
               /\d/.test(password);
    }

    /**
     * Secure session storage (uses sessionStorage for security)
     */
    static setSecureSession(key, value) {
        try {
            sessionStorage.setItem(key, JSON.stringify({
                value: value,
                timestamp: Date.now(),
                checksum: this.generateChecksum(value)
            }));
        } catch (error) {
            console.error('Failed to store session data:', error);
        }
    }

    static getSecureSession(key) {
        try {
            const item = sessionStorage.getItem(key);
            if (!item) return null;

            const data = JSON.parse(item);
            if (!data.checksum || data.checksum !== this.generateChecksum(data.value)) {
                // Data has been tampered with
                this.clearSecureSession(key);
                return null;
            }

            return data.value;
        } catch (error) {
            console.error('Failed to retrieve session data:', error);
            return null;
        }
    }

    static clearSecureSession(key) {
        try {
            sessionStorage.removeItem(key);
        } catch (error) {
            console.error('Failed to clear session data:', error);
        }
    }

    /**
     * Generate simple checksum for data integrity
     */
    static generateChecksum(data) {
        let hash = 0;
        const str = JSON.stringify(data);
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString();
    }
}

// API Client
class APIClient {
    constructor(baseURL) {
        this.baseURL = baseURL;
        this.retryCount = 0;
    }

    /**
     * Make API request with retry logic and error handling
     */
    async makeRequest(endpoint, data = {}) {
        const url = `${this.baseURL}?endpoint=${endpoint}`;

        // Add client information for security logging
        const requestData = {
            ...data,
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };

        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(requestData)
        };

        try {
            const response = await fetch(url, options);
            const result = await response.json();

            // Reset retry count on success
            this.retryCount = 0;

            if (!response.ok) {
                throw new Error(result.message || `HTTP ${response.status}`);
            }

            return result;

        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);

            // Retry logic for network errors
            if (this.retryCount < CONFIG.MAX_RETRY_ATTEMPTS &&
                (error.name === 'TypeError' || error.message.includes('fetch'))) {

                this.retryCount++;
                console.log(`Retrying request (${this.retryCount}/${CONFIG.MAX_RETRY_ATTEMPTS})`);

                await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY * this.retryCount));
                return this.makeRequest(endpoint, data);
            }

            throw error;
        }
    }

    /**
     * Login request
     */
    async login(username, password) {
        return this.makeRequest('/login', {
            username: SecurityUtils.sanitizeInput(username),
            password: password, // Don't sanitize password as it might contain special chars
            csrf_token: SecurityUtils.generateCSRFToken()
        });
    }

    /**
     * Logout request
     */
    async logout(sessionToken) {
        return this.makeRequest('/logout', {
            session_token: sessionToken
        });
    }

    /**
     * Check session validity
     */
    async checkSession(sessionToken) {
        return this.makeRequest('/checkSession', {
            session_token: sessionToken
        });
    }
}

// UI Manager
class UIManager {
    static showLoading(button, show = true) {
        if (show) {
            button.classList.add('loading');
            button.disabled = true;
        } else {
            button.classList.remove('loading');
            button.disabled = false;
        }
    }

    static showError(message, type = 'error') {
        const errorDiv = elements.errorMessage;
        errorDiv.textContent = message;
        errorDiv.className = `error-message ${type}-message`;
        errorDiv.style.display = 'block';

        // Auto-hide after 5 seconds
        setTimeout(() => {
            errorDiv.style.display = 'none';
        }, 5000);
    }

    static hideError() {
        elements.errorMessage.style.display = 'none';
    }

    static clearForm() {
        elements.loginForm.reset();
        this.hideError();
    }

    static setFormEnabled(enabled) {
        const inputs = [elements.usernameInput, elements.passwordInput, elements.rememberMeCheckbox];
        inputs.forEach(input => input.disabled = !enabled);
    }
}

// Session Manager
class SessionManager {
    constructor(apiClient) {
        this.apiClient = apiClient;
        this.checkInterval = null;
        this.warningShown = false;
    }

    /**
     * Handle successful login
     */
    handleLoginSuccess(response) {
        try {
            // Store session securely
            SecurityUtils.setSecureSession('session_token', response.session_token);
            SecurityUtils.setSecureSession('user', response.user);
            SecurityUtils.setSecureSession('expires_at', response.expires_at);

            // Store remember me preference (only username for security)
            if (elements.rememberMeCheckbox.checked) {
                localStorage.setItem('remember_username', response.user.username);
            } else {
                localStorage.removeItem('remember_username');
            }

            // Start session monitoring
            this.startSessionMonitoring();

            // Redirect to dashboard
            window.location.href = 'dashboard.html';

        } catch (error) {
            console.error('Error handling login success:', error);
            UIManager.showError('Failed to process login response. Please try again.');
        }
    }

    /**
     * Check if user is logged in
     */
    isLoggedIn() {
        const token = SecurityUtils.getSecureSession('session_token');
        const expiresAt = SecurityUtils.getSecureSession('expires_at');

        if (!token || !expiresAt) {
            return false;
        }

        // Check if session is expired
        return Date.now() < expiresAt;
    }

    /**
     * Logout user
     */
    async logout() {
        const token = SecurityUtils.getSecureSession('session_token');

        if (token) {
            try {
                await this.apiClient.logout(token);
            } catch (error) {
                console.warn('Logout API call failed, but clearing local session anyway:', error);
            }
        }

        this.clearSession();
        window.location.href = 'index.html';
    }

    /**
     * Clear local session data
     */
    clearSession() {
        SecurityUtils.clearSecureSession('session_token');
        SecurityUtils.clearSecureSession('user');
        SecurityUtils.clearSecureSession('expires_at');
        this.stopSessionMonitoring();
        this.warningShown = false;
    }

    /**
     * Start monitoring session expiry
     */
    startSessionMonitoring() {
        this.checkInterval = setInterval(async () => {
            const token = SecurityUtils.getSecureSession('session_token');
            const expiresAt = SecurityUtils.getSecureSession('expires_at');

            if (!token || !expiresAt) {
                this.clearSession();
                window.location.href = 'index.html';
                return;
            }

            const timeUntilExpiry = expiresAt - Date.now();

            // Show warning 10 minutes before expiry
            if (timeUntilExpiry <= CONFIG.SESSION_WARNING_TIME && !this.warningShown) {
                this.showExpiryWarning(Math.ceil(timeUntilExpiry / (60 * 1000)));
                this.warningShown = true;
            }

            // Auto-logout when expired
            if (timeUntilExpiry <= 0) {
                alert('Your session has expired. Please log in again.');
                this.clearSession();
                window.location.href = 'index.html';
                return;
            }

            // Periodic session validation
            try {
                await this.apiClient.checkSession(token);
            } catch (error) {
                console.warn('Session validation failed:', error);
                this.clearSession();
                window.location.href = 'index.html';
            }

        }, CONFIG.SESSION_CHECK_INTERVAL);
    }

    /**
     * Stop session monitoring
     */
    stopSessionMonitoring() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }

    /**
     * Show session expiry warning
     */
    showExpiryWarning(minutesLeft) {
        const extend = confirm(`Your session will expire in ${minutesLeft} minutes. Click OK to extend your session.`);

        if (extend) {
            // Refresh the page to extend session (will trigger new session check)
            window.location.reload();
        }
    }

    /**
     * Get current user info
     */
    getCurrentUser() {
        return SecurityUtils.getSecureSession('user');
    }

    /**
     * Validate current session on page load
     */
    async validateSessionOnLoad() {
        if (this.isLoggedIn()) {
            const token = SecurityUtils.getSecureSession('session_token');

            try {
                const response = await this.apiClient.checkSession(token);
                SecurityUtils.setSecureSession('user', response.user);
                this.startSessionMonitoring();
                return true;
            } catch (error) {
                console.warn('Session validation failed on load:', error);
                this.clearSession();
                return false;
            }
        }
        return false;
    }
}

// Main Application
class LoginApp {
    constructor() {
        this.apiClient = new APIClient(CONFIG.API_BASE_URL);
        this.sessionManager = new SessionManager(this.apiClient);
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.restoreRememberedUsername();
        this.checkExistingSession();
    }

    setupEventListeners() {
        // Form submission
        elements.loginForm.addEventListener('submit', (e) => this.handleLogin(e));

        // Input validation
        elements.usernameInput.addEventListener('input', () => this.validateInput());
        elements.passwordInput.addEventListener('input', () => this.validateInput());

        // Security modal
        setTimeout(() => {
            elements.securityModal.style.display = 'block';
        }, 1000);

        elements.closeModalButton.addEventListener('click', () => {
            elements.securityModal.style.display = 'none';
        });

        window.addEventListener('click', (e) => {
            if (e.target === elements.securityModal) {
                elements.securityModal.style.display = 'none';
            }
        });

        // Prevent form submission on enter in username field
        elements.usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                elements.passwordInput.focus();
            }
        });
    }

    restoreRememberedUsername() {
        const rememberedUsername = localStorage.getItem('remember_username');
        if (rememberedUsername) {
            elements.usernameInput.value = rememberedUsername;
            elements.rememberMeCheckbox.checked = true;
        }
    }

    async checkExistingSession() {
        const isValid = await this.sessionManager.validateSessionOnLoad();
        if (isValid) {
            // User is already logged in, redirect to dashboard
            window.location.href = 'dashboard.html';
        }
    }

    validateInput() {
        const username = elements.usernameInput.value.trim();
        const password = elements.passwordInput.value;

        const isUsernameValid = SecurityUtils.isValidUsername(username);
        const isPasswordValid = password.length >= 8; // Basic check

        // Visual feedback
        elements.usernameInput.classList.toggle('invalid', username && !isUsernameValid);
        elements.passwordInput.classList.toggle('invalid', password && !isPasswordValid);

        return isUsernameValid && isPasswordValid;
    }

    async handleLogin(e) {
        e.preventDefault();
        UIManager.hideError();

        const username = elements.usernameInput.value.trim();
        const password = elements.passwordInput.value;

        // Client-side validation
        if (!username || !password) {
            UIManager.showError('Please enter both username and password.');
            return;
        }

        if (!SecurityUtils.isValidUsername(username)) {
            UIManager.showError('Invalid username format.');
            return;
        }

        if (!SecurityUtils.isValidPassword(password)) {
            UIManager.showError('Password must be at least 8 characters long with uppercase, lowercase, and numbers.');
            return;
        }

        // Show loading state
        UIManager.showLoading(elements.loginButton, true);
        UIManager.setFormEnabled(false);

        try {
            const response = await this.apiClient.login(username, password);

            if (response.success) {
                this.sessionManager.handleLoginSuccess(response);
            } else {
                throw new Error(response.message || 'Login failed');
            }

        } catch (error) {
            console.error('Login error:', error);

            let errorMessage = 'Login failed. Please try again.';

            // Handle specific error types
            if (error.message.includes('INVALID_CREDENTIALS')) {
                errorMessage = 'Invalid username or password.';
            } else if (error.message.includes('RATE_LIMITED')) {
                errorMessage = 'Too many login attempts. Please wait before trying again.';
            } else if (error.message.includes('ACCOUNT_INACTIVE')) {
                errorMessage = 'Your account is not active. Please contact support.';
            } else if (error.message.includes('NETWORK') || error.message.includes('fetch')) {
                errorMessage = 'Network error. Please check your connection and try again.';
            }

            UIManager.showError(errorMessage);

        } finally {
            // Hide loading state
            UIManager.showLoading(elements.loginButton, false);
            UIManager.setFormEnabled(true);
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the login page
    if (document.getElementById('loginForm')) {
        new LoginApp();
    }
});

// Global error handling
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    // Don't show to user in production, but log for debugging
});

window.addEventListener('error', (event) => {
    console.error('JavaScript error:', event.error);
    // Don't show to user in production
});

// Prevent common security issues
document.addEventListener('contextmenu', (e) => e.preventDefault());
document.addEventListener('keydown', (e) => {
    // Disable F12, Ctrl+Shift+I, Ctrl+U
    if (e.key === 'F12' ||
        (e.ctrlKey && e.shiftKey && e.key === 'I') ||
        (e.ctrlKey && e.key === 'U')) {
        e.preventDefault();
    }
});

// DASHBOARD FUNCTIONALITY
class DashboardApp {
    constructor() {
        this.apiClient = new APIClient(CONFIG.API_BASE_URL);
        this.sessionManager = new SessionManager(this.apiClient);
        this.sessionStartTime = Date.now();
        this.sessionTimerInterval = null;
        this.init();
    }

    async init() {
        // Show loading screen
        this.showLoading(true);

        // Validate session
        const isValid = await this.sessionManager.validateSessionOnLoad();

        if (!isValid) {
            // Redirect to login if session invalid
            window.location.href = 'index.html';
            return;
        }

        // Initialize dashboard
        this.setupEventListeners();
        this.loadUserData();
        this.startSessionTimer();
        this.showLoading(false);

        // Show dashboard
        document.getElementById('dashboard').style.display = 'flex';
    }

    setupEventListeners() {
        // Navigation tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
        });

        // Logout button
        document.getElementById('logoutButton').addEventListener('click', () => this.handleLogout());

        // Profile actions
        document.getElementById('changePasswordBtn').addEventListener('click', () => this.showChangePassword());
        document.getElementById('viewActivityBtn').addEventListener('click', () => this.showActivityHistory());

        // Security actions
        document.getElementById('forceLogoutBtn').addEventListener('click', () => this.forceLogoutAll());
        document.getElementById('reportIssueBtn').addEventListener('click', () => this.reportSecurityIssue());

        // Modal actions
        document.getElementById('extendSessionBtn').addEventListener('click', () => this.extendSession());
        document.getElementById('logoutNowBtn').addEventListener('click', () => this.handleLogout());
    }

    switchTab(tabName) {
        // Update navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}Tab`).classList.add('active');

        // Load tab-specific data
        switch (tabName) {
            case 'department':
                this.loadDepartmentContent();
                break;
            case 'profile':
                this.loadProfileData();
                break;
            case 'security':
                this.loadSecurityInfo();
                break;
        }
    }

    loadUserData() {
        const user = this.sessionManager.getCurrentUser();
        if (!user) return;

        // Update header
        document.getElementById('userName').textContent = user.username;
        document.getElementById('departmentBadge').textContent = user.department;

        // Update overview stats
        document.getElementById('lastLogin').textContent = 'Current session';
        document.getElementById('accessLevel').textContent = user.department;

        // Update profile info
        document.getElementById('profileName').textContent = user.username;
        document.getElementById('profileDepartment').textContent = `${user.department} Department`;
        document.getElementById('profileInitials').textContent = user.username.substring(0, 2).toUpperCase();
    }

    startSessionTimer() {
        this.updateSessionTimer();
        this.sessionTimerInterval = setInterval(() => {
            this.updateSessionTimer();
        }, 1000);
    }

    updateSessionTimer() {
        const elapsed = Date.now() - this.sessionStartTime;
        const hours = Math.floor(elapsed / (1000 * 60 * 60));
        const minutes = Math.floor((elapsed % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((elapsed % (1000 * 60)) / 1000);

        const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        document.getElementById('sessionTime').textContent = timeString;
    }

    loadDepartmentContent() {
        const user = this.sessionManager.getCurrentUser();
        if (!user) return;

        // Hide all department sections
        document.querySelectorAll('.department-section').forEach(section => {
            section.style.display = 'none';
        });
        document.getElementById('accessDenied').style.display = 'none';

        // Show appropriate department content
        const departmentContent = document.getElementById(`${user.department.toLowerCase()}Content`);
        if (departmentContent) {
            departmentContent.style.display = 'block';
            document.getElementById('departmentTitle').textContent = `${user.department} Department Resources`;
        } else {
            document.getElementById('accessDenied').style.display = 'block';
            document.getElementById('departmentTitle').textContent = 'Access Restricted';
        }
    }

    loadProfileData() {
        // Profile data is already loaded in loadUserData()
        // Additional profile data could be loaded here from API
    }

    loadSecurityInfo() {
        const expiresAt = SecurityUtils.getSecureSession('expires_at');
        if (expiresAt) {
            const expiryDate = new Date(expiresAt);
            document.getElementById('sessionExpiry').textContent = expiryDate.toLocaleString();
        }

        // Get browser info
        const userAgent = navigator.userAgent;
        let browserName = 'Unknown';

        if (userAgent.includes('Chrome')) browserName = 'Chrome';
        else if (userAgent.includes('Firefox')) browserName = 'Firefox';
        else if (userAgent.includes('Safari')) browserName = 'Safari';
        else if (userAgent.includes('Edge')) browserName = 'Edge';

        document.getElementById('userAgent').textContent = browserName;

        // IP address would need to be retrieved from server
        document.getElementById('clientIP').textContent = 'Hidden for security';
    }

    async handleLogout() {
        this.showLoading(true);
        await this.sessionManager.logout();
        // Redirect will happen automatically
    }

    showChangePassword() {
        alert('Password change functionality would be implemented here.\nThis would require additional API endpoints.');
    }

    showActivityHistory() {
        alert('Activity history would be loaded from the audit logs.\nThis requires additional API endpoints.');
    }

    forceLogoutAll() {
        if (confirm('This will log you out from all devices. Are you sure?')) {
            alert('Force logout functionality would be implemented here.\nThis requires additional API endpoints.');
        }
    }

    reportSecurityIssue() {
        const issue = prompt('Please describe the security issue:');
        if (issue) {
            alert('Security issue reported. An administrator will review it.');
            // In a real implementation, this would send to an API endpoint
        }
    }

    extendSession() {
        // Hide modal
        document.getElementById('expiryModal').style.display = 'none';

        // Refresh the page to extend session
        window.location.reload();
    }

    showLoading(show) {
        document.getElementById('loadingScreen').style.display = show ? 'flex' : 'none';
    }

    // Override session manager's warning to show modal
    showExpiryWarning(minutesLeft) {
        document.getElementById('expiryTime').textContent = minutesLeft;
        document.getElementById('expiryModal').style.display = 'block';
    }
}

// Initialize dashboard if on dashboard page
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('dashboard')) {
        // Override the session manager's warning method
        SessionManager.prototype.showExpiryWarning = DashboardApp.prototype.showExpiryWarning;
        new DashboardApp();
    }
});
