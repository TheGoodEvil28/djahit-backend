// Authentication Manager for JWT-based auth
class AuthManager {
    constructor() {
        this.baseURL = '/api'; // Your REST API base URL
        this.tokenKey = 'djahit_auth_token';
    }

    // Store JWT token in sessionStorage
    setToken(token) {
        sessionStorage.setItem(this.tokenKey, token);
    }

    // Get JWT token from sessionStorage
    getToken() {
        return sessionStorage.getItem(this.tokenKey);
    }

    // Remove JWT token from sessionStorage
    removeToken() {
        sessionStorage.removeItem(this.tokenKey);
    }

    // Check if user is authenticated
    isAuthenticated() {
        const token = this.getToken();
        if (!token) return false;
        
        try {
            // Decode JWT payload to check expiration
            const payload = JSON.parse(atob(token.split('.')[1]));
            const now = Date.now() / 1000;
            
            // Check if token is expired
            if (payload.exp && payload.exp < now) {
                this.removeToken();
                return false;
            }
            
            return true;
        } catch (error) {
            console.error('Token validation error:', error);
            this.removeToken();
            return false;
        }
    }

    // Get authorization headers for API requests
    getAuthHeaders() {
        const token = this.getToken();
        return token ? {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        } : {
            'Content-Type': 'application/json'
        };
    }

    // Make authenticated API request
    async apiRequest(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            ...options,
            headers: {
                ...this.getAuthHeaders(),
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            // Handle unauthorized responses
            if (response.status === 401 || response.status === 403) {
                this.removeToken();
                window.location.href = '/views/login.html?error=session_expired';
                return null;
            }

            return { response, data };
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }

    // Login method
    async login(email, password) {
        try {
            const response = await fetch(`${this.baseURL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                this.setToken(data.data.token);
                return { success: true, user: data.data.user };
            } else {
                return { 
                    success: false, 
                    message: data.error?.message || 'Login failed' 
                };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { 
                success: false, 
                message: 'Network error occurred' 
            };
        }
    }

    // Register method - UPDATED to NOT auto-login
    async register(userData) {
        try {
            const response = await fetch(`${this.baseURL}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                // DON'T SET TOKEN - Just return success
                // this.setToken(data.data.token); // REMOVED THIS LINE
                return { 
                    success: true, 
                    user: data.data.user,
                    message: data.message || 'Registration successful! Please login to continue.' 
                };
            } else {
                return { 
                    success: false, 
                    message: data.error?.message || 'Registration failed' 
                };
            }
        } catch (error) {
            console.error('Registration error:', error);
            return { 
                success: false, 
                message: 'Network error occurred' 
            };
        }
    }

    // Logout method
    async logout() {
        try {
            // Call logout endpoint (optional since JWT is stateless)
            await this.apiRequest('/auth/logout', { method: 'POST' });
        } catch (error) {
            console.error('Logout API error:', error);
        } finally {
            // Always remove token and redirect
            this.removeToken();
            window.location.href = '/views/login.html?success=logout_successful';
        }
    }

    // Get current user profile
    async getCurrentUser() {
        if (!this.isAuthenticated()) {
            return null;
        }

        try {
            const result = await this.apiRequest('/users/me');
            if (result && result.data.success) {
                return result.data.data.user;
            }
            return null;
        } catch (error) {
            console.error('Get current user error:', error);
            return null;
        }
    }
}

// Create global auth manager instance
const authManager = new AuthManager();

// Route protection function
function requireAuth() {
    if (!authManager.isAuthenticated()) {
        window.location.href = '/views/login.html?error=authentication_required';
        return false;
    }
    return true;
}

// Redirect authenticated users away from login/register pages
function redirectIfAuthenticated() {
    if (authManager.isAuthenticated()) {
        window.location.href = '/views/indexLoggedin.html';
        return true;
    }
    return false;
}

// Toast notification system
function showToast(message, type = 'success') {
    // Create or get toast container
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; max-width: 400px;';
        document.body.appendChild(container);
    }

    // Create toast
    const toast = document.createElement('div');
    const bgColor = type === 'success' ? '#10B981' : '#EF4444';
    
    toast.innerHTML = `
        <div style="background-color: ${bgColor}; color: white; padding: 12px 16px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); margin-bottom: 8px; display: flex; align-items: center; justify-content: space-between; font-family: 'Plus Jakarta Sans', sans-serif; font-size: 14px; transform: translateX(100%); transition: transform 0.3s ease;">
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: white; font-size: 18px; margin-left: 12px; cursor: pointer; padding: 0;">×</button>
        </div>
    `;

    container.appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.firstElementChild.style.transform = 'translateX(0)';
    }, 100);

    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.firstElementChild.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 3000);
        }
    }, 5000);
}