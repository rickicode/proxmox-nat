import { navigate } from '$lib/router.svelte.js';

const API_BASE = '/api';

class ApiClient {
    constructor() {
        this.csrfToken = null;
        this.fetchingToken = null; // Promise to prevent concurrent token fetches
    }

    async fetchCSRFToken() {
        // If already fetching, wait for that request
        if (this.fetchingToken) {
            return this.fetchingToken;
        }

        this.fetchingToken = (async () => {
            try {
                const response = await fetch(`${API_BASE}/csrf-token`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                    }
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch CSRF token');
                }

                const data = await response.json();
                if (data.success && data.data && data.data.token) {
                    this.csrfToken = data.data.token;
                    return this.csrfToken;
                }
                throw new Error('Invalid CSRF token response');
            } catch (error) {
                console.error('CSRF token fetch error:', error);
                this.csrfToken = null;
                throw error;
            } finally {
                this.fetchingToken = null;
            }
        })();

        return this.fetchingToken;
    }

    async request(endpoint, options = {}, retryCount = 0) {
        if (typeof window === 'undefined') return null;

        const url = `${API_BASE}${endpoint}`;
        const method = options.method || 'GET';

        // Get token from localStorage
        const token = localStorage.getItem('token');

        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        // Add Authorization header if token exists
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        // Add CSRF token for mutating requests
        const isMutatingRequest = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase());
        if (isMutatingRequest) {
            // Fetch CSRF token if we don't have one
            if (!this.csrfToken) {
                try {
                    await this.fetchCSRFToken();
                } catch (error) {
                    console.error('Failed to fetch CSRF token:', error);
                }
            }

            // Add CSRF token to headers if available
            if (this.csrfToken) {
                headers['X-CSRF-Token'] = this.csrfToken;
            }
        }

        try {
            const response = await fetch(url, { ...options, headers });

            // Handle 401 Unauthorized - redirect to login
            if (response.status === 401) {
                localStorage.removeItem('token');
                localStorage.removeItem('username');
                navigate('/login');
                throw new Error('Unauthorized');
            }

            const data = await response.json();

            // Handle CSRF token errors with retry
            if (!response.ok && response.status === 403 && data.error &&
                (data.error.includes('CSRF') || data.error.includes('csrf'))) {

                // Only retry once
                if (retryCount === 0) {
                    console.log('CSRF token error, fetching new token and retrying...');
                    this.csrfToken = null; // Clear invalid token
                    await this.fetchCSRFToken(); // Fetch new token
                    return this.request(endpoint, options, retryCount + 1); // Retry request
                }
            }

            if (!response.ok) {
                throw new Error(data.error || 'API Request Failed');
            }

            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    }

    get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    post(endpoint, body) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    put(endpoint, body) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}

export const api = new ApiClient();
