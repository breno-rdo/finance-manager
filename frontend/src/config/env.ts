const raw = import.meta.env.VITE_API_URL;

if (!raw) {
    throw new Error('VITE_API_URL is not defined in the environment variables.');
}

export const API_URL = raw.replace(/\/+$/, '');