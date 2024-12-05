// File: frontend/src/hooks/useStorage.ts

import { useEffect, useState } from 'react';
import { init } from '@/pkg/overpass_wasm';

// TODO: Fix type

export function useStorage(): { storage: any; error: Error | null } {
    const [storage, setStorage] = useState<any | null>(null);                   
    const [error, setError] = useState<Error | null>(null);

    useEffect(() => {
        async function initStorage() {
            try {
                init();
                const storage = new Storage();
                setStorage(storage);
            } catch (err) {
                setError(err instanceof Error ? err : new Error(String(err)));
            }
        }
        initStorage();
    }, []);

    return { storage, error };
}