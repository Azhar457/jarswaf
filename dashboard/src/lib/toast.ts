import { writable } from 'svelte/store';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

export interface Toast {
  id: number;
  message: string;
  type: ToastType;
}

const toasts = writable<Toast[]>([]);

let nextId = 0;

export const toast = {
  subscribe: toasts.subscribe,
  send: (message: string, type: ToastType = 'info', duration: number = 3000) => {
    const id = nextId++;
    toasts.update(all => [{ id, message, type }, ...all]);
    if (duration) {
      setTimeout(() => {
        toast.remove(id);
      }, duration);
    }
  },
  success: (msg: string) => toast.send(msg, 'success'),
  error: (msg: string) => toast.send(msg, 'error'),
  info: (msg: string) => toast.send(msg, 'info'),
  warning: (msg: string) => toast.send(msg, 'warning'),
  remove: (id: number) => {
    toasts.update(all => all.filter(t => t.id !== id));
  }
};
