import { useState, useCallback, type ReactNode } from 'react';
import { X, AlertCircle, CheckCircle, Info } from 'lucide-react';
import { ToastContext, type ToastItem, type ToastType } from './toast-context';

let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const toast = useCallback((type: ToastType, message: string) => {
    const id = nextId++;
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}

      {/* Toast container */}
      <div className="fixed bottom-5 right-5 z-[100] space-y-2 max-w-sm">
        {toasts.map((t) => (
          <ToastCard key={t.id} item={t} onDismiss={() => dismiss(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

function ToastCard({ item, onDismiss }: { item: ToastItem; onDismiss: () => void }) {
  const icons = { error: AlertCircle, success: CheckCircle, info: Info };
  const colors = {
    error: 'border-risk-high/40 bg-risk-high/10 text-risk-high',
    success: 'border-risk-low/40 bg-risk-low/10 text-risk-low',
    info: 'border-accent/40 bg-accent/10 text-accent',
  };
  const Icon = icons[item.type];

  return (
    <div className={`flex items-start gap-3 p-3 rounded-xl border backdrop-blur-sm ${colors[item.type]} animate-[slideIn_0.2s_ease-out]`}>
      <Icon size={16} className="mt-0.5 shrink-0" />
      <p className="text-sm flex-1">{item.message}</p>
      <button onClick={onDismiss} className="p-0.5 rounded hover:bg-white/10 shrink-0">
        <X size={14} />
      </button>
    </div>
  );
}
