import React from 'react';
import type { Alert } from '../../types/investigation';
import { X, Copy, Check } from 'lucide-react';

interface AlertJsonModalProps {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertJsonModal: React.FC<AlertJsonModalProps> = ({ alert, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  if (!alert) return null;

  // Format exactly matching Sentinel standardized schema
  const jsonString = JSON.stringify(alert, null, 2);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
      <div className="bg-white border border-slate-200 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl font-mono">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-200">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <span>Section 21 Alert JSON Schema</span>
              <span className="text-[11px] text-blue-600 font-normal">({alert.alert_id})</span>
            </h3>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Standardized forensic record for threat intelligence and downstream SIEM ingest.
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1 rounded-md transition cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* JSON Code Viewer */}
        <div className="p-4 flex-1 overflow-auto bg-slate-50">
          <pre className="text-xs text-emerald-700 font-mono leading-relaxed select-all">
            {jsonString}
          </pre>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-slate-200 bg-slate-50">
          <span className="text-[11px] text-slate-500">
            Host: {alert.host} | Severity: {alert.severity}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={copyToClipboard}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 transition cursor-pointer"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 text-xs rounded bg-blue-600 hover:bg-blue-700 text-white font-medium transition cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
