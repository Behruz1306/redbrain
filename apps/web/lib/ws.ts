export interface ScanEvent {
  type: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export type EventHandler = (event: ScanEvent) => void;

const API_HOST = process.env.NEXT_PUBLIC_API_HOST || "localhost:8000";

export function connectScanStream(
  scanId: string,
  onEvent: EventHandler,
  onClose?: () => void
): WebSocket {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${API_HOST}/api/scan/${scanId}/stream`;
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (msg) => {
    try {
      const event: ScanEvent = JSON.parse(msg.data);
      onEvent(event);
    } catch {}
  };

  ws.onclose = () => onClose?.();
  ws.onerror = () => onClose?.();

  return ws;
}
