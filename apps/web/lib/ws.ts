export interface ScanEvent {
  type: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export type EventHandler = (event: ScanEvent) => void;

export function connectScanStream(
  scanId: string,
  onEvent: EventHandler,
  onClose?: () => void
): WebSocket {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/api/scan/${scanId}/stream`;
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
