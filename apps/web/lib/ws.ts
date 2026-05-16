export interface ScanEvent {
  type: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export type EventHandler = (event: ScanEvent) => void;

function getWsUrl(scanId: string): string {
  const apiHost = process.env.NEXT_PUBLIC_API_HOST;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";

  if (apiHost) {
    return `${protocol}//${apiHost}/api/scan/${scanId}/stream`;
  }

  // In containerized/nginx setup, WS goes through same origin
  if (typeof window !== "undefined" && window.location.hostname !== "localhost") {
    return `${protocol}//${window.location.host}/api/scan/${scanId}/stream`;
  }

  return `ws://localhost:8000/api/scan/${scanId}/stream`;
}

export function connectScanStream(
  scanId: string,
  onEvent: EventHandler,
  onClose?: () => void
): WebSocket {
  const wsUrl = getWsUrl(scanId);
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
