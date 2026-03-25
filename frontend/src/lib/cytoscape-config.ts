import type { Device } from '../types';
import { riskColor } from './risk-colors';

const DEVICE_SHAPES: Record<string, string> = {
  router: 'diamond',
  server: 'rectangle',
  workstation: 'ellipse',
  mobile: 'triangle',
  iot: 'hexagon',
  printer: 'barrel',
  unknown: 'ellipse',
};

export function buildElements(devices: Device[]) {
  const nodes = devices.map((d) => ({
    data: {
      id: String(d.id),
      label: d.hostname || d.ip_address,
      ip: d.ip_address,
      vendor: d.vendor,
      deviceType: d.device_type,
      riskScore: d.risk_score,
      riskColor: riskColor(d.risk_score),
      shape: DEVICE_SHAPES[d.device_type] || 'ellipse',
    },
  }));

  // Find gateway (first router, or use first device)
  const gateway = devices.find((d) => d.device_type === 'router') || devices[0];
  if (gateway && devices.length > 1) {
    nodes.unshift({
      data: {
        id: 'gateway',
        label: gateway.hostname || gateway.ip_address,
        ip: gateway.ip_address,
        vendor: gateway.vendor,
        deviceType: 'router',
        riskScore: gateway.risk_score,
        riskColor: riskColor(gateway.risk_score),
        shape: 'diamond',
      },
    });
  }

  const edges = devices
    .filter((d) => !gateway || d.id !== gateway.id)
    .map((d) => ({
      data: {
        id: `e-${d.id}`,
        source: 'gateway',
        target: String(d.id),
      },
    }));

  return { nodes, edges };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const stylesheet: any[] = [
  {
    selector: 'node',
    style: {
      label: 'data(label)',
      'background-color': 'data(riskColor)',
      shape: 'data(shape)',
      width: 40,
      height: 40,
      'font-size': '11px',
      'text-valign': 'bottom',
      'text-margin-y': 6,
      color: '#cbd5e1',
      'text-outline-color': '#0f172a',
      'text-outline-width': 2,
      'border-width': 2,
      'border-color': '#475569',
    },
  },
  {
    selector: 'node#gateway',
    style: {
      width: 56,
      height: 56,
      'font-size': '13px',
      'font-weight': 700,
      'border-width': 3,
    },
  },
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': '#334155',
      'curve-style': 'bezier',
      'target-arrow-shape': 'none',
    },
  },
  {
    selector: 'node:selected',
    style: {
      'border-color': '#3b82f6',
      'border-width': 3,
    },
  },
];

export const layoutOptions = {
  name: 'cose',
  animate: false,
  nodeDimensionsIncludeLabels: true,
  idealEdgeLength: () => 120,
  nodeRepulsion: () => 8000,
  gravity: 0.3,
};
