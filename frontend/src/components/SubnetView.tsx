import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Device } from '../types';
import { stylesheet } from '../lib/cytoscape-config';
import { riskColor } from '../lib/risk-colors';

interface SubnetViewProps {
  devices: Device[];
  onDeviceSelect: (deviceId: number) => void;
}

function getSubnet(ip: string): string {
  const parts = ip.split('.');
  return parts.length >= 3 ? `${parts[0]}.${parts[1]}.${parts[2]}.x` : ip;
}

export function SubnetView({ devices, onDeviceSelect }: SubnetViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current || devices.length === 0) return;

    const subnets = new Map<string, Device[]>();
    for (const d of devices) {
      const subnet = getSubnet(d.ip_address);
      if (!subnets.has(subnet)) subnets.set(subnet, []);
      subnets.get(subnet)!.push(d);
    }

    const elements: cytoscape.ElementDefinition[] = [];

    // Parent nodes for each subnet
    for (const subnet of subnets.keys()) {
      elements.push({ data: { id: `subnet-${subnet}`, label: subnet } });
    }

    // Device nodes parented to their subnet
    for (const [subnet, devs] of subnets) {
      for (const d of devs) {
        elements.push({
          data: {
            id: String(d.id),
            label: d.hostname || d.ip_address,
            parent: `subnet-${subnet}`,
            riskColor: riskColor(d.risk_score),
            shape: 'ellipse',
          },
        });
      }
    }

    if (cyRef.current) cyRef.current.destroy();

    const extendedStyle = [
      ...stylesheet,
      {
        selector: ':parent',
        style: {
          'background-opacity': 0.08,
          'background-color': '#3b82f6',
          'border-color': '#334155',
          'border-width': 1,
          label: 'data(label)',
          'text-valign': 'top' as const,
          'text-halign': 'center' as const,
          'font-size': '12px',
          color: '#64748b',
          'padding': '24px',
        },
      },
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: extendedStyle,
      layout: { name: 'cose', animate: false, padding: 40 } as cytoscape.LayoutOptions,
    });

    cy.on('tap', 'node', (e) => {
      const id = e.target.id();
      if (!id.startsWith('subnet-')) onDeviceSelect(Number(id));
    });

    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, [devices, onDeviceSelect]);

  if (devices.length === 0) {
    return <div className="flex items-center justify-center h-full text-text-secondary">No devices</div>;
  }

  return <div ref={containerRef} className="w-full h-full min-h-[500px]" />;
}
