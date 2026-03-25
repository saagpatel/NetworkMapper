import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Device } from '../types';
import { buildElements, stylesheet, layoutOptions } from '../lib/cytoscape-config';

interface TopologyGraphProps {
  devices: Device[];
  onDeviceSelect: (deviceId: number) => void;
}

export function TopologyGraph({ devices, onDeviceSelect }: TopologyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current || devices.length === 0) return;

    const { nodes, edges } = buildElements(devices);

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: stylesheet,
      layout: layoutOptions,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    cy.on('tap', 'node', (e) => {
      const id = e.target.id();
      if (id !== 'gateway') {
        onDeviceSelect(Number(id));
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [devices, onDeviceSelect]);

  if (devices.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-text-secondary gap-4">
        <div className="text-6xl opacity-30">⬡</div>
        <p className="text-lg font-light">No devices discovered yet</p>
        <p className="text-sm">Start a scan to map your network</p>
      </div>
    );
  }

  return <div ref={containerRef} className="w-full h-full min-h-[500px]" />;
}
