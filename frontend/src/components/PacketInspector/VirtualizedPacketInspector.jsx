import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { NVQL } from '../../utils/nvql.js';

const ROW_HEIGHT = 32;
const OVERSCAN = 15;

export function VirtualizedPacketInspector({ packets = [], onPacketSelect, height = 700 }) {
  const [filterQuery, setFilterQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [highlightedByteRange, setHighlightedByteRange] = useState(null); // [start, end]
  const [expandedNodes, setExpandedNodes] = useState({
    frame: true,
    eth: true,
    ip: true,
    transport: true,
    app: true,
  });

  const containerRef = useRef(null);

  // Compile NVQL filter
  const filterFn = useMemo(() => {
    return NVQL.compile(activeFilter);
  }, [activeFilter]);

  const filterValidation = useMemo(() => {
    return NVQL.validate(filterQuery);
  }, [filterQuery]);

  // Filtered packets
  const filteredPackets = useMemo(() => {
    if (!activeFilter.trim()) return packets;
    return packets.filter(filterFn);
  }, [packets, activeFilter, filterFn]);

  // Selected packet
  const selectedPacket = useMemo(() => {
    if (filteredPackets.length === 0) return null;
    const idx = Math.min(Math.max(0, selectedIndex), filteredPackets.length - 1);
    return filteredPackets[idx];
  }, [filteredPackets, selectedIndex]);

  // Notify parent if selection changes
  useEffect(() => {
    if (selectedPacket && onPacketSelect) {
      onPacketSelect(selectedPacket);
    }
  }, [selectedPacket, onPacketSelect]);

  // Virtualization window calculation
  const totalCount = filteredPackets.length;
  const tableHeight = Math.max(200, Math.floor(height * 0.45));
  const visibleCount = Math.ceil(tableHeight / ROW_HEIGHT);

  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(totalCount, Math.floor((scrollTop + tableHeight) / ROW_HEIGHT) + OVERSCAN);

  const visiblePackets = useMemo(() => {
    return filteredPackets.slice(startIndex, endIndex).map((pkt, idx) => ({
      packet: pkt,
      index: startIndex + idx,
      top: (startIndex + idx) * ROW_HEIGHT,
    }));
  }, [filteredPackets, startIndex, endIndex]);

  const handleScroll = (e) => {
    setScrollTop(e.currentTarget.scrollTop);
  };

  // Keyboard navigation
  const handleKeyDown = useCallback((e) => {
    if (['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End'].includes(e.key)) {
      e.preventDefault();
      setSelectedIndex((prev) => {
        let next = prev;
        if (e.key === 'ArrowDown') next = Math.min(totalCount - 1, prev + 1);
        else if (e.key === 'ArrowUp') next = Math.max(0, prev - 1);
        else if (e.key === 'PageDown') next = Math.min(totalCount - 1, prev + visibleCount);
        else if (e.key === 'PageUp') next = Math.max(0, prev - visibleCount);
        else if (e.key === 'Home') next = 0;
        else if (e.key === 'End') next = totalCount - 1;

        // Scroll into view
        const targetTop = next * ROW_HEIGHT;
        if (containerRef.current) {
          if (targetTop < containerRef.current.scrollTop) {
            containerRef.current.scrollTop = targetTop;
          } else if (targetTop + ROW_HEIGHT > containerRef.current.scrollTop + tableHeight) {
            containerRef.current.scrollTop = targetTop - tableHeight + ROW_HEIGHT;
          }
        }
        return next;
      });
    }
  }, [totalCount, tableHeight, visibleCount]);

  const handleApplyFilter = (e) => {
    e.preventDefault();
    if (filterValidation.valid) {
      setActiveFilter(filterQuery);
      setSelectedIndex(0);
      if (containerRef.current) containerRef.current.scrollTop = 0;
    }
  };

  const handleQuickFilter = (q) => {
    setFilterQuery(q);
    setActiveFilter(q);
    setSelectedIndex(0);
    if (containerRef.current) containerRef.current.scrollTop = 0;
  };

  const toggleNode = (node) => {
    setExpandedNodes((prev) => ({ ...prev, [node]: !prev[node] }));
  };

  // Synthetic or real hex buffer for Pane 3
  const hexDumpRows = useMemo(() => {
    if (!selectedPacket) return [];
    const len = Math.min(256, selectedPacket.bytes || selectedPacket.length || 64);
    const bytes = [];
    // Generate deterministic bytes from packet fields if raw payload not present
    for (let i = 0; i < len; i++) {
      if (selectedPacket.raw_bytes && selectedPacket.raw_bytes[i] !== undefined) {
        bytes.push(selectedPacket.raw_bytes[i]);
      } else {
        const seed = (selectedPacket.src_port || 1) + (selectedPacket.dst_port || 1) + i * 17;
        bytes.push((seed ^ (i * 31)) % 256);
      }
    }

    const rows = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const hexGroup1 = slice.slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join(' ');
      const hexGroup2 = slice.slice(8, 16).map((b) => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = slice.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');

      rows.push({
        offset: i.toString(16).padStart(4, '0'),
        hexGroup1,
        hexGroup2,
        ascii,
        startByte: i,
        endByte: i + slice.length,
      });
    }
    return rows;
  }, [selectedPacket]);

  // Protocol styling helper
  const getProtoBadge = (proto) => {
    const p = String(proto || 'TCP').toUpperCase();
    if (p === 'TCP') return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    if (p === 'UDP') return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    if (p === 'DNS') return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    if (p === 'TLS') return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
    return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
  };

  return (
    <div
      className="flex flex-col bg-slate-950 text-slate-200 border border-slate-800 rounded-lg overflow-hidden font-mono text-xs select-none shadow-2xl"
      style={{ height: `${height}px` }}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      role="region"
      aria-label="Packet Inspector"
    >
      {/* Top Filter Bar */}
      <div className="flex items-center gap-2 px-3 py-2 bg-slate-900 border-b border-slate-800">
        <form onSubmit={handleApplyFilter} className="flex-1 flex items-center gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder='Apply NVQL filter (e.g. ip.src == 192.168.1.1 && tcp.port == 443, dns.qry.name contains "evil")'
              className={`w-full bg-slate-950 border px-3 py-1.5 rounded text-xs outline-none transition-all ${
                !filterValidation.valid
                  ? 'border-rose-500 text-rose-200 focus:ring-1 focus:ring-rose-500'
                  : 'border-slate-700 text-slate-100 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
              }`}
            />
            {filterQuery && (
              <span className="absolute right-2.5 top-2 text-[10px]">
                {filterValidation.valid ? (
                  <span className="text-emerald-400">✓ Valid</span>
                ) : (
                  <span className="text-rose-400" title={filterValidation.error}>✗ Error</span>
                )}
              </span>
            )}
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded transition-colors text-xs"
          >
            Apply
          </button>
          {activeFilter && (
            <button
              type="button"
              onClick={() => handleQuickFilter('')}
              className="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition-colors text-xs"
            >
              Clear
            </button>
          )}
        </form>

        {/* Quick Filter Buttons */}
        <div className="flex items-center gap-1 border-l border-slate-800 pl-2">
          {['TCP', 'UDP', 'DNS', 'TLS', 'threat.detected'].map((q) => (
            <button
              key={q}
              onClick={() => handleQuickFilter(q.includes('.') ? q : `frame.protocols == "${q.toLowerCase()}"`)}
              className="px-2 py-1 bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 rounded text-[11px] border border-slate-700/50 transition-colors"
            >
              {q.replace('threat.detected', 'Threats')}
            </button>
          ))}
        </div>

        <div className="text-[11px] text-slate-400 pl-2 border-l border-slate-800">
          {filteredPackets.length.toLocaleString()} / {packets.length.toLocaleString()} pkts
        </div>
      </div>

      {/* Pane 1: Virtualized Summary Table */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="overflow-y-auto overflow-x-hidden relative border-b border-slate-800 bg-slate-950"
        style={{ height: `${tableHeight}px` }}
      >
        {/* Table Header */}
        <div className="sticky top-0 z-10 grid grid-cols-12 bg-slate-900 border-b border-slate-800 text-slate-400 font-semibold px-2 py-1.5 text-[11px]">
          <div className="col-span-1">No.</div>
          <div className="col-span-2">Time</div>
          <div className="col-span-2">Source</div>
          <div className="col-span-2">Destination</div>
          <div className="col-span-1">Protocol</div>
          <div className="col-span-1">Length</div>
          <div className="col-span-2">Info</div>
          <div className="col-span-1 text-right">Threat</div>
        </div>

        {/* Virtualized Container */}
        <div style={{ height: `${totalCount * ROW_HEIGHT}px`, position: 'relative' }}>
          {visiblePackets.map(({ packet, index, top }) => {
            const isSelected = index === selectedIndex;
            const hasThreat = Boolean(packet.threat_indicator || packet.risk_score > 50);

            return (
              <div
                key={packet.flow_id || packet.id || index}
                onClick={() => setSelectedIndex(index)}
                style={{
                  position: 'absolute',
                  top: `${top}px`,
                  height: `${ROW_HEIGHT}px`,
                  left: 0,
                  right: 0,
                }}
                className={`grid grid-cols-12 items-center px-2 cursor-pointer transition-colors border-b border-slate-900/60 ${
                  isSelected
                    ? 'bg-cyan-950/60 text-cyan-200 border-l-2 border-l-cyan-400'
                    : hasThreat
                    ? 'bg-rose-950/20 text-slate-300 hover:bg-slate-900/80'
                    : index % 2 === 0
                    ? 'bg-slate-950 text-slate-300 hover:bg-slate-900/60'
                    : 'bg-slate-900/30 text-slate-300 hover:bg-slate-900/60'
                }`}
              >
                <div className="col-span-1 text-slate-400 font-mono text-[11px]">{index + 1}</div>
                <div className="col-span-2 truncate text-slate-400 text-[11px]">
                  {packet.timestamp_epoch_ms
                    ? new Date(packet.timestamp_epoch_ms).toISOString().slice(11, 23)
                    : '+0.000000'}
                </div>
                <div className="col-span-2 truncate font-mono text-[11px]">
                  {packet.src_ip || '0.0.0.0'}:{packet.src_port || 0}
                </div>
                <div className="col-span-2 truncate font-mono text-[11px]">
                  {packet.dst_ip || '0.0.0.0'}:{packet.dst_port || 0}
                </div>
                <div className="col-span-1">
                  <span className={`px-1.5 py-0.5 rounded border text-[10px] uppercase font-semibold ${getProtoBadge(packet.protocol)}`}>
                    {packet.protocol || 'TCP'}
                  </span>
                </div>
                <div className="col-span-1 text-slate-400 text-[11px]">
                  {packet.bytes || packet.length || 64} B
                </div>
                <div className="col-span-2 truncate text-[11px] text-slate-300" title={packet.dns_query || packet.tls_sni || packet.flags || ''}>
                  {packet.dns_query ? `DNS: ${packet.dns_query}` : packet.tls_sni ? `SNI: ${packet.tls_sni}` : packet.flags ? `[${packet.flags}]` : 'Application Data'}
                </div>
                <div className="col-span-1 text-right">
                  {hasThreat && (
                    <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[10px] font-semibold">
                      {packet.threat_indicator || 'THREAT'}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom Panes Container: Dissection Tree (Left) & Hex Dump (Right) */}
      <div className="flex-1 grid grid-cols-2 bg-slate-950 overflow-hidden divide-x divide-slate-800">
        {/* Pane 2: Protocol Dissection Tree */}
        <div className="p-3 overflow-y-auto font-mono text-[11px] space-y-1">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">
            Protocol Dissection
          </div>

          {selectedPacket ? (
            <>
              {/* Frame Tree Node */}
              <div className="rounded bg-slate-900/40 border border-slate-800/80 p-2">
                <div
                  onClick={() => toggleNode('frame')}
                  className="cursor-pointer font-semibold text-slate-300 flex items-center gap-1 hover:text-cyan-400"
                >
                  <span>{expandedNodes.frame ? '▼' : '▶'}</span>
                  <span>Frame {selectedIndex + 1}: {selectedPacket.bytes || 64} bytes on wire</span>
                </div>
                {expandedNodes.frame && (
                  <div className="pl-4 pt-1 space-y-0.5 text-slate-400 text-[11px]">
                    <div onClick={() => setHighlightedByteRange([0, 14])} className="cursor-pointer hover:text-cyan-300">
                      • Interface id: 0 (eth0)
                    </div>
                    <div>• Frame Length: {selectedPacket.bytes || 64} bytes</div>
                    <div>• Capture Length: {selectedPacket.bytes || 64} bytes</div>
                    <div>• Epoch Arrival: {selectedPacket.timestamp_epoch_ms || Date.now()} ms</div>
                  </div>
                )}
              </div>

              {/* Ethernet II Tree Node */}
              <div className="rounded bg-slate-900/40 border border-slate-800/80 p-2">
                <div
                  onClick={() => toggleNode('eth')}
                  className="cursor-pointer font-semibold text-slate-300 flex items-center gap-1 hover:text-cyan-400"
                >
                  <span>{expandedNodes.eth ? '▼' : '▶'}</span>
                  <span>Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: ff:ff:ff:ff:ff:ff</span>
                </div>
                {expandedNodes.eth && (
                  <div className="pl-4 pt-1 space-y-0.5 text-slate-400 text-[11px]">
                    <div onClick={() => setHighlightedByteRange([0, 6])} className="cursor-pointer hover:text-cyan-300">
                      • Destination: Broadcast (ff:ff:ff:ff:ff:ff)
                    </div>
                    <div onClick={() => setHighlightedByteRange([6, 12])} className="cursor-pointer hover:text-cyan-300">
                      • Source: 00:1a:2b:3c:4d:5e
                    </div>
                    <div onClick={() => setHighlightedByteRange([12, 14])} className="cursor-pointer hover:text-cyan-300">
                      • Type: IPv4 (0x0800)
                    </div>
                  </div>
                )}
              </div>

              {/* IPv4 Tree Node */}
              <div className="rounded bg-slate-900/40 border border-slate-800/80 p-2">
                <div
                  onClick={() => toggleNode('ip')}
                  className="cursor-pointer font-semibold text-slate-300 flex items-center gap-1 hover:text-cyan-400"
                >
                  <span>{expandedNodes.ip ? '▼' : '▶'}</span>
                  <span>Internet Protocol Version 4, Src: {selectedPacket.src_ip}, Dst: {selectedPacket.dst_ip}</span>
                </div>
                {expandedNodes.ip && (
                  <div className="pl-4 pt-1 space-y-0.5 text-slate-400 text-[11px]">
                    <div onClick={() => setHighlightedByteRange([14, 15])} className="cursor-pointer hover:text-cyan-300">
                      • Version: 4, Header Length: 20 bytes
                    </div>
                    <div onClick={() => setHighlightedByteRange([22, 23])} className="cursor-pointer hover:text-cyan-300">
                      • Time to Live: 64
                    </div>
                    <div onClick={() => setHighlightedByteRange([23, 24])} className="cursor-pointer hover:text-cyan-300">
                      • Protocol: {selectedPacket.protocol || 'TCP'} ({selectedPacket.protocol === 'UDP' ? 17 : 6})
                    </div>
                    <div onClick={() => setHighlightedByteRange([26, 30])} className="cursor-pointer hover:text-cyan-300">
                      • Source Address: {selectedPacket.src_ip}
                    </div>
                    <div onClick={() => setHighlightedByteRange([30, 34])} className="cursor-pointer hover:text-cyan-300">
                      • Destination Address: {selectedPacket.dst_ip}
                    </div>
                  </div>
                )}
              </div>

              {/* Transport Tree Node (TCP / UDP) */}
              <div className="rounded bg-slate-900/40 border border-slate-800/80 p-2">
                <div
                  onClick={() => toggleNode('transport')}
                  className="cursor-pointer font-semibold text-slate-300 flex items-center gap-1 hover:text-cyan-400"
                >
                  <span>{expandedNodes.transport ? '▼' : '▶'}</span>
                  <span>
                    {selectedPacket.protocol || 'TCP'}, Src Port: {selectedPacket.src_port}, Dst Port: {selectedPacket.dst_port}
                  </span>
                </div>
                {expandedNodes.transport && (
                  <div className="pl-4 pt-1 space-y-0.5 text-slate-400 text-[11px]">
                    <div onClick={() => setHighlightedByteRange([34, 36])} className="cursor-pointer hover:text-cyan-300">
                      • Source Port: {selectedPacket.src_port}
                    </div>
                    <div onClick={() => setHighlightedByteRange([36, 38])} className="cursor-pointer hover:text-cyan-300">
                      • Destination Port: {selectedPacket.dst_port}
                    </div>
                    <div onClick={() => setHighlightedByteRange([38, 42])} className="cursor-pointer hover:text-cyan-300">
                      • Sequence Number: 1 (relative)
                    </div>
                    <div onClick={() => setHighlightedByteRange([46, 48])} className="cursor-pointer hover:text-cyan-300">
                      • Flags: {selectedPacket.flags || 'SYN, ACK'}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-slate-500 py-8 text-center">No packet selected</div>
          )}
        </div>

        {/* Pane 3: 16-Byte Hex and ASCII Dump */}
        <div className="p-3 overflow-y-auto font-mono text-[11px]">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">
            Hex & ASCII Byte Stream
          </div>

          <div className="bg-slate-900/60 p-2 rounded border border-slate-800/80 select-text overflow-x-auto">
            {hexDumpRows.map((row) => {
              const isHighlighted =
                highlightedByteRange &&
                row.startByte < highlightedByteRange[1] &&
                row.endByte > highlightedByteRange[0];

              return (
                <div
                  key={row.offset}
                  className={`flex items-center gap-4 py-0.5 transition-colors ${
                    isHighlighted ? 'bg-cyan-500/20 text-cyan-200' : 'text-slate-300 hover:bg-slate-800/40'
                  }`}
                >
                  <span className="text-slate-500 font-mono w-10">{row.offset}</span>
                  <span className="text-cyan-400/90 font-mono w-48 tracking-wider">{row.hexGroup1}</span>
                  <span className="text-cyan-400/90 font-mono w-48 tracking-wider">{row.hexGroup2}</span>
                  <span className="text-emerald-400 font-mono tracking-widest pl-2 border-l border-slate-800">
                    {row.ascii}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
