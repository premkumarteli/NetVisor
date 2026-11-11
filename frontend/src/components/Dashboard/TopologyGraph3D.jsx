import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';

const MOCK_NODES = [
  { id: '1', ip: '192.168.1.10', hostname: 'Laptop-01', type: 'laptop', os: 'Windows', risk: 'Normal', color: '#60A5FA', angle: 0.2, radius: 4.8, yOffset: 0.3, speed: 0.02 },
  { id: '2', ip: '192.168.1.15', hostname: 'Android-12', type: 'phone', os: 'Android', risk: 'VPN', color: '#8B5CF6', angle: 0.7, radius: 5.6, yOffset: -0.4, speed: 0.03 },
  { id: '3', ip: '192.168.1.20', hostname: 'PC-Office', type: 'desktop', os: 'Windows', risk: 'Normal', color: '#60A5FA', angle: 1.2, radius: 4.3, yOffset: 0.5, speed: 0.015 },
  { id: '4', ip: '192.168.1.25', hostname: 'iPhone', type: 'phone', os: 'iOS', risk: 'High Risk', color: '#EF4444', angle: 1.8, radius: 5.1, yOffset: -0.2, speed: 0.035 },
  { id: '5', ip: '192.168.1.30', hostname: 'Server-01', type: 'server', os: 'Linux', risk: 'Normal', color: '#60A5FA', angle: 2.3, radius: 6.2, yOffset: 0.6, speed: 0.022 },
  { id: '6', ip: '192.168.1.35', hostname: 'SmartTV', type: 'tv', os: 'Others', risk: 'Normal', color: '#60A5FA', angle: 2.9, radius: 5.8, yOffset: -0.5, speed: 0.012 },
  { id: '7', ip: '192.168.1.40', hostname: 'Printer-HQ', type: 'printer', os: 'Others', risk: 'New Device', color: '#10B981', angle: 3.5, radius: 4.6, yOffset: 0.4, speed: 0.018 },
  { id: '8', ip: '192.168.1.45', hostname: 'Security-Cam', type: 'camera', os: 'Linux', risk: 'High Risk', color: '#EF4444', angle: 4.0, radius: 5.4, yOffset: -0.6, speed: 0.028 },
  { id: '9', ip: '192.168.1.50', hostname: 'VPN-Gateway', type: 'gateway', os: 'Linux', risk: 'VPN', color: '#8B5CF6', angle: 4.6, radius: 6.0, yOffset: 0.2, speed: 0.025 },
  { id: '10', ip: '192.168.1.55', hostname: 'New-Device', type: 'phone', os: 'Android', risk: 'New Device', color: '#10B981', angle: 5.1, radius: 4.2, yOffset: -0.3, speed: 0.02 },
  { id: '11', ip: '192.168.1.60', hostname: 'Backup-NAS', type: 'storage', os: 'Linux', risk: 'Normal', color: '#60A5FA', angle: 5.6, radius: 5.0, yOffset: 0.7, speed: 0.016 },
  { id: '12', ip: '192.168.1.65', hostname: 'Tablet-02', type: 'tablet', os: 'iOS', risk: 'Normal', color: '#60A5FA', angle: 6.0, radius: 4.5, yOffset: -0.4, speed: 0.024 },
];

export const TopologyGraph3D = ({
  devices = [],
  activity = [],
  onSelectDevice,
  activeFilter = 'ALL',
  isMotionPaused = false,
  palette = null,
}) => {
  const mountRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Map real devices to 3D celestial nodes
  const nodesData = useMemo(() => {
    return MOCK_NODES.map((mockNode, index) => {
      const realDevice = Array.isArray(devices) && devices[index] ? devices[index] : null;
      if (!realDevice) return mockNode;

      const isHighRisk =
        (Number(realDevice.risk_score) || 0) >= 60 ||
        ['CRITICAL', 'HIGH'].includes(String(realDevice.risk_level || realDevice.severity).toUpperCase());
      const isVpn = Boolean(realDevice.is_vpn || realDevice.vpn_provider || realDevice.detection_type === 'vpn');
      const isNew = Boolean(realDevice.is_new);

      let color = '#60A5FA';
      let riskLabel = 'Normal';
      if (isHighRisk) {
        color = palette?.danger || '#EF4444';
        riskLabel = 'High Risk';
      } else if (isVpn) {
        color = palette?.secondary || '#8B5CF6';
        riskLabel = 'VPN';
      } else if (isNew) {
        color = palette?.success || '#10B981';
        riskLabel = 'New Device';
      }

      return {
        ...mockNode,
        ip: realDevice.ip || realDevice.ip_address || mockNode.ip,
        hostname: realDevice.hostname || realDevice.name || mockNode.hostname,
        risk: riskLabel,
        color,
        deviceRef: realDevice,
      };
    });
  }, [devices, palette]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let width = container.clientWidth || 680;
    let height = container.clientHeight || 260;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05070e, 0.04);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 7.5, 11);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.2;
    container.appendChild(renderer.domElement);

    // 2. Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const centerPointLight = new THREE.PointLight(palette?.accent ? parseInt(palette.accent.replace('#', '0x'), 16) : 0x3b82f6, 3, 20);
    centerPointLight.position.set(0, 1, 0);
    scene.add(centerPointLight);

    // Root Group for interactive rotation
    const worldGroup = new THREE.Group();
    scene.add(worldGroup);

    // 3. Central Gateway Hub Geometry
    const hubGroup = new THREE.Group();

    // Inner glowing sphere
    const hubCoreGeo = new THREE.IcosahedronGeometry(0.75, 1);
    const hubCoreMat = new THREE.MeshBasicMaterial({
      color: palette?.accent ? parseInt(palette.accent.replace('#', '0x'), 16) : 0x3b82f6,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const hubCoreMesh = new THREE.Mesh(hubCoreGeo, hubCoreMat);
    hubGroup.add(hubCoreMesh);

    // Inner solid core
    const hubInnerGeo = new THREE.SphereGeometry(0.45, 16, 16);
    const hubInnerMat = new THREE.MeshBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.9,
    });
    const hubInnerMesh = new THREE.Mesh(hubInnerGeo, hubInnerMat);
    hubGroup.add(hubInnerMesh);

    // Outer gateway protective orbital ring
    const hubRingGeo = new THREE.RingGeometry(0.95, 1.05, 32);
    const hubRingMat = new THREE.MeshBasicMaterial({
      color: 0x60a5fa,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.4,
    });
    const hubRingMesh = new THREE.Mesh(hubRingGeo, hubRingMat);
    hubRingMesh.rotation.x = Math.PI / 2;
    hubGroup.add(hubRingMesh);

    worldGroup.add(hubGroup);

    // 4. Concentric Radar Grid Rings & Sweeper
    const gridGroup = new THREE.Group();
    const ringMat = new THREE.LineBasicMaterial({ color: 0x1e3a8a, transparent: true, opacity: 0.4 });

    const createRing = (radius) => {
      const segments = 64;
      const ringPoints = [];
      for (let i = 0; i <= segments; i++) {
        const theta = (i / segments) * Math.PI * 2;
        ringPoints.push(new THREE.Vector3(Math.cos(theta) * radius, 0, Math.sin(theta) * radius));
      }
      const ringGeo = new THREE.BufferGeometry().setFromPoints(ringPoints);
      return new THREE.Line(ringGeo, ringMat);
    };

    const ring1 = createRing(3.2);
    const ring2 = createRing(5.2);
    const ring3 = createRing(7.0);
    gridGroup.add(ring1);
    gridGroup.add(ring2);
    gridGroup.add(ring3);

    // Radar Rotating Sector Sweep
    const radarBeamGeo = new THREE.RingGeometry(0.2, 7.2, 32, 1, 0, Math.PI / 3);
    const radarBeamMat = new THREE.MeshBasicMaterial({
      color: 0x3b82f6,
      transparent: true,
      opacity: 0.08,
      side: THREE.DoubleSide,
    });
    const radarBeam = new THREE.Mesh(radarBeamGeo, radarBeamMat);
    radarBeam.rotation.x = Math.PI / 2;
    gridGroup.add(radarBeam);

    worldGroup.add(gridGroup);

    // 5. Satellite Device Nodes
    const nodeMeshes = [];
    const interactiveObjects = [];
    const spokeLines = [];

    nodesData.forEach((node, index) => {
      const nodeGroup = new THREE.Group();

      const x = Math.cos(node.angle) * node.radius;
      const z = Math.sin(node.angle) * (node.radius * 0.85);
      const y = node.yOffset;

      nodeGroup.position.set(x, y, z);

      // Node Sphere
      const nodeColor = parseInt(node.color.replace('#', '0x'), 16);
      const nodeGeo = new THREE.SphereGeometry(0.24, 16, 16);
      const nodeMat = new THREE.MeshBasicMaterial({ color: nodeColor });
      const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
      nodeGroup.add(nodeMesh);

      // Outer Status Halo Ring
      const haloGeo = new THREE.RingGeometry(0.34, 0.4, 24);
      const haloMat = new THREE.MeshBasicMaterial({
        color: nodeColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.6,
      });
      const haloMesh = new THREE.Mesh(haloGeo, haloMat);
      haloMesh.rotation.x = Math.PI / 2;
      nodeGroup.add(haloMesh);

      // Save references
      nodeGroup.userData = { ...node, index, originalScale: 1 };
      nodeMeshes.push(nodeGroup);
      interactiveObjects.push(nodeMesh);
      worldGroup.add(nodeGroup);

      // Spoke Connection Line to Hub
      const spokePoints = [new THREE.Vector3(0, 0, 0), new THREE.Vector3(x, y, z)];
      const spokeGeo = new THREE.BufferGeometry().setFromPoints(spokePoints);
      const spokeMat = new THREE.LineBasicMaterial({
        color: nodeColor,
        transparent: true,
        opacity: 0.18,
      });
      const spokeLine = new THREE.Line(spokeGeo, spokeMat);
      spokeLines.push(spokeLine);
      worldGroup.add(spokeLine);
    });

    // 6. Real-Time Packet Particle Stream
    const PARTICLE_COUNT = 45;
    const packetGeo = new THREE.BufferGeometry();
    const packetPositions = new Float32Array(PARTICLE_COUNT * 3);
    const packetColors = new Float32Array(PARTICLE_COUNT * 3);
    const particles = [];

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const targetNodeIndex = i % nodesData.length;
      const speed = 0.008 + Math.random() * 0.015;
      const isOutbound = Math.random() > 0.4;
      particles.push({
        targetIndex: targetNodeIndex,
        progress: Math.random(),
        speed,
        isOutbound,
      });

      const nodeColor = new THREE.Color(nodesData[targetNodeIndex].color);
      packetColors[i * 3] = nodeColor.r;
      packetColors[i * 3 + 1] = nodeColor.g;
      packetColors[i * 3 + 2] = nodeColor.b;
    }

    packetGeo.setAttribute('position', new THREE.BufferAttribute(packetPositions, 3));
    packetGeo.setAttribute('color', new THREE.BufferAttribute(packetColors, 3));

    const packetMat = new THREE.PointsMaterial({
      size: 0.18,
      vertexColors: true,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    const packetSystem = new THREE.Points(packetGeo, packetMat);
    worldGroup.add(packetSystem);

    // 7. Interactive Raycasting & Controls
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(-999, -999);

    let isMouseDown = false;
    let prevMouseX = 0;
    let rotationVelocityY = 0.002;

    const dom = renderer.domElement;

    const handlePointerMove = (e) => {
      const rect = dom.getBoundingClientRect();
      const clientX = e.clientX - rect.left;
      const clientY = e.clientY - rect.top;

      mouse.x = (clientX / rect.width) * 2 - 1;
      mouse.y = -(clientY / rect.height) * 2 + 1;

      if (isMouseDown) {
        const deltaX = e.clientX - prevMouseX;
        worldGroup.rotation.y += deltaX * 0.006;
        prevMouseX = e.clientX;
      }

      // Raycast against nodes
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(interactiveObjects);

      if (intersects.length > 0) {
        const hitGroup = intersects[0].object.parent;
        const data = hitGroup.userData;
        setHoveredNode(data);
        setTooltipPos({ x: clientX, y: clientY });
        dom.style.cursor = 'pointer';

        nodeMeshes.forEach((n) => {
          if (n === hitGroup) {
            n.scale.setScalar(1.35);
          } else {
            n.scale.setScalar(1);
          }
        });
      } else {
        setHoveredNode(null);
        dom.style.cursor = 'grab';
        nodeMeshes.forEach((n) => n.scale.setScalar(1));
      }
    };

    const handlePointerDown = (e) => {
      isMouseDown = true;
      prevMouseX = e.clientX;
      dom.style.cursor = 'grabbing';
    };

    const handlePointerUp = () => {
      isMouseDown = false;
      dom.style.cursor = 'grab';
    };

    const handleClick = () => {
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(interactiveObjects);
      if (intersects.length > 0) {
        const hitData = intersects[0].object.parent.userData;
        if (onSelectDevice) {
          onSelectDevice(hitData.deviceRef || hitData);
        }
      }
    };

    dom.addEventListener('pointermove', handlePointerMove);
    dom.addEventListener('pointerdown', handlePointerDown);
    window.addEventListener('pointerup', handlePointerUp);
    dom.addEventListener('click', handleClick);

    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth;
      const newHeight = container.clientHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };
    window.addEventListener('resize', handleResize);

    // 8. Animation Loop with Reduced-Motion and Visibility Check
    let animationFrameId;
    let lastTime = performance.now();
    let startTime = performance.now();

    const animate = (currentTime) => {
      animationFrameId = requestAnimationFrame(animate);

      // Auto-pause rendering when browser tab is hidden
      if (document.hidden) return;

      const now = currentTime || performance.now();
      const delta = Math.min((now - lastTime) / 1000, 0.1);
      lastTime = now;
      const elapsedTime = (now - startTime) / 1000;

      if (!isMotionPaused && !isMouseDown) {
        worldGroup.rotation.y += rotationVelocityY;
      }

      // Hub dynamic rotation
      hubCoreMesh.rotation.x += 0.015;
      hubCoreMesh.rotation.y += 0.02;

      // Radar beam rotation
      radarBeam.rotation.z -= 0.035;

      // Pulse Radar Rings
      ring1.scale.setScalar(1 + Math.sin(elapsedTime * 2.2) * 0.06);
      ring2.scale.setScalar(1 + Math.sin(elapsedTime * 1.8) * 0.04);

      // Update Streaming Data Packets
      const positions = packetGeo.attributes.position.array;
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const p = particles[i];
        const targetNode = nodeMeshes[p.targetIndex];

        if (!isMotionPaused) {
          p.progress += p.speed;
          if (p.progress >= 1) {
            p.progress = 0;
            p.isOutbound = Math.random() > 0.4;
          }
        }

        const t = p.isOutbound ? p.progress : 1 - p.progress;
        const targetPos = targetNode.position;

        positions[i * 3] = targetPos.x * t;
        // Parabolic arc trajectory
        const heightArc = Math.sin(t * Math.PI) * 0.45;
        positions[i * 3 + 1] = targetPos.y * t + heightArc;
        positions[i * 3 + 2] = targetPos.z * t;
      }
      packetGeo.attributes.position.needsUpdate = true;

      // Filter Visibility Highlights
      nodeMeshes.forEach((mesh) => {
        const rk = mesh.userData.risk;
        if (activeFilter === 'ALL') {
          mesh.visible = true;
        } else if (activeFilter === 'HIGH' && rk === 'High Risk') {
          mesh.visible = true;
        } else if (activeFilter === 'VPN' && rk === 'VPN') {
          mesh.visible = true;
        } else if (activeFilter === 'NEW' && rk === 'New Device') {
          mesh.visible = true;
        } else {
          mesh.visible = false;
        }
      });

      renderer.render(scene, camera);
    };

    animate(performance.now());

    // 9. Proper Cleanup on Unmount
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      dom.removeEventListener('pointermove', handlePointerMove);
      dom.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('pointerup', handlePointerUp);
      dom.removeEventListener('click', handleClick);

      // Dispose Geometries and Materials
      scene.traverse((object) => {
        if (object.geometry) object.geometry.dispose();
        if (object.material) {
          if (Array.isArray(object.material)) {
            object.material.forEach((mat) => mat.dispose());
          } else {
            object.material.dispose();
          }
        }
      });

      renderer.dispose();
      if (dom && dom.parentNode) {
        dom.parentNode.removeChild(dom);
      }
    };
  }, [nodesData, activeFilter, isMotionPaused, onSelectDevice, palette]);

  return (
    <div className="relative w-full h-full select-none overflow-hidden" style={{ minHeight: '260px' }}>
      {/* 3D WebGL Canvas Container */}
      <div ref={mountRef} className="w-full h-full" style={{ height: '260px' }} />

      {/* Cyber HUD Floating Tooltip on Hover */}
      {hoveredNode && (
        <div
          className="absolute z-30 pointer-events-none transform -translate-x-1/2 -translate-y-full mb-3"
          style={{
            left: `${tooltipPos.x}px`,
            top: `${tooltipPos.y}px`,
          }}
        >
          <div className="glass-card px-3 py-2 rounded-xl border border-white/20 bg-[#090C16]/95 shadow-[0_10px_25px_rgba(0,0,0,0.8)] backdrop-blur-md flex flex-col gap-1 min-w-[150px]">
            <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-1">
              <span className="font-bold text-xs text-white truncate max-w-[100px]">
                {hoveredNode.hostname}
              </span>
              <span
                className="text-[9.5px] font-bold px-1.5 py-0.5 rounded-full uppercase"
                style={{
                  color: hoveredNode.color,
                  backgroundColor: `${hoveredNode.color}20`,
                  border: `1px solid ${hoveredNode.color}40`,
                }}
              >
                {hoveredNode.risk}
              </span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-[#9AA3B8] pt-0.5">
              <span>IP Address:</span>
              <span className="mono text-white font-medium">{hoveredNode.ip}</span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-[#9AA3B8]">
              <span>Device Type:</span>
              <span className="capitalize text-white">{hoveredNode.type}</span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-[#9AA3B8]">
              <span>Operating System:</span>
              <span className="text-white">{hoveredNode.os}</span>
            </div>
            <div className="text-[9px] text-blue-400 font-medium text-center pt-1 border-t border-white/5">
              Click node to view details &rarr;
            </div>
          </div>
        </div>
      )}

      {/* Subtle Hint Controls */}
      <div className="absolute bottom-2 left-3 z-10 pointer-events-none flex items-center gap-3 text-[10px] text-[#9AA3B8]/80 bg-black/50 backdrop-blur-sm px-2.5 py-1 rounded-lg border border-white/10">
        <span className="flex items-center gap-1">
          <i className="ri-drag-move-2-line text-blue-400"></i> Drag to rotate
        </span>
        <span className="w-1 h-1 rounded-full bg-white/20" />
        <span className="flex items-center gap-1">
          <i className="ri-cursor-line text-emerald-400"></i> Hover & Click node
        </span>
      </div>
    </div>
  );
};

export default TopologyGraph3D;
