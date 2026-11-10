import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
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
}) => {
  const mountRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);

  // Map real devices to 3D celestial nodes
  const nodesData = useMemo(() => {
    return MOCK_NODES.map((mockNode, index) => {
      const realDevice = Array.isArray(devices) && devices[index] ? devices[index] : null;
      if (!realDevice) return mockNode;

      const isHighRisk =
        (Number(realDevice.risk_score) || 0) >= 60 ||
        ['CRITICAL', 'HIGH'].includes(String(realDevice.risk_level).toUpperCase());
      const isVpn = Boolean(realDevice.is_vpn || realDevice.vpn_provider || realDevice.detection_type === 'vpn');
      const isNew = Boolean(realDevice.is_new);

      let color = '#60A5FA';
      let riskLabel = 'Normal';
      if (isHighRisk) {
        color = '#EF4444';
        riskLabel = 'High Risk';
      } else if (isVpn) {
        color = '#8B5CF6';
        riskLabel = 'VPN';
      } else if (isNew) {
        color = '#10B981';
        riskLabel = 'New Device';
      }

      return {
        ...mockNode,
        ip: realDevice.ip || mockNode.ip,
        hostname: realDevice.hostname || mockNode.hostname,
        risk: riskLabel,
        color,
      };
    });
  }, [devices]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let width = container.clientWidth || 720;
    let height = container.clientHeight || 250;

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

    const centerPointLight = new THREE.PointLight(0x3b82f6, 3, 20);
    centerPointLight.position.set(0, 1, 0);
    scene.add(centerPointLight);

    // Root Group for interactive rotation
    const worldGroup = new THREE.Group();
    scene.add(worldGroup);

    // 3. Central Gateway Hub Geometry
    const hubGroup = new THREE.Group();
    worldGroup.add(hubGroup);

    const hubCoreGeo = new THREE.IcosahedronGeometry(0.7, 1);
    const hubCoreMat = new THREE.MeshBasicMaterial({
      color: 0x60a5fa,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const hubCoreMesh = new THREE.Mesh(hubCoreGeo, hubCoreMat);
    hubGroup.add(hubCoreMesh);

    const hubInnerGeo = new THREE.SphereGeometry(0.35, 16, 16);
    const hubInnerMat = new THREE.MeshBasicMaterial({ color: 0x93c5fd });
    const hubInnerMesh = new THREE.Mesh(hubInnerGeo, hubInnerMat);
    hubGroup.add(hubInnerMesh);

    // Concentric Radar Rings
    const ringGeo1 = new THREE.RingGeometry(1.2, 1.25, 48);
    const ringGeo2 = new THREE.RingGeometry(2.8, 2.85, 48);
    const ringGeo3 = new THREE.RingGeometry(5.2, 5.25, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x3b82f6,
      transparent: true,
      opacity: 0.22,
      side: THREE.DoubleSide,
    });

    const ring1 = new THREE.Mesh(ringGeo1, ringMat);
    ring1.rotation.x = Math.PI / 2;
    worldGroup.add(ring1);

    const ring2 = new THREE.Mesh(ringGeo2, ringMat);
    ring2.rotation.x = Math.PI / 2;
    worldGroup.add(ring2);

    const ring3 = new THREE.Mesh(ringGeo3, ringMat.clone());
    ring3.material.opacity = 0.12;
    ring3.rotation.x = Math.PI / 2;
    worldGroup.add(ring3);

    // Rotating Radar Sweep Beam
    const radarBeamGeo = new THREE.CircleGeometry(6.2, 32, 0, Math.PI / 3);
    const radarBeamMat = new THREE.MeshBasicMaterial({
      color: 0x60a5fa,
      transparent: true,
      opacity: 0.08,
      side: THREE.DoubleSide,
    });
    const radarBeam = new THREE.Mesh(radarBeamGeo, radarBeamMat);
    radarBeam.rotation.x = Math.PI / 2;
    worldGroup.add(radarBeam);

    // 4. Client Satellite Nodes & Spoke Lines
    const nodeMeshes = [];
    const spokeLines = [];
    const nodeGeo = new THREE.SphereGeometry(0.28, 16, 16);
    const haloGeo = new THREE.RingGeometry(0.36, 0.42, 24);

    nodesData.forEach((node) => {
      const colorNum = new THREE.Color(node.color);

      // Node mesh
      const mat = new THREE.MeshBasicMaterial({ color: colorNum });
      const mesh = new THREE.Mesh(nodeGeo, mat);

      const x = Math.cos(node.angle) * node.radius;
      const z = Math.sin(node.angle) * (node.radius * 0.75); // slight elliptical squish
      const y = node.yOffset || 0;
      mesh.position.set(x, y, z);
      mesh.userData = node;

      // Halo ring
      const haloMat = new THREE.MeshBasicMaterial({
        color: colorNum,
        transparent: true,
        opacity: node.risk === 'High Risk' ? 0.8 : 0.4,
        side: THREE.DoubleSide,
      });
      const haloMesh = new THREE.Mesh(haloGeo, haloMat);
      haloMesh.lookAt(camera.position);
      mesh.add(haloMesh);

      worldGroup.add(mesh);
      nodeMeshes.push(mesh);

      // Spoke Line from Hub (0,0,0) to Node
      const lineGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(x, y, z),
      ]);
      const lineMat = new THREE.LineBasicMaterial({
        color: colorNum,
        transparent: true,
        opacity: node.risk === 'High Risk' ? 0.45 : 0.18,
      });
      const line = new THREE.Line(lineGeo, lineMat);
      line.userData = { nodeId: node.id };
      worldGroup.add(line);
      spokeLines.push(line);
    });

    // 5. Streaming Data Packet Particle System
    const PARTICLE_COUNT = 90;
    const packetGeo = new THREE.BufferGeometry();
    const packetPositions = new Float32Array(PARTICLE_COUNT * 3);
    const packetColors = new Float32Array(PARTICLE_COUNT * 3);

    const particles = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const targetNode = nodeMeshes[i % nodeMeshes.length];
      const targetColor = new THREE.Color(targetNode.userData.color);
      const isOutbound = Math.random() > 0.4;

      particles.push({
        targetIndex: i % nodeMeshes.length,
        progress: Math.random(),
        speed: (0.006 + Math.random() * 0.012) * (targetNode.userData.risk === 'High Risk' ? 1.6 : 1.0),
        isOutbound,
      });

      packetColors[i * 3] = targetColor.r;
      packetColors[i * 3 + 1] = targetColor.g;
      packetColors[i * 3 + 2] = targetColor.b;
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
    const packetPoints = new THREE.Points(packetGeo, packetMat);
    worldGroup.add(packetPoints);

    // 6. Interactive Raycasting & Mouse Controls
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(-999, -999);
    let rotationVelocityX = 0;
    let rotationVelocityY = 0.0018;
    let isMouseDown = false;
    let prevMouseX = 0;
    let prevMouseY = 0;

    const handlePointerMove = (e) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      if (isMouseDown) {
        const deltaX = e.clientX - prevMouseX;
        const deltaY = e.clientY - prevMouseY;
        worldGroup.rotation.y += deltaX * 0.006;
        worldGroup.rotation.x = Math.max(-0.4, Math.min(0.4, worldGroup.rotation.x + deltaY * 0.004));
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;
      }
    };

    const handlePointerDown = (e) => {
      isMouseDown = true;
      setIsDragging(true);
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const handlePointerUp = () => {
      isMouseDown = false;
      setIsDragging(false);
    };

    const handleClick = (e) => {
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);
      if (intersects.length > 0) {
        const hit = intersects[0].object;
        if (hit?.userData?.ip) {
          onSelectDevice?.(hit.userData.ip);
        }
      }
    };

    const dom = renderer.domElement;
    dom.addEventListener('pointermove', handlePointerMove);
    dom.addEventListener('pointerdown', handlePointerDown);
    window.addEventListener('pointerup', handlePointerUp);
    dom.addEventListener('click', handleClick);

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      width = container.clientWidth || 720;
      height = container.clientHeight || 250;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    };
    window.addEventListener('resize', handleResize);

    // 7. Animation Loop with Reduced-Motion and Visibility Check
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
        positions[i * 3 + 1] = targetPos.y * t + Math.sin(t * Math.PI) * 0.35; // gentle parabolic arc
        positions[i * 3 + 2] = targetPos.z * t;
      }
      packetGeo.attributes.position.needsUpdate = true;

      // Interactive Raycasting for Hover Highlights
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        const hit = intersects[0].object;
        dom.style.cursor = 'pointer';

        if (hoveredNode?.id !== hit.userData.id) {
          setHoveredNode(hit.userData);
        }

        // Project 3D coordinate to 2D screen coordinate for tooltip positioning
        const screenPos = hit.position.clone();
        screenPos.project(camera);
        const screenX = ((screenPos.x + 1) * width) / 2;
        const screenY = ((-screenPos.y + 1) * height) / 2;
        setTooltipPos({ x: screenX, y: screenY });

        // Enlarge hovered node
        hit.scale.setScalar(1.35);
      } else {
        dom.style.cursor = isMouseDown ? 'grabbing' : 'grab';
        if (hoveredNode) {
          setHoveredNode(null);
        }
        nodeMeshes.forEach((mesh) => mesh.scale.setScalar(1.0));
      }

      // Filter Dimmings
      nodeMeshes.forEach((mesh) => {
        const matchesFilter = activeFilter === 'ALL' || mesh.userData.risk === activeFilter;
        mesh.visible = matchesFilter;
      });

      spokeLines.forEach((line) => {
        const matchingNode = nodeMeshes.find((m) => m.userData.id === line.userData.nodeId);
        line.visible = matchingNode ? matchingNode.visible : true;
      });

      renderer.render(scene, camera);
    };

    animate();

    // 8. Proper Cleanup on Unmount
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
  }, [nodesData, activeFilter, isMotionPaused, onSelectDevice]);

  return (
    <div className="relative w-full h-full select-none overflow-hidden">
      {/* 3D WebGL Canvas Container */}
      <div ref={mountRef} className="w-full h-full" />

      {/* Cyber HUD Floating Tooltip on Hover */}
      {hoveredNode && (
        <div
          className="absolute z-30 pointer-events-none transform -translate-x-1/2 -translate-y-full mb-3 transition-transform duration-75"
          style={{
            left: `${tooltipPos.x}px`,
            top: `${tooltipPos.y}px`,
          }}
        >
          <div className="glass-card px-3 py-2 rounded-xl border border-white/20 bg-[#090C16]/90 shadow-[0_10px_25px_rgba(0,0,0,0.6)] backdrop-blur-md flex flex-col gap-1 min-w-[140px]">
            <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-1">
              <span className="font-bold text-xs text-white truncate max-w-[100px]">
                {hoveredNode.hostname}
              </span>
              <span
                className="text-[9.5px] font-bold px-1.5 py-0.2 rounded-full uppercase"
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
              Click node to view telemetry &rarr;
            </div>
          </div>
        </div>
      )}

      {/* Subtle Hint Controls */}
      <div className="absolute bottom-2.5 left-3 z-10 pointer-events-none flex items-center gap-3 text-[10px] text-[#9AA3B8]/80 bg-black/40 backdrop-blur-sm px-2.5 py-1 rounded-lg border border-white/5">
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
