/**
 * SS-TOOLS 3D Visualization Engine
 * Pure Canvas-based 3D Minecraft block visualization
 * No external dependencies -- works in Electron CSP
 */

// ============================================================
// 3D Minecraft Block Renderer (Isometric Canvas)
// ============================================================

class MinecraftViz {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.width = 0;
    this.height = 0;
    this.rotation = 0;
    this.scanProgress = 0;
    this.threats = [];
    this.particles = [];
    this.isScanning = false;
    this.status = 'READY';
    this.animationId = null;

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.startAnimation();
  }

  resize() {
    const container = this.canvas.parentElement;
    if (!container) return;
    this.width = container.clientWidth;
    this.height = container.clientHeight || 280;
    this.canvas.width = this.width * (window.devicePixelRatio || 1);
    this.canvas.height = this.height * (window.devicePixelRatio || 1);
    this.canvas.style.width = this.width + 'px';
    this.canvas.style.height = this.height + 'px';
    this.ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
  }

  startAnimation() {
    const animate = () => {
      this.rotation += 0.008;
      this.render();
      this.animationId = requestAnimationFrame(animate);
    };
    animate();
  }

  stopAnimation() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
      this.animationId = null;
    }
  }

  setScanning(scanning) {
    this.isScanning = scanning;
    this.status = scanning ? 'SCANNING' : 'READY';
    if (scanning) {
      this.scanProgress = 0;
      this.threats = [];
    }
  }

  setProgress(progress) {
    this.scanProgress = Math.min(100, Math.max(0, progress));
  }

  setStatus(status) {
    this.status = status;
  }

  addThreat(severity) {
    this.threats.push({
      x: Math.random() * this.width,
      y: Math.random() * this.height,
      severity: severity,
      alpha: 1,
      radius: 5 + Math.random() * 15,
      age: 0
    });
  }

  // Add floating particles
  addParticle() {
    this.particles.push({
      x: Math.random() * this.width,
      y: this.height + 10,
      vx: (Math.random() - 0.5) * 0.5,
      vy: -0.5 - Math.random() * 1.5,
      size: 1 + Math.random() * 3,
      alpha: 0.3 + Math.random() * 0.5,
      color: this.isScanning ? '#6c5ce7' : '#2a2a40',
      life: 200 + Math.random() * 200
    });
  }

  render() {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    // Clear
    ctx.clearRect(0, 0, w, h);

    // Background gradient
    const bgGrad = ctx.createLinearGradient(0, 0, 0, h);
    bgGrad.addColorStop(0, '#0a0a0f');
    bgGrad.addColorStop(1, '#12121a');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = 'rgba(108, 92, 231, 0.05)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Particles
    if (Math.random() < (this.isScanning ? 0.3 : 0.05)) {
      this.addParticle();
    }

    this.particles = this.particles.filter(p => {
      p.x += p.vx;
      p.y += p.vy;
      p.life--;
      p.alpha *= 0.998;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color + Math.round(p.alpha * 255).toString(16).padStart(2, '0');
      ctx.fill();

      return p.life > 0 && p.alpha > 0.01;
    });

    // Draw rotating 3D Minecraft block
    this.drawMinecraftBlock(ctx, w / 2, h / 2 - 10, 60, this.rotation);

    // Draw scan ring
    if (this.isScanning) {
      this.drawScanRing(ctx, w / 2, h / 2 - 10, 90, this.scanProgress);
    }

    // Draw threats
    this.threats = this.threats.filter(t => {
      t.age++;
      t.alpha = Math.max(0, 1 - t.age / 120);
      t.radius += 0.3;

      const color = t.severity === 'critical' ? '255, 71, 87' :
                    t.severity === 'high' ? '255, 165, 2' : '108, 92, 231';

      ctx.beginPath();
      ctx.arc(t.x, t.y, t.radius, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${color}, ${t.alpha})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(t.x, t.y, t.radius * 0.3, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${color}, ${t.alpha * 0.5})`;
      ctx.fill();

      return t.alpha > 0.01;
    });

    // Progress bar at bottom
    if (this.isScanning) {
      const barY = h - 20;
      const barW = w - 80;
      const barH = 4;
      const barX = 40;

      ctx.fillStyle = 'rgba(42, 42, 64, 0.5)';
      ctx.fillRect(barX, barY, barW, barH);

      const progressGrad = ctx.createLinearGradient(barX, barY, barX + barW * (this.scanProgress / 100), barY);
      progressGrad.addColorStop(0, '#6c5ce7');
      progressGrad.addColorStop(1, '#7c6cf7');
      ctx.fillStyle = progressGrad;
      ctx.fillRect(barX, barY, barW * (this.scanProgress / 100), barH);

      // Glow
      ctx.shadowColor = '#6c5ce7';
      ctx.shadowBlur = 8;
      ctx.fillRect(barX, barY, barW * (this.scanProgress / 100), barH);
      ctx.shadowBlur = 0;
    }
  }

  drawMinecraftBlock(ctx, cx, cy, size, rotation) {
    const sin = Math.sin(rotation);
    const cos = Math.cos(rotation);

    // Isometric projection of a cube
    const s = size * 0.5;

    // Project 3D point to 2D (isometric)
    function project(x, y, z) {
      // Rotate around Y axis
      const rx = x * cos - z * sin;
      const rz = x * sin + z * cos;
      // Isometric projection
      const px = cx + (rx - rz) * 0.866;
      const py = cy + (rx + rz) * 0.5 - y;
      return [px, py];
    }

    // Cube vertices
    const vertices = [
      [-s, -s, -s], [s, -s, -s], [s, -s, s], [-s, -s, s], // bottom
      [-s,  s, -s], [s,  s, -s], [s,  s, s], [-s,  s, s]   // top
    ];

    const projected = vertices.map(v => project(v[0], v[1], v[2]));

    // Determine which faces are visible
    // Top face (grass)
    const topColor = this.isScanning ? '#6c5ce7' : '#4CAF50';
    ctx.beginPath();
    ctx.moveTo(...projected[4]);
    ctx.lineTo(...projected[5]);
    ctx.lineTo(...projected[6]);
    ctx.lineTo(...projected[7]);
    ctx.closePath();
    ctx.fillStyle = topColor;
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,0,0,0.3)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Draw pixelated texture on top
    this.drawBlockTexture(ctx, projected[4], projected[5], projected[6], projected[7], topColor);

    // Right face (dirt/side)
    const rightColor = this.isScanning ? '#5a4dc7' : '#8B6914';
    ctx.beginPath();
    ctx.moveTo(...projected[5]);
    ctx.lineTo(...projected[1]);
    ctx.lineTo(...projected[2]);
    ctx.lineTo(...projected[6]);
    ctx.closePath();
    ctx.fillStyle = rightColor;
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,0,0,0.3)';
    ctx.stroke();

    // Left face (dirt/side darker)
    const leftColor = this.isScanning ? '#4a3db7' : '#6B4F12';
    ctx.beginPath();
    ctx.moveTo(...projected[7]);
    ctx.lineTo(...projected[6]);
    ctx.lineTo(...projected[2]);
    ctx.lineTo(...projected[3]);
    ctx.closePath();
    ctx.fillStyle = leftColor;
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,0,0,0.3)';
    ctx.stroke();

    // Glow effect when scanning
    if (this.isScanning) {
      ctx.save();
      ctx.shadowColor = '#6c5ce7';
      ctx.shadowBlur = 20 + Math.sin(Date.now() / 200) * 10;
      ctx.beginPath();
      ctx.moveTo(...projected[4]);
      ctx.lineTo(...projected[5]);
      ctx.lineTo(...projected[6]);
      ctx.lineTo(...projected[7]);
      ctx.closePath();
      ctx.strokeStyle = 'rgba(108, 92, 231, 0.5)';
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.restore();
    }

    // Status indicator
    if (this.status === 'DETECTED') {
      ctx.save();
      ctx.shadowColor = '#ff4757';
      ctx.shadowBlur = 30 + Math.sin(Date.now() / 150) * 15;
      ctx.beginPath();
      ctx.arc(cx, cy - size * 0.3, size * 0.8, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255, 71, 87, 0.3)';
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.restore();
    }
  }

  drawBlockTexture(ctx, p1, p2, p3, p4, baseColor) {
    // Simple pixelated texture overlay
    ctx.save();
    ctx.globalAlpha = 0.15;

    const steps = 4;
    for (let i = 0; i < steps; i++) {
      for (let j = 0; j < steps; j++) {
        if (Math.random() > 0.5) {
          const t = i / steps;
          const s = j / steps;
          const x = p1[0] + (p2[0] - p1[0]) * t + (p4[0] - p1[0]) * s;
          const y = p1[1] + (p2[1] - p1[1]) * t + (p4[1] - p1[1]) * s;
          const w = (p2[0] - p1[0]) / steps;
          const h = (p4[1] - p1[1]) / steps;

          ctx.fillStyle = Math.random() > 0.5 ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
          ctx.fillRect(x, y, Math.abs(w), Math.abs(h) || 3);
        }
      }
    }
    ctx.restore();
  }

  drawScanRing(ctx, cx, cy, radius, progress) {
    const startAngle = -Math.PI / 2;
    const endAngle = startAngle + (Math.PI * 2 * progress / 100);

    // Background ring
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(42, 42, 64, 0.3)';
    ctx.lineWidth = 3;
    ctx.stroke();

    // Progress ring
    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = '#6c5ce7';
    ctx.lineWidth = 3;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Glow dot at the end
    const dotX = cx + radius * Math.cos(endAngle);
    const dotY = cy + radius * Math.sin(endAngle);
    ctx.beginPath();
    ctx.arc(dotX, dotY, 5, 0, Math.PI * 2);
    ctx.fillStyle = '#7c6cf7';
    ctx.shadowColor = '#6c5ce7';
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  destroy() {
    this.stopAnimation();
  }
}

// ============================================================
// Threat Graph (2D Canvas bar chart)
// ============================================================

class ThreatGraph {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.data = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
  }

  update(detections) {
    this.data = { critical: 0, high: 0, medium: 0, low: 0 };

    if (Array.isArray(detections)) {
      for (const det of detections) {
        const sev = (det.severity || 'medium').toLowerCase();
        if (this.data[sev] !== undefined) {
          this.data[sev]++;
        }
      }
    } else if (typeof detections === 'object') {
      this.data = { ...this.data, ...detections };
    }

    this.render();
  }

  render() {
    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;

    ctx.clearRect(0, 0, w, h);

    // Background
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(0, 0, w, h);

    const categories = [
      { key: 'critical', label: 'Critical', color: '#ff4757' },
      { key: 'high', label: 'High', color: '#ffa502' },
      { key: 'medium', label: 'Medium', color: '#6c5ce7' },
      { key: 'low', label: 'Low', color: '#8888a0' }
    ];

    const maxVal = Math.max(1, ...Object.values(this.data));
    const barWidth = (w - 80) / categories.length;
    const maxBarHeight = h - 60;

    ctx.font = '12px Segoe UI';
    ctx.textAlign = 'center';

    categories.forEach((cat, i) => {
      const x = 40 + i * barWidth + barWidth * 0.15;
      const barW = barWidth * 0.7;
      const val = this.data[cat.key] || 0;
      const barH = (val / maxVal) * maxBarHeight;
      const y = h - 30 - barH;

      // Bar
      const grad = ctx.createLinearGradient(x, y, x, h - 30);
      grad.addColorStop(0, cat.color);
      grad.addColorStop(1, cat.color + '44');
      ctx.fillStyle = grad;
      ctx.fillRect(x, y, barW, barH);

      // Glow
      ctx.shadowColor = cat.color;
      ctx.shadowBlur = 6;
      ctx.fillRect(x, y, barW, 2);
      ctx.shadowBlur = 0;

      // Value
      ctx.fillStyle = '#e8e8f0';
      ctx.fillText(val.toString(), x + barW / 2, y - 8);

      // Label
      ctx.fillStyle = '#8888a0';
      ctx.fillText(cat.label, x + barW / 2, h - 12);
    });
  }
}

// ============================================================
// Logo Cube (mini rotating cube in sidebar)
// ============================================================

class LogoCube {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.rotation = 0;

    const animate = () => {
      this.rotation += 0.02;
      this.render();
      requestAnimationFrame(animate);
    };
    animate();
  }

  render() {
    const ctx = this.ctx;
    const s = 16;
    const cx = 16;
    const cy = 16;

    ctx.clearRect(0, 0, 32, 32);

    const sin = Math.sin(this.rotation);
    const cos = Math.cos(this.rotation);

    function proj(x, y, z) {
      const rx = x * cos - z * sin;
      const rz = x * sin + z * cos;
      return [cx + (rx - rz) * 0.6, cy + (rx + rz) * 0.3 - y * 0.8];
    }

    const h = s * 0.5;
    const pts = [
      proj(-h, -h, -h), proj(h, -h, -h), proj(h, -h, h), proj(-h, -h, h),
      proj(-h, h, -h), proj(h, h, -h), proj(h, h, h), proj(-h, h, h)
    ];

    // Top
    ctx.beginPath();
    ctx.moveTo(...pts[4]); ctx.lineTo(...pts[5]); ctx.lineTo(...pts[6]); ctx.lineTo(...pts[7]);
    ctx.closePath();
    ctx.fillStyle = '#6c5ce7';
    ctx.fill();

    // Right
    ctx.beginPath();
    ctx.moveTo(...pts[5]); ctx.lineTo(...pts[1]); ctx.lineTo(...pts[2]); ctx.lineTo(...pts[6]);
    ctx.closePath();
    ctx.fillStyle = '#5a4dc7';
    ctx.fill();

    // Left
    ctx.beginPath();
    ctx.moveTo(...pts[7]); ctx.lineTo(...pts[6]); ctx.lineTo(...pts[2]); ctx.lineTo(...pts[3]);
    ctx.closePath();
    ctx.fillStyle = '#4a3db7';
    ctx.fill();
  }
}

// ============================================================
// Initialize on load
// ============================================================

let viz = null;
let threatGraph = null;
let logoCube = null;

document.addEventListener('DOMContentLoaded', () => {
  viz = new MinecraftViz('three-canvas');
  threatGraph = new ThreatGraph('threat-canvas');
  logoCube = new LogoCube('logo-cube');
});
