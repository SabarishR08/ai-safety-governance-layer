import React, { useEffect, useRef } from 'react';
import type { InterceptEvent } from '../App';

export default function LiveFlow({ events }: { events: InterceptEvent[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let particles: any[] = [];

    const resize = () => {
      const parent = canvas.parentElement;
      if (parent) {
        canvas.width = parent.clientWidth - 32; // padding
        canvas.height = parent.clientHeight - 60; // title
      }
    };
    resize();
    window.addEventListener('resize', resize);

    const membraneX = canvas.width / 2;

    const spawnParticles = (event: InterceptEvent) => {
      // Create a burst of particles for each event based on detections
      const isBlocked = event.audit_logs.some(l => l.action === 'BLOCK');
      const isMasked = event.audit_logs.some(l => l.action === 'MASK');
      
      const numParticles = Math.min(10 + Math.floor(event.original_length / 10), 30);
      
      for (let i = 0; i < numParticles; i++) {
        // Find if this specific particle should be a 'threat'
        const isThreat = i < (event.detections.length * 3);
        
        particles.push({
          x: 0,
          y: Math.random() * canvas.height,
          vx: Math.random() * 2 + 2, // speed
          color: isThreat ? (isBlocked ? '#FF3B5C' : '#FFB020') : '#00E5FF',
          size: isThreat ? 4 : 2,
          isThreat,
          isBlocked,
          stopped: false,
          life: 1000
        });
      }
    };

    if (events.length > 0) {
      // Spawn for the latest event
      spawnParticles(events[events.length - 1]);
    }

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw Membrane
      ctx.beginPath();
      ctx.moveTo(membraneX, 0);
      ctx.lineTo(membraneX, canvas.height);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
      ctx.lineWidth = 4;
      ctx.stroke();

      // Draw active zone glow
      ctx.shadowBlur = 20;
      ctx.shadowColor = '#00E5FF';
      ctx.beginPath();
      ctx.moveTo(membraneX, 0);
      ctx.lineTo(membraneX, canvas.height);
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.2)';
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Update and draw particles
      particles = particles.filter(p => p.x < canvas.width && p.life > 0);
      
      particles.forEach(p => {
        if (!p.stopped) {
          p.x += p.vx;
        } else {
          p.life -= 10;
        }

        // Membrane collision logic
        if (p.x >= membraneX - 5 && p.x <= membraneX + 5) {
          if (p.isThreat) {
            if (p.isBlocked) {
              p.stopped = true;
              p.x = membraneX - 5;
              // pulse red
              ctx.shadowBlur = 10;
              ctx.shadowColor = '#FF3B5C';
            } else {
              // Masked - slow down briefly then pass
              p.x += p.vx * 0.1;
              ctx.shadowBlur = 5;
              ctx.shadowColor = '#FFB020';
            }
          }
        } else {
          ctx.shadowBlur = p.isThreat ? 5 : 2;
          ctx.shadowColor = p.color;
        }

        ctx.fillStyle = p.color;
        
        if (p.isThreat && p.x > membraneX && !p.isBlocked) {
          // Changed shape after passing (masked)
          ctx.fillRect(p.x, p.y - p.size, p.size * 2, p.size * 2);
        } else {
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fill();
        }
        
        ctx.shadowBlur = 0;
      });

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [events]); // Re-run effect or push to particles on events

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <canvas ref={canvasRef} style={{ display: 'block' }} />
    </div>
  );
}
