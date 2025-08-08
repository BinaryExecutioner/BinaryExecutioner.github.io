(function(){
  const canvas = document.getElementById('matrixCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const letters = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%^&*{}[]<>()/\\'.split('');
  const fontSize = 14;
  let columns = 0, drops = [];
  function resize(){
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.floor(canvas.width / fontSize);
    drops = new Array(columns).fill(1 + Math.random()*40);
  }
  window.addEventListener('resize', resize);
  function draw(){
    if (getComputedStyle(canvas).display === 'none') return; // skip when hidden
    ctx.fillStyle = 'rgba(0,0,0,0.08)';
    ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle = '#0F0';
    ctx.font = fontSize + 'px Courier New';
    for (let i=0;i<drops.length;i++){
      const txt = letters[Math.floor(Math.random()*letters.length)];
      ctx.fillText(txt, i*fontSize, drops[i]*fontSize);
      if (drops[i]*fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  resize();
  setInterval(draw, 33);
})();
