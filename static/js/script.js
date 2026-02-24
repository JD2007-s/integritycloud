const arr = []; // particles
const c = document.querySelector("canvas");
const ctx = c.getContext("2d");

// 1. Make width and height dynamic variables instead of hardcoded numbers
let cw, ch;

// 2. Create a function to resize the canvas to perfectly fit the screen
function resizeCanvas() {
  cw = c.width = window.innerWidth;
  ch = c.height = window.innerHeight;
}

// 3. Run it immediately, and listen for screen resizes
resizeCanvas();
window.addEventListener("resize", resizeCanvas);

// start flakes (reduced)
for (let i = 0; i < 300; i++) makeFlake(i, true);

function makeFlake(i, ff) {
  arr.push({ i: i, x: 0, x2: 0, y: 0, s: 0 });
  arr[i].t = gsap.timeline({ repeat: -1, repeatRefresh: true })
    .fromTo(arr[i], {
      x: () => -400 + (cw + 800) * Math.random(),
      y: -15,
      s: () => 'random(1.8, 7, .1)',
      x2: -500
    }, {
      ease: 'none',
      // 4. Change 'y: ch' to 'y: () => ch + 15' so it recalculates the bottom of the screen
      y: () => ch + 15, 
      x: '+=' + 'random(-400, 400, 1)',
      x2: 500
    })
    .seek(ff ? Math.random() * 99 : 0)
    .timeScale(arr[i].s / 37);
}

gsap.ticker.add(render);

function render() {
  ctx.clearRect(0, 0, cw, ch);
  
  // Ensure the snow is always white
  ctx.fillStyle = "#fff";

  arr.forEach((p) => {
    ctx.beginPath();
    ctx.arc(
      p.x + p.x2,
      p.y,
      p.s * gsap.utils.interpolate(1, .2, p.y / ch),
      0,
      Math.PI * 2
    );
    ctx.fill();
  });
}