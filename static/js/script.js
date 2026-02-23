const arr = []; // particles
const c = document.querySelector("canvas");
const ctx = c.getContext("2d");

// performance-friendly size
const cw = (c.width = 1400);
const ch = (c.height = 1400);

// ✅ No text-mask canvas at all (Option B)
let ctx2 = null;

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
      y: ch,
      x: '+=' + 'random(-400, 400, 1)',
      x2: 500
    })
    .seek(ff ? Math.random() * 99 : 0)
    .timeScale(arr[i].s / 37);
}

ctx.fillStyle = "#fff";
gsap.ticker.add(render);

function render() {
  ctx.clearRect(0, 0, cw, ch);

  arr.forEach((p) => {
    // ctx2 always null in Option B, so no heavy sampling

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
