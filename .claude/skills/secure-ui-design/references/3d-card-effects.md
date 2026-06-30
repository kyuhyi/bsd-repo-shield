# 3D Card Effects — 구현 가이드

목차: 1) perspective tilt 2) 홀로그래픽 sheen 3) 호버 모션/글로우 4) 성능·접근성 5) React 패턴

---

## 1. perspective tilt

부모 그리드에 원근, 카드에 3D 회전.

```css
.launcher-grid { perspective: 1200px; }
.card {
  transform-style: preserve-3d;
  transition: transform .22s cubic-bezier(.2,.8,.2,1), box-shadow .22s;
  transform: rotateX(var(--rx,0deg)) rotateY(var(--ry,0deg)) translateZ(0);
}
```

마우스 위치 → 회전각(JS). 카드 중심 기준 -1~1 정규화 후 최대 ±10deg 정도.

```js
function onMove(e, el){
  const r = el.getBoundingClientRect();
  const px = (e.clientX - r.left)/r.width - .5;   // -0.5~0.5
  const py = (e.clientY - r.top)/r.height - .5;
  el.style.setProperty('--ry', `${px*16}deg`);
  el.style.setProperty('--rx', `${-py*16}deg`);
  el.style.setProperty('--mx', `${(px+.5)*100}%`); // sheen 위치
  el.style.setProperty('--my', `${(py+.5)*100}%`);
}
function onLeave(el){ el.style.setProperty('--rx','0deg'); el.style.setProperty('--ry','0deg'); }
```

`requestAnimationFrame`으로 throttle해 mousemove 폭주를 막는다.

---

## 2. 홀로그래픽 sheen (빛반사)

마우스 추종 하이라이트 + 무지개 오버레이. 카드 위 의사요소 2겹.

```css
.card::before {              /* 마우스 추종 광택 */
  content:''; position:absolute; inset:0; border-radius:inherit;
  background: radial-gradient(circle at var(--mx,50%) var(--my,50%),
              rgba(255,255,255,.35), transparent 40%);
  opacity:0; transition:opacity .2s; mix-blend-mode:soft-light; pointer-events:none;
}
.card:hover::before { opacity:1; }
.card::after {               /* 홀로그래픽 무지개 */
  content:''; position:absolute; inset:0; border-radius:inherit; pointer-events:none;
  background: linear-gradient(110deg, transparent 30%,
     hsla(var(--hue,210),90%,70%,.18), hsla(calc(var(--hue,210)+60),90%,70%,.18), transparent 70%);
  opacity:0; transition:opacity .25s;
}
.card:hover::after { opacity:1; }
```

각 카드의 `--hue`는 사이트 데이터의 `hue`로 설정해 브랜드별 색감.

---

## 3. 호버 모션 / 글로우

```css
.card { box-shadow: 0 6px 18px rgba(0,0,0,.4); }
.card:hover {
  transform: rotateX(var(--rx)) rotateY(var(--ry)) translateZ(30px) scale(1.04);
  box-shadow: 0 24px 60px rgba(0,0,0,.55),
              0 0 0 1px hsla(var(--hue,210),90%,65%,.5),
              0 0 40px hsla(var(--hue,210),90%,60%,.25);
}
.card__title, .card__icon { transform: translateZ(40px); } /* 패럴랙스 깊이 */
```

내부 요소에 `translateZ`를 다르게 줘 떠 있는 깊이감.

---

## 4. 성능·접근성

- `transform`/`opacity`만 애니메이트(리플로우 0). `will-change: transform`은 카드에만.
- `@media (prefers-reduced-motion: reduce)` → tilt/sheen 비활성, 단순 그림자 호버만.
- 모바일(`hover:none`) → tilt 끄고 정적 그라데이션 유지. 터치는 즉시 링크 이동.
- 카드는 실제 `<a href>` 로 만들어 키보드 포커스·새 탭·우클릭 복사 모두 동작(`rel="noopener noreferrer"`).

---

## 5. React 패턴

```jsx
function LauncherCard({site}){
  const ref = useRef(null);
  const raf = useRef(0);
  const move = e => {
    cancelAnimationFrame(raf.current);
    raf.current = requestAnimationFrame(()=>onMove(e, ref.current));
  };
  return (
    <a ref={ref} className="card" style={{'--hue':site.hue}}
       href={site.url} target="_blank" rel="noopener noreferrer"
       onMouseMove={move} onMouseLeave={()=>onLeave(ref.current)}>
      <span className="card__icon">↗</span>
      <h3 className="card__title">{site.name}</h3>
      <p className="card__desc">{site.desc}</p>
    </a>
  );
}
```

그리드는 `display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:1.5rem;`.
