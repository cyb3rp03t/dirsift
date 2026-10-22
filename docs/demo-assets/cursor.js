/* A pointer for the recording: headless Chromium draws none. It follows the
   real mouse events Playwright sends, and never takes a click. */
(() => {
  const add = () => {
    if (document.getElementById("demo-cursor")) return;
    const c = document.createElement("div");
    c.id = "demo-cursor";
    c.innerHTML =
      '<svg width="22" height="22" viewBox="0 0 24 24"><path d="M4 2l15 11-7 1 4 8-3 1-4-8-5 5z" ' +
      'fill="#e9eefa" stroke="#070b12" stroke-width="1.5" stroke-linejoin="round"/></svg>';
    Object.assign(c.style, {
      position: "fixed", left: "-40px", top: "-40px", zIndex: 2147483647,
      pointerEvents: "none", width: "22px", height: "22px",
    });
    document.documentElement.appendChild(c);
    document.addEventListener("mousemove", (e) => {
      c.style.left = e.clientX - 3 + "px";
      c.style.top = e.clientY - 2 + "px";
    }, true);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", add);
  else add();
})();
