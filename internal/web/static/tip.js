// Themed tooltips. The templates keep plain title attributes and SVG <title>
// elements, so without JavaScript the browser's own tooltips still work. On the
// first hover or focus an element's title moves to data-tip (which stops the
// native tooltip) and one shared .tip box shows it instead. Elements swapped in
// by app.js's auto-refresh are picked up the same way.
(function () {
  "use strict";
  var SVG = "http://www.w3.org/2000/svg";
  var GAP = 10, EDGE = 8, DELAY = 300, WARM = 400;

  var box = null, anchor = null, pending = null, timer = 0, hiddenAt = 0;

  function tipBox() {
    if (box) return box;
    box = document.createElement("div");
    box.className = "tip";
    box.id = "tip";
    box.setAttribute("role", "tooltip");
    document.body.appendChild(box);
    return box;
  }

  // adopt moves a title attribute or a direct SVG <title> child to data-tip.
  function adopt(el) {
    if (el.hasAttribute("data-tip")) return true;
    var text = "";
    if (el.hasAttribute("title")) {
      text = el.getAttribute("title");
      el.removeAttribute("title");
    } else if (el.namespaceURI === SVG && el.localName !== "svg") {
      for (var c = el.firstElementChild; c; c = c.nextElementSibling) {
        if (c.localName === "title" && c.namespaceURI === SVG) {
          text = c.textContent;
          el.removeChild(c);
          break;
        }
      }
    }
    text = (text || "").trim();
    if (!text) return false;
    el.setAttribute("data-tip", text);
    // The title was the accessible name of icon-only elements; keep it.
    if (!el.hasAttribute("aria-label") && !(el.textContent || "").trim()) {
      el.setAttribute("aria-label", text);
    }
    return true;
  }

  function find(t) {
    for (var el = t; el && el.nodeType === 1 && el !== document.body; el = el.parentNode) {
      if (el.id === "tip") return null;
      if (adopt(el)) return el;
    }
    return null;
  }

  // place puts the box above the point or rect, below when there is no room.
  function place(r) {
    var b = tipBox();
    var vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
    var w = b.offsetWidth, h = b.offsetHeight;
    var cx = r.left + r.width / 2;
    var x = Math.max(EDGE, Math.min(cx - w / 2, vw - w - EDGE));
    var below = r.top - h - GAP < EDGE && r.bottom + h + GAP <= vh - EDGE;
    var y = below ? r.bottom + GAP : r.top - h - GAP;
    b.classList.toggle("tip-below", below);
    b.style.left = Math.round(x) + "px";
    b.style.top = Math.round(Math.max(EDGE, y)) + "px";
    b.style.setProperty("--tip-arrow", Math.round(Math.max(12, Math.min(cx - x, w - 12))) + "px");
  }

  // target is where the box points: the dot of a chart column, the pointer on
  // other SVG shapes (a map link's box can be the whole map), else the element.
  function target(el, ev) {
    if (el.classList && el.classList.contains("chart-hit")) {
      var dot = el.querySelector("circle");
      if (dot) return dot.getBoundingClientRect();
    }
    if (ev && ev.clientX !== undefined && el.namespaceURI === SVG && el.localName !== "svg") {
      return { left: ev.clientX, right: ev.clientX, top: ev.clientY - 4, bottom: ev.clientY + 16, width: 0, height: 0 };
    }
    return el.getBoundingClientRect();
  }

  function show(el, ev) {
    var b = tipBox();
    anchor = el;
    b.textContent = el.getAttribute("data-tip");
    b.classList.remove("tip-on");
    place(target(el, ev));
    el.setAttribute("aria-describedby", "tip");
    // Next frame, so the fade starts from the placed position.
    requestAnimationFrame(function () { if (anchor === el) b.classList.add("tip-on"); });
  }

  function hide() {
    clearTimeout(timer);
    pending = null;
    if (!anchor) return;
    if (anchor.getAttribute("aria-describedby") === "tip") anchor.removeAttribute("aria-describedby");
    anchor = null;
    hiddenAt = Date.now();
    if (box) box.classList.remove("tip-on");
  }

  function enter(el, ev) {
    if (el === anchor || el === pending) return;
    clearTimeout(timer);
    if (anchor) hide();
    // Moving from one tooltip to the next shows at once.
    if (Date.now() - hiddenAt < WARM) { show(el, ev); return; }
    var x = ev && ev.clientX, y = ev && ev.clientY;
    pending = el;
    timer = setTimeout(function () {
      pending = null;
      show(el, x === undefined ? null : { clientX: x, clientY: y });
    }, DELAY);
  }

  document.addEventListener("pointerdown", hide, true);

  document.addEventListener("pointerover", function (e) {
    if (e.pointerType === "touch") return;
    var el = find(e.target);
    if (el) enter(el, e);
    else hide();
  });

  // Follow the pointer along SVG shapes such as the map's links.
  document.addEventListener("pointermove", function (e) {
    if (!anchor || e.pointerType === "touch") return;
    if (anchor.namespaceURI === SVG && !anchor.classList.contains("chart-hit") && anchor.contains(e.target)) {
      place(target(anchor, e));
    }
  });

  document.addEventListener("pointerout", function (e) {
    var el = anchor || pending;
    if (el && !el.contains(e.relatedTarget)) hide();
  });

  // Keyboard focus only: a click or tap also focuses a link.
  function keyboardFocus(el) {
    try { return el.matches(":focus-visible"); } catch (err) { return false; }
  }

  document.addEventListener("focusin", function (e) {
    if (!keyboardFocus(e.target)) return;
    var el = find(e.target);
    if (el) { clearTimeout(timer); hide(); show(el, null); }
  });
  document.addEventListener("focusout", hide);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") hide(); });
  window.addEventListener("scroll", hide, true);
  window.addEventListener("resize", hide);
  // app.js swapped <main>; the anchor may be gone.
  document.addEventListener("mpinfra:swap", hide);
})();
