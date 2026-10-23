// Quiet auto-refresh: every 60 s, fetch this page in the background and swap
// in the new <main> instead of reloading the whole document. Open <details>
// stay open, the scroll position stays put, and nothing changes when the data
// has not. Without JavaScript the <noscript> meta refresh does the job.
(function () {
  "use strict";
  var every = 60000;
  var timer = 0;

  function main(doc) { return doc.querySelector("main.container"); }

  // Keys for the <details> that are open, so they stay open after the swap.
  function openDetails(root) {
    var keys = {};
    var all = root.querySelectorAll("details");
    for (var i = 0; i < all.length; i++) {
      if (all[i].open) keys[key(all[i], i)] = true;
    }
    return keys;
  }
  function key(d, i) { return (d.id || d.className || "") + "#" + i; }

  // Do not pull the page out from under someone using a form control.
  function busy(root) {
    var a = document.activeElement;
    return a && a !== document.body && root.contains(a) &&
      /^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(a.tagName);
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(tick, every);
  }

  function tick() {
    if (document.hidden) return; // resumes on visibilitychange
    var cur = main(document);
    if (!cur || busy(cur)) { schedule(); return; }
    fetch(location.href, { credentials: "same-origin", cache: "no-store", redirect: "manual" })
      .then(function (r) {
        // A redirect or error (signed out, server restarting): let the
        // browser handle it the plain way on the next full load.
        if (r.type === "opaqueredirect" || r.status === 401 || r.status === 403) {
          location.reload();
          return null;
        }
        return r.ok ? r.text() : null;
      })
      .then(function (html) {
        if (!html) return;
        var doc = new DOMParser().parseFromString(html, "text/html");
        var next = main(doc);
        if (!next) return;
        cur = main(document);
        if (!cur || busy(cur)) return;
        if (next.innerHTML !== cur.innerHTML) {
          var open = openDetails(cur);
          var x = window.scrollX, y = window.scrollY;
          cur.innerHTML = next.innerHTML;
          var all = cur.querySelectorAll("details");
          for (var i = 0; i < all.length; i++) {
            if (open[key(all[i], i)]) all[i].open = true;
          }
          window.scrollTo(x, y);
        }
        if (doc.title) document.title = doc.title;
      })
      .catch(function () {})
      .then(schedule);
  }

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) tick();
  });
  schedule();
})();
