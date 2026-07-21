// Theme: follow the OS until the reader says otherwise, then remember the choice.
// A tiny bootstrap in each page's <head> applies the saved theme before first
// paint; this file only wires the toggle. Stamping data-theme on :root is also
// how an embedding viewer drives the page, so the CSS overrides it in both
// directions rather than only toggling to dark.
(function () {
  var root = document.documentElement;
  function current() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  var btn = document.getElementById("themer");
  if (!btn) return;
  function describe() {
    btn.setAttribute("aria-label", "Switch to the " + (current() === "dark" ? "light" : "dark") + " theme");
  }
  describe();
  btn.addEventListener("click", function () {
    root.setAttribute("data-theme", current() === "dark" ? "light" : "dark");
    try { localStorage.setItem("akson-theme", root.getAttribute("data-theme")); } catch (e) { /* private mode */ }
    describe();
  });
})();

// Copy buttons — hidden when the Clipboard API is unavailable; comments are
// part of what you'd paste anyway.
document.querySelectorAll(".copy").forEach(function (btn) {
  if (!(navigator.clipboard && navigator.clipboard.writeText)) {
    btn.hidden = true;
    return;
  }
  var original = btn.textContent;
  var timer = null;
  function flash(text) {
    btn.textContent = text;
    btn.classList.toggle("done", text === "Copied");
    clearTimeout(timer);
    timer = setTimeout(function () {
      btn.textContent = original;
      btn.classList.remove("done");
    }, 1400);
  }
  btn.addEventListener("click", function () {
    var block = btn.closest(".cmd, .file");
    var pre = block && block.querySelector("pre");
    if (!pre) return;
    navigator.clipboard.writeText(pre.textContent).then(
      function () { flash("Copied"); },
      function () { flash("Blocked"); }
    );
  });
});

// Highlight the section being read: the last h2 that has crossed the reading
// line stays active until the next one does, so long sections keep their mark.
// Only hash links take part; the cross-page links keep their static .here state.
(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll('#nav a[href^="#"]'));
  var byId = {};
  links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
  var headings = Array.prototype.slice.call(document.querySelectorAll("main h2[id]"));
  if (!links.length || !headings.length) return;

  var queued = false;
  function sync() {
    queued = false;
    var id = null;
    var cutoff = Math.min(window.innerHeight * 0.3, 160);
    headings.forEach(function (h) {
      if (h.getBoundingClientRect().top <= cutoff) id = h.id;
    });
    if (window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2) {
      id = headings[headings.length - 1].id;
    }
    links.forEach(function (a) {
      var on = a === byId[id];
      a.classList.toggle("on", on);
      if (on) a.setAttribute("aria-current", "location");
      else a.removeAttribute("aria-current");
    });
  }
  function queue() {
    if (!queued) {
      queued = true;
      requestAnimationFrame(sync);
    }
  }
  sync();
  addEventListener("scroll", queue, { passive: true });
  addEventListener("resize", queue);
})();
