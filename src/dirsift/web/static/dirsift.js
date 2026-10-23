/* DirSift console behaviour.

   Everything here is progressive: the pages work without it, this only makes
   reading faster. No network calls to anywhere but this console live in this
   file. The scan itself is the only thing that talks to a target, and that
   happens on the server when the button is pressed. */

(function () {
  "use strict";

  function onClick(selector, handler) {
    document.addEventListener("click", function (event) {
      var hit = event.target.closest(selector);
      if (hit) {
        handler(hit, event);
      }
    });
  }

  function all(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  /* One shared live region in the corner. A short line fades in, is announced
     once, and clears itself. Without this script the region stays empty and
     invisible, so nothing depends on it. */
  function toast(text, kind) {
    var region = document.getElementById("toast-region");
    if (!region) {
      return;
    }
    var node = document.createElement("div");
    node.className = kind === "alert" ? "toast is-alert" : "toast";
    node.textContent = text;
    region.appendChild(node);
    window.requestAnimationFrame(function () {
      node.classList.add("is-in");
    });
    window.setTimeout(function () {
      node.classList.remove("is-in");
      window.setTimeout(function () {
        if (node.parentNode) {
          node.parentNode.removeChild(node);
        }
      }, 200);
    }, 2000);
  }

  function writeClipboard(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      var field = document.createElement("textarea");
      field.value = value;
      document.body.appendChild(field);
      field.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (error) {
        reject(error);
      }
      document.body.removeChild(field);
    });
  }

  /* Copy a hash or an indicator without selecting it by hand. */
  onClick("[data-copy]", function (button) {
    var say = function (text) {
      var previous = button.getAttribute("data-label") || button.textContent;
      button.setAttribute("data-label", previous);
      button.textContent = text;
      window.setTimeout(function () {
        button.textContent = button.getAttribute("data-label");
      }, 1200);
      toast(text, text === "blocked" ? "alert" : null);
    };
    writeClipboard(button.getAttribute("data-copy")).then(
      function () { say("copied"); },
      function () { say("blocked"); }
    );
  });

  /* Copy a detection file with its live values. The page only ever shows the
     defanged preview; the live text is fetched from this console's download
     route at the moment of the copy and goes straight to the clipboard. */
  onClick("[data-copy-live]", function (button) {
    fetch(button.getAttribute("data-copy-live"), { credentials: "same-origin" })
      .then(function (reply) {
        if (!reply.ok) {
          throw new Error(String(reply.status));
        }
        return reply.text();
      })
      .then(writeClipboard)
      .then(
        function () { toast("Copied, with live values"); },
        function () { toast("The copy was blocked", "alert"); }
      );
  });

  /* Preview tabs: contents, hex, links. */
  onClick(".tab", function (tab) {
    var group = tab.closest(".preview");
    if (!group) {
      return;
    }
    var wanted = tab.getAttribute("aria-controls");
    all(".tab", group).forEach(function (other) {
      other.setAttribute("aria-selected", String(other === tab));
    });
    all(".tab-panel", group).forEach(function (panel) {
      panel.hidden = panel.id !== wanted;
    });
  });

  /* Long lines: wrap them or keep them honest. */
  onClick("[data-wrap]", function (button) {
    var pre = document.getElementById(button.getAttribute("data-wrap"));
    if (!pre) {
      return;
    }
    var wrapped = pre.classList.toggle("is-wrapped");
    button.setAttribute("aria-pressed", String(wrapped));
  });

  /* Find inside the open file: marks the lines that match and counts them.
     The contents carry markup now (line numbers, indicator marks), so the search
     highlights whole lines rather than rewriting the text. */
  document.addEventListener("input", function (event) {
    var input = event.target.closest("[data-find]");
    if (!input) {
      return;
    }
    var pre = document.getElementById(input.getAttribute("data-find"));
    var report = document.getElementById(input.getAttribute("data-find-count"));
    if (!pre) {
      return;
    }
    var needle = input.value.toLowerCase();
    var hits = 0;
    var first = null;
    all(".line", pre).forEach(function (line) {
      var match = needle !== "" && line.textContent.toLowerCase().indexOf(needle) !== -1;
      line.classList.toggle("is-hit", match);
      if (match) {
        hits += 1;
        if (!first) {
          first = line;
        }
      }
    });
    if (report) {
      if (needle === "") {
        report.textContent = "";
      } else if (hits === 1) {
        report.textContent = "1 line";
      } else {
        report.textContent = String(hits) + " lines";
      }
    }
    if (first) {
      first.scrollIntoView({ block: "nearest" });
    }
  });

  /* Walk the listing from the keyboard: j and k, or the arrow keys. The keys
     belong to the page until focus is inside the listing rows: anywhere else
     the arrows scroll, as they should. Enter on a row's own controls does what
     they say; Enter anywhere else on a row opens its file. */
  document.addEventListener("keydown", function (event) {
    if (event.ctrlKey || event.altKey || event.metaKey || event.shiftKey) {
      return;
    }
    var body = event.target.closest && event.target.closest("[data-listing-rows]");
    if (!body) {
      return;
    }
    var row = event.target.closest("[data-row]");
    var own = row && row.querySelector("[data-file-url]");
    if (!own) {
      return;
    }
    if (event.key === "Enter" && event.target !== own && !event.target.closest("a, button")) {
      event.preventDefault();
      own.click();
      return;
    }
    var down = event.key === "j" || event.key === "ArrowDown";
    var up = event.key === "k" || event.key === "ArrowUp";
    if (!down && !up) {
      return;
    }
    /* Files inside a folded group are skipped: the walk follows what is shown. */
    var files = all("[data-row] [data-file-url]", body).filter(function (link) {
      return link.offsetParent !== null;
    });
    var next = files.indexOf(own) + (down ? 1 : -1);
    if (next < 0 || next >= files.length) {
      return;
    }
    event.preventDefault();
    files[next].focus();
  });

  /* An inventory row folds its details away; the chevron, or a click on the
     row's empty space, opens them. */
  function toggleRow(row) {
    var open = row.classList.toggle("is-open");
    var button = row.querySelector(".row-toggle");
    if (button) {
      button.setAttribute("aria-expanded", String(open));
    }
  }

  onClick(".row-toggle", function (button) {
    toggleRow(button.closest("[data-row]"));
  });

  onClick("[data-row] > .rh", function (head, event) {
    if (event.target.closest("a, button, input, label")) {
      return;
    }
    toggleRow(head.closest("[data-row]"));
  });

  /* "Open preview" inside a row's details is a plain link to ?file= for a page
     without the script. With it, the row's own file link does the opening, so
     there is one way a file opens. */
  onClick("[data-opens]", function (link, event) {
    var url = link.getAttribute("data-opens");
    var own = fileLinks().filter(function (other) {
      return other.getAttribute("data-file-url") === url;
    })[0];
    if (own) {
      event.preventDefault();
      own.click();
    }
  });

  /* Keep the open file in the address bar so a preview can be shared or reloaded.
     The vendored htmx is 4.x, which names the event htmx:after:swap and puts the
     element that asked on detail.ctx; htmx:afterOnLoad is the 2.x name. */
  function swapSource(event) {
    var detail = event.detail || {};
    return (detail.ctx && detail.ctx.sourceElement) || detail.elt || null;
  }

  function onSwap(handler) {
    var run = function (event) {
      handler(swapSource(event), event);
    };
    document.body.addEventListener("htmx:after:swap", run);
    document.body.addEventListener("htmx:afterOnLoad", run);
  }

  /* the case file: section menu, old links, sticky offset */

  var top = document.querySelector(".app-top");
  function measureTop() {
    if (top) {
      document.documentElement.style.setProperty("--top-h", top.offsetHeight + "px");
    }
  }
  measureTop();
  window.addEventListener("resize", measureTop);

  var spy = document.querySelector("[data-spy]");
  var spyLinks = spy ? all("[data-spy-link]", spy) : [];

  function markSection(id) {
    var current = null;
    spyLinks.forEach(function (link) {
      var on = link.getAttribute("href") === "#" + id;
      if (on) {
        link.setAttribute("aria-current", "location");
        current = link;
      } else {
        link.removeAttribute("aria-current");
      }
    });
    /* Keep the lit part in view inside the pill on a narrow screen, without
       scrolling the page itself. While a keyboard user is on the menu the
       pill stays where focus put it, or the focused part slides out of view. */
    var focusOnMenu = spy.contains(document.activeElement);
    if (current && !focusOnMenu && spy.scrollWidth > spy.clientWidth) {
      var left = current.offsetLeft - (spy.clientWidth - current.offsetWidth) / 2;
      spy.scrollLeft = Math.max(0, left);
    }
  }

  /* The lit part is the last one whose top has passed under the sticky bar.
     A part picked from the menu stays lit until the reader scrolls on their
     own, so a short part near the end of the page still lights when asked. */
  if (spy) {
    var sections = spyLinks.map(function (link) {
      return document.getElementById(link.getAttribute("href").slice(1));
    }).filter(Boolean);
    var chosenPart = null;
    var queued = false;
    var settle = function () {
      queued = false;
      if (chosenPart) {
        markSection(chosenPart);
        return;
      }
      var line = ((top && top.offsetHeight) || 0) + 24;
      var lit = sections[0];
      sections.forEach(function (section) {
        if (section.getBoundingClientRect().top <= line) {
          lit = section;
        }
      });
      if (lit) {
        markSection(lit.id);
      }
    };
    window.addEventListener("scroll", function () {
      if (!queued) {
        queued = true;
        window.requestAnimationFrame(settle);
      }
    }, { passive: true });
    ["wheel", "touchstart", "keydown"].forEach(function (name) {
      window.addEventListener(name, function () {
        chosenPart = null;
      }, { passive: true });
    });
    spyLinks.forEach(function (link) {
      link.addEventListener("click", function () {
        chosenPart = link.getAttribute("href").slice(1);
        markSection(chosenPart);
      });
      /* A browser leaves a half shown part where it is when Tab reaches it,
         so the pill slides until the whole part is inside it. */
      link.addEventListener("focus", function () {
        var box = spy.getBoundingClientRect();
        var part = link.getBoundingClientRect();
        if (part.left < box.left) {
          spy.scrollLeft -= box.left - part.left;
        } else if (part.right > box.right) {
          spy.scrollLeft += part.right - box.right;
        }
      });
    });
    settle();
  }

  /* A link made when the run page had tabs (?tab=notes) lands on that part.
     The server marks the part it recognised; the address bar is rewritten to
     the anchor so the link reads the way the page now works. */
  var landing = document.querySelector("[data-land]");
  var landOn = null;
  if (landing) {
    landOn = document.getElementById(landing.getAttribute("data-land"));
    if (landOn) {
      var moved = new URL(window.location.href);
      moved.searchParams.delete("tab");
      moved.hash = landOn.id;
      window.history.replaceState(window.history.state, "", moved);
    }
  } else if (window.location.hash.length > 1 && !new URL(window.location.href).searchParams.get("file")) {
    landOn = document.getElementById(window.location.hash.slice(1));
  }

  /* The rule pack loads after the page, above the run settings, and pushes
     what is below it down. Until the reader moves the page themselves, a
     landing is kept in place after each late swap. */
  function land() {
    if (landOn) {
      landOn.scrollIntoView({ block: "start" });
    }
  }
  if (landOn) {
    window.requestAnimationFrame(land);
    ["wheel", "touchstart", "keydown", "mousedown"].forEach(function (name) {
      window.addEventListener(name, function () {
        landOn = null;
      }, { passive: true, once: true });
    });
  }

  /* indicators: one kind at a time, and the first forty at once */

  var timeline = document.querySelector("[data-iocs]");
  var moreWrap = document.querySelector("[data-more-wrap]");
  var CAP = 40;
  if (timeline) {
    var count = timeline.children.length;
    if (count > CAP) {
      timeline.classList.add("is-capped");
    } else if (moreWrap) {
      moreWrap.hidden = true;
    }
  }

  onClick("[data-more]", function () {
    if (timeline) {
      timeline.classList.remove("is-capped");
    }
    if (moreWrap) {
      moreWrap.hidden = true;
    }
  });

  onClick("[data-facet]", function (button) {
    var kind = button.getAttribute("data-facet");
    all("[data-facet]").forEach(function (other) {
      other.setAttribute("aria-pressed", String(other === button));
    });
    if (!timeline) {
      return;
    }
    all(".tl", timeline).forEach(function (row) {
      row.hidden = kind !== "" && row.getAttribute("data-ioc-type") !== kind;
    });
    /* A single kind shows in full; all kinds go back to the first forty unless
       the reader already asked for everything. */
    if (kind !== "") {
      timeline.classList.remove("is-capped");
    } else if (moreWrap && !moreWrap.hidden) {
      timeline.classList.add("is-capped");
    }
  });

  /* detections: the YARA picker and the rule pack */

  var yaraForm = document.querySelector("[data-yara-form]");

  function picked() {
    return yaraForm ? all("input[name=pick]:checked", yaraForm) : [];
  }

  function sayPicked() {
    var label = yaraForm && yaraForm.querySelector("[data-pick-count]");
    if (!label) {
      return;
    }
    var n = picked().length;
    label.textContent = n === 0 ? "No file picked" : n === 1 ? "1 picked" : n + " picked";
  }
  sayPicked();

  if (yaraForm) {
    yaraForm.addEventListener("change", sayPicked);
  }

  function pickEvery(on) {
    if (!yaraForm) {
      return;
    }
    all("input[name=pick]", yaraForm).forEach(function (box) {
      box.checked = on;
    });
    sayPicked();
    yaraForm.dispatchEvent(new Event("change", { bubbles: true }));
  }

  onClick("[data-pick-all]", function () {
    pickEvery(true);
  });

  onClick("[data-pick-none]", function () {
    pickEvery(false);
  });

  /* The zip carries a YARA file only for the files picked above. */
  onClick("[data-zip]", function (link) {
    var url = new URL(link.getAttribute("href"), window.location.href);
    url.searchParams.delete("pick");
    picked().forEach(function (box) {
      url.searchParams.append("pick", box.value);
    });
    link.setAttribute("href", url.pathname + url.search);
  });

  /* the preview dialog */

  /* A file opens as a dialog over the case file, at every width (full screen
     on a phone). Without the script there is no dialog: the preview is the
     last part of the page. The dialog takes one history entry when it opens,
     so the browser's back button closes it. */
  var sheet = document.querySelector("[data-sheet]");
  var scrim = document.querySelector("[data-sheet-scrim]");
  var sheetReturn = null;
  var sheetPushed = false;
  var sheetInert = [];

  function sheetIsOpen() {
    return Boolean(sheet && sheet.classList.contains("is-open"));
  }

  function sheetHeading() {
    var preview = document.getElementById("preview");
    return preview && preview.querySelector(".preview-name");
  }

  function fileLinks() {
    return all("[data-listing-rows] [data-row] [data-file-url]");
  }

  function shownFile() {
    var panel = document.querySelector("#preview .preview");
    return panel && panel.getAttribute("data-preview-file");
  }

  function selectedLink() {
    return document.querySelector("[data-listing-rows] .link-button.is-selected");
  }

  /* The bar over the dialog: the file's name, where it sits among the files,
     and the previous and next buttons, which follow the inventory order. */
  function paintBar() {
    if (!sheet) {
      return;
    }
    var links = fileLinks();
    var url = shownFile();
    var at = -1;
    links.forEach(function (link, index) {
      if (at === -1 && link.getAttribute("data-file-url") === url) {
        at = index;
      }
    });
    var pos = sheet.querySelector("[data-sheet-pos]");
    var name = sheet.querySelector("[data-sheet-name]");
    var heading = sheetHeading();
    if (name) {
      name.textContent = heading ? heading.textContent.trim() : "";
    }
    if (pos) {
      pos.textContent = at === -1 ? "" : String(at + 1) + " / " + String(links.length);
    }
    all("[data-sheet-step]", sheet).forEach(function (button) {
      var to = at + Number(button.getAttribute("data-sheet-step"));
      button.disabled = at === -1 || to < 0 || to >= links.length;
    });
  }

  function stepFile(by) {
    var links = fileLinks();
    var url = shownFile();
    var at = -1;
    links.forEach(function (link, index) {
      if (at === -1 && link.getAttribute("data-file-url") === url) {
        at = index;
      }
    });
    var next = links[at + by];
    if (at === -1 || !next) {
      return;
    }
    next.click();
  }

  function setOutsideInert(on) {
    if (!on) {
      sheetInert.forEach(function (node) {
        node.inert = false;
      });
      sheetInert = [];
      return;
    }
    var keep = function (node) {
      return node === scrim || node.id === "toast-region" || node.tagName === "SCRIPT";
    };
    for (var node = sheet; node && node !== document.body; node = node.parentElement) {
      Array.prototype.forEach.call(node.parentElement.children, function (sibling) {
        if (sibling !== node && !sibling.inert && !keep(sibling)) {
          sibling.inert = true;
          sheetInert.push(sibling);
        }
      });
    }
  }

  function openSheet(returnTo) {
    if (!sheet) {
      return;
    }
    if (!sheetIsOpen()) {
      sheetReturn = returnTo || null;
      sheet.classList.add("is-open");
      sheet.setAttribute("role", "dialog");
      sheet.setAttribute("aria-modal", "true");
      sheet.setAttribute("aria-label", "File preview");
      document.documentElement.classList.add("sheet-open");
      if (scrim) {
        scrim.hidden = false;
      }
      setOutsideInert(true);
    }
    paintBar();
    var heading = sheetHeading();
    if (heading) {
      heading.focus();
    }
  }

  function finishClose() {
    if (!sheetIsOpen()) {
      return;
    }
    sheet.classList.remove("is-open");
    sheet.removeAttribute("role");
    sheet.removeAttribute("aria-modal");
    sheet.removeAttribute("aria-label");
    document.documentElement.classList.remove("sheet-open");
    if (scrim) {
      scrim.hidden = true;
    }
    setOutsideInert(false);
    sheetPushed = false;
    /* Back to the link that opened the dialog, unless j and k moved on to
       another file: then to that file's row, which is where the reader is. */
    var current = selectedLink();
    var opener = sheetReturn && document.contains(sheetReturn) ? sheetReturn : null;
    var back = opener && current && opener.getAttribute("data-file-url") !== current.getAttribute("data-file-url")
      ? current
      : opener || current;
    sheetReturn = null;
    if (back) {
      var group = back.closest("details");
      if (group && !group.open) {
        group.open = true;
      }
      back.focus();
    }
  }

  function closeSheet() {
    if (!sheetIsOpen()) {
      return;
    }
    if (sheetPushed) {
      window.history.back(); /* popstate below finishes the close */
      return;
    }
    var url = new URL(window.location.href);
    url.searchParams.delete("file");
    if (url.hash === "#preview-sheet") {
      url.hash = "";
    }
    window.history.replaceState({}, "", url);
    finishClose();
  }

  /* No page here pushes history through htmx, so a restore can only come from
     a step the sheet took. The page is already right; do not refetch it. */
  document.addEventListener("htmx:before:history:restore", function (event) {
    event.preventDefault();
  });

  window.addEventListener("popstate", function () {
    var hasFile = new URL(window.location.href).searchParams.get("file");
    if (sheetIsOpen() && !hasFile) {
      finishClose();
    } else if (!sheetIsOpen() && hasFile && sheet && sheetHeading()) {
      /* The forward button brought ?file= back: re-open the sheet so the screen
         matches the address bar. We sit on the pushed entry again, so the back
         button (or Esc) can step off it to close. */
      sheetPushed = true;
      openSheet(selectedLink());
    }
  });

  onClick("[data-sheet-close]", function () {
    closeSheet();
  });

  onClick("[data-sheet-scrim]", function () {
    closeSheet();
  });

  onClick("[data-sheet-step]", function (button) {
    stepFile(Number(button.getAttribute("data-sheet-step")));
  });

  document.addEventListener("keydown", function (event) {
    if (!sheetIsOpen()) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeSheet();
      return;
    }
    var typing = event.target.closest && event.target.closest("input, textarea, select");
    var plain = !(event.ctrlKey || event.altKey || event.metaKey || event.shiftKey);
    if (plain && !typing && (event.key === "j" || event.key === "k")) {
      event.preventDefault();
      stepFile(event.key === "j" ? 1 : -1);
      return;
    }
    /* Focus stays in the dialog: the page behind is inert, and Tab wraps. */
    if (event.key === "Tab") {
      var stops = all(
        "a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex='0']",
        sheet
      ).filter(function (node) {
        return node.offsetParent !== null;
      });
      if (!stops.length) {
        return;
      }
      var first = stops[0];
      var last = stops[stops.length - 1];
      var here = document.activeElement;
      if (event.shiftKey && (here === first || !sheet.contains(here))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (here === last || !sheet.contains(here))) {
        event.preventDefault();
        first.focus();
      }
    }
  });

  /* Whatever lands in the preview (a file, a comparison, a verdict) opens the
     dialog. htmx 4 reports the swap target, not the button, as the source when
     the button is removed by the swap (a link inside the preview), so the file
     that is now shown is read from the swapped-in panel, not from the trigger.
     The panel stamps its own file url (data-preview-file), and a 404 panel
     stamps data-preview-miss so the address bar is not pointed at a file the
     run does not have. Swaps elsewhere on the page (the YARA rule, the rule
     pack) are left alone. */
  function landsInPreview(trigger, preview) {
    if (!trigger) {
      return false;
    }
    /* The assessment form swaps itself out, so its trigger is no longer in the
       page by the time this runs; it never belongs to the preview. */
    var own = trigger instanceof Element ? trigger : trigger.parentElement;
    if (own && own.closest("[data-report], [data-assess]")) {
      return false;
    }
    if (trigger === preview || preview.contains(trigger) || !document.contains(trigger)) {
      return true;
    }
    /* A load from the address bar (?file=) reports the document or a text node
       as the source; only an element can be asked where it was aimed. */
    var node = trigger instanceof Element ? trigger : trigger.parentElement;
    if (!node) {
      return false;
    }
    var aimed = node.closest("[hx-target]");
    return Boolean(aimed && aimed.getAttribute("hx-target") === "#preview");
  }

  onSwap(function () {
    window.requestAnimationFrame(land);
  });

  onSwap(function (trigger) {
    var preview = document.getElementById("preview");
    var panel = preview && preview.querySelector(".preview");
    if (!panel || !landsInPreview(trigger, preview)) {
      return;
    }
    var fileUrl = panel.getAttribute("data-preview-file");
    var isMiss = panel.hasAttribute("data-preview-miss");

    if (fileUrl && !isMiss) {
      var url = new URL(window.location.href);
      url.searchParams.set("file", fileUrl);
      url.hash = "";
      if (sheet && !sheetIsOpen()) {
        /* htmx 4 marks the entry it starts on and, on a back step to a marked
           entry, refetches the whole page. Unmark it: the sheet owns this step. */
        window.history.replaceState({}, "", window.location.href);
        window.history.pushState({ sheet: true }, "", url);
        sheetPushed = true;
      } else {
        window.history.replaceState(sheetPushed ? { sheet: true } : {}, "", url);
      }
      all("[data-listing-rows] [data-row]").forEach(function (row) {
        var own = row.querySelector("[data-file-url]");
        var on = Boolean(own && own.getAttribute("data-file-url") === fileUrl);
        row.classList.toggle("is-selected", on);
        if (own) {
          own.classList.toggle("is-selected", on);
        }
      });
    }

    /* Where focus returns when the sheet closes: the link that opened it,
       unless that link lives inside the sheet (a preview-internal link), in
       which case keep the row that opened the sheet. */
    var returnTo = trigger && trigger.tagName === "FORM"
      ? trigger.querySelector("[type=submit]")
      : trigger;
    if (returnTo && (sheet.contains(returnTo) || !document.contains(returnTo))) {
      returnTo = null;
    }
    openSheet(returnTo); /* moves focus to the panel heading */
  });

  /* A page opened with ?file= starts with the dialog up. */
  if (sheet && sheet.hasAttribute("data-sheet-open") && sheetHeading()) {
    openSheet(selectedLink());
  }

  /* The report window. Without the script it is the last part of the run page
     and the Report link scrolls to it. With it, the link opens it as a dialog:
     the page behind goes inert, Tab wraps inside, Esc and the scrim close it,
     and focus goes back to the link. */
  var report = document.querySelector("[data-report]");
  var reportScrim = document.querySelector("[data-report-scrim]");
  var reportReturn = null;
  var reportInert = [];

  function reportIsOpen() {
    return Boolean(report && report.classList.contains("is-open"));
  }

  function reportInertOutside(on) {
    if (!on) {
      reportInert.forEach(function (node) {
        node.inert = false;
      });
      reportInert = [];
      return;
    }
    var keep = function (node) {
      return node === reportScrim || node.id === "toast-region" || node.tagName === "SCRIPT";
    };
    for (var node = report; node && node !== document.body; node = node.parentElement) {
      Array.prototype.forEach.call(node.parentElement.children, function (sibling) {
        if (sibling !== node && !sibling.inert && !keep(sibling)) {
          sibling.inert = true;
          reportInert.push(sibling);
        }
      });
    }
  }

  function openReport(returnTo) {
    if (!report || reportIsOpen()) {
      return;
    }
    reportReturn = returnTo || null;
    report.classList.add("is-open");
    report.setAttribute("role", "dialog");
    report.setAttribute("aria-modal", "true");
    document.documentElement.classList.add("sheet-open");
    if (reportScrim) {
      reportScrim.hidden = false;
    }
    reportInertOutside(true);
    var title = report.querySelector("#report-title");
    if (title) {
      title.focus();
    }
  }

  function closeReport() {
    if (!reportIsOpen()) {
      return;
    }
    report.classList.remove("is-open");
    report.removeAttribute("role");
    report.removeAttribute("aria-modal");
    document.documentElement.classList.remove("sheet-open");
    if (reportScrim) {
      reportScrim.hidden = true;
    }
    reportInertOutside(false);
    if (window.location.hash === "#report" || window.location.hash === "#assessment") {
      window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
    }
    var back = reportReturn && document.contains(reportReturn)
      ? reportReturn
      : document.querySelector("[data-report-open]");
    reportReturn = null;
    if (back) {
      back.focus();
    }
  }

  onClick("[data-report-open]", function (link, event) {
    if (!report) {
      return;
    }
    event.preventDefault();
    openReport(link);
  });

  onClick("[data-report-close]", function () {
    closeReport();
  });

  onClick("[data-report-scrim]", function () {
    closeReport();
  });

  document.addEventListener("keydown", function (event) {
    if (!reportIsOpen()) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeReport();
      return;
    }
    if (event.key !== "Tab") {
      return;
    }
    var stops = all(
      "a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex='0']",
      report
    ).filter(function (node) {
      return node.offsetParent !== null || node.getClientRects().length > 0;
    });
    if (!stops.length) {
      return;
    }
    var first = stops[0];
    var last = stops[stops.length - 1];
    var here = document.activeElement;
    if (event.shiftKey && (here === first || !report.contains(here) || here.id === "report-title")) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (here === last || !report.contains(here))) {
      event.preventDefault();
      first.focus();
    }
  });

  /* Format: one Download button that follows the choice. Without the script the
     two formats are two buttons. */
  function chosenFormat() {
    var on = report && report.querySelector("[data-report-format]:checked");
    return on ? on.value : "pdf";
  }

  function paintFormat() {
    if (!report) {
      return;
    }
    var button = report.querySelector("[data-report-download]");
    var label = report.querySelector("[data-report-format-name]");
    var md = chosenFormat() === "md";
    if (button) {
      button.setAttribute("formaction", report.getAttribute(md ? "data-md-url" : "data-pdf-url"));
      if (md) {
        button.setAttribute("name", "download");
        button.setAttribute("value", "1");
      } else {
        button.removeAttribute("name");
        button.removeAttribute("value");
      }
    }
    if (label) {
      label.textContent = md ? "Markdown" : "PDF";
    }
  }

  /* TLP: the definition under the select follows the choice, and a choice less
     restrictive than the label saved for this run says so, with the same
     sentence the command line prints. */
  function paintTlp() {
    if (!report) {
      return;
    }
    var select = report.querySelector("[data-report-tlp]");
    if (!select) {
      return;
    }
    var value = select.value;
    all("[data-tlp-def]", report).forEach(function (line) {
      line.hidden = line.getAttribute("data-tlp-def") !== value;
    });
    var warn = report.querySelector("[data-report-warn]");
    if (!warn) {
      return;
    }
    var savedRank = report.getAttribute("data-saved-rank");
    var saved = report.getAttribute("data-saved-tlp");
    var option = select.options[select.selectedIndex];
    var rank = option ? Number(option.getAttribute("data-rank")) : NaN;
    if (saved && savedRank !== "" && rank < Number(savedRank)) {
      warn.textContent = report.getAttribute("data-warn-template")
        .replace("{choice}", value)
        .replace("{saved}", saved);
      warn.hidden = false;
    } else {
      warn.textContent = "";
      warn.hidden = true;
    }
  }

  /* After a save the label saved for this run may have changed; the warning
     reads the new one. */
  function syncSavedTlp() {
    var box = document.querySelector("[data-assess]");
    if (!report || !box) {
      return;
    }
    var saved = box.getAttribute("data-saved-tlp") || "";
    var stored = report.getAttribute("data-saved-tlp") || "";
    if (!box.querySelector("[data-assess-status] [role=status]") || saved === stored) {
      return;
    }
    var select = report.querySelector("[data-report-tlp]");
    var match = select && all("option", select).filter(function (option) {
      return option.value === saved;
    })[0];
    report.setAttribute("data-saved-tlp", saved);
    report.setAttribute("data-saved-rank", match ? match.getAttribute("data-rank") : "");
    var note = report.querySelector("#report-tlp-saved");
    if (note && saved) {
      note.textContent = "Saved for this run: TLP:" + saved + ". Change the saved label in the assessment below.";
    }
    if (select && match) {
      select.value = saved;
    }
    paintTlp();
  }

  document.addEventListener("change", function (event) {
    if (!report || !report.contains(event.target)) {
      return;
    }
    if (event.target.matches("[data-report-format]")) {
      paintFormat();
    } else if (event.target.matches("[data-report-tlp]")) {
      paintTlp();
    } else if (event.target.matches("select[data-defined]")) {
      var option = event.target.options[event.target.selectedIndex];
      var help = report.querySelector("[data-definition-for='" + event.target.id + "']");
      if (help && option) {
        help.textContent = option.getAttribute("data-definition") || "";
      }
    }
  });

  onClick("[data-report-copy]", function (button) {
    var select = report && report.querySelector("[data-report-tlp]");
    var url = report.getAttribute("data-md-url") + "?logo=none&tlp=" +
      encodeURIComponent(select ? select.value : "");
    fetch(url, { headers: { Accept: "text/plain" } })
      .then(function (reply) {
        if (!reply.ok) {
          throw new Error(String(reply.status));
        }
        return reply.text();
      })
      .then(writeClipboard)
      .then(
        function () { toast("Copied the report as text"); },
        function () { toast("The report could not be copied", "alert"); }
      );
    button.blur();
    button.focus();
  });

  /* A saved, refused or conflicting assessment comes back as the same box. Put
     focus on its first message, so the result is read out where the reader is. */
  onSwap(function () {
    var box = document.querySelector("[data-assess]");
    if (!box || !report || !reportIsOpen()) {
      return;
    }
    var active = document.activeElement;
    if (active && active !== document.body && document.contains(active)) {
      return;
    }
    var alert = box.querySelector("[role=alert]");
    var target = alert || box.querySelector("[data-assess-status]");
    if (alert) {
      alert.setAttribute("tabindex", "-1");
    }
    if (target) {
      target.focus();
    }
    syncSavedTlp();
  });

  if (report) {
    paintFormat();
    paintTlp();
    all("[data-report-open]").forEach(function (link) {
      link.setAttribute("aria-haspopup", "dialog");
    });
    /* A link to #report or #assessment (the redirect after a plain form save)
       opens the window with the assessment showing. */
    var hash = window.location.hash;
    if (hash === "#report" || hash === "#assessment") {
      if (hash === "#assessment") {
        var fold = report.querySelector("#assessment");
        if (fold) {
          fold.open = true;
        }
      }
      openReport(document.querySelector("[data-report-open]"));
    }
  }

  /* the rule pack: busy state, last choice wins, focus kept across the redraw */

  /* The rule pack form redraws its whole panel (outerHTML) on every change, so
     the control that changed is torn out and focus falls to the body. These
     handlers keep the keyboard's place: the control that fired the change is
     found again in the fresh panel (by id for the selects, by name and value
     for the radios and checkboxes) and refocused. While the request is in
     flight the panel is marked busy and the still stale output is dimmed, so the
     radio that already moved and the output that has not do not read as a
     mismatch. htmx 4 aborts an in flight request when a newer change starts
     (hx-sync on the form), so a slow answer does not let the first choice
     overwrite the last. */
  var detLive = null;
  var detBusyTimer = null;
  var detPendingFocus = null;
  var detInFlight = 0;

  function detPanel() {
    return document.getElementById("det-panel");
  }

  function detRequest(event) {
    var elt = event.target;
    return elt && elt.closest ? elt.closest("[data-det-form]") : null;
  }

  function describeControl(el) {
    if (!el || !el.closest || !el.closest("[data-det-form]")) {
      return null;
    }
    return {
      id: el.id || "",
      name: (el.getAttribute && el.getAttribute("name")) || "",
      value: (el.getAttribute && el.getAttribute("value")) || ""
    };
  }

  function cssEscape(value) {
    if (window.CSS && window.CSS.escape) {
      return window.CSS.escape(value);
    }
    return String(value).replace(/["\\\]]/g, "\\$&");
  }

  function twinOf(panel, want) {
    if (!panel || !want) {
      return null;
    }
    if (want.id) {
      var byId = panel.querySelector("#" + cssEscape(want.id));
      if (byId) {
        return byId;
      }
    }
    if (want.name) {
      var selector = '[name="' + cssEscape(want.name) + '"]';
      if (want.value) {
        selector += '[value="' + cssEscape(want.value) + '"]';
      }
      return panel.querySelector(selector);
    }
    return null;
  }

  /* One quiet line for the screen reader, made the first time a redraw runs so
     it is in the page before any text is set into it. */
  function detSay(text) {
    if (!detLive) {
      detLive = document.createElement("p");
      detLive.className = "visually-hidden";
      detLive.setAttribute("role", "status");
      detLive.setAttribute("aria-live", "polite");
      document.body.appendChild(detLive);
    }
    detLive.textContent = text;
  }

  document.body.addEventListener("htmx:before:request", function (event) {
    if (!detRequest(event)) {
      return;
    }
    detInFlight += 1;
    detPendingFocus = describeControl(document.activeElement);
    var panel = detPanel();
    if (panel) {
      panel.classList.add("is-busy");
      panel.setAttribute("aria-busy", "true");
    }
    /* A fast answer never speaks: the line is set only if the wait runs long,
       and each new change resets the timer, so a flurry of clicks says it once. */
    detSay("");
    window.clearTimeout(detBusyTimer);
    detBusyTimer = window.setTimeout(function () {
      if (detInFlight > 0) {
        detSay("Updating the rules");
      }
    }, 300);
  });

  document.body.addEventListener("htmx:after:request", function (event) {
    if (!detRequest(event)) {
      return;
    }
    detInFlight = Math.max(0, detInFlight - 1);
    if (detInFlight === 0) {
      window.clearTimeout(detBusyTimer);
      detSay("");
      /* htmx 4 ends the request just before it swaps. On success the fresh
         panel arrives without the flag anyway; on a failed request with no swap
         this is what makes the panel usable again. */
      var panel = detPanel();
      if (panel && panel.classList.contains("is-busy")) {
        panel.classList.remove("is-busy");
        panel.removeAttribute("aria-busy");
      }
    }
  });

  onSwap(function () {
    if (!detPendingFocus) {
      return;
    }
    var panel = detPanel();
    if (!panel) {
      return;
    }
    var here = document.activeElement;
    if (here && here !== document.body && document.contains(here)) {
      /* Focus is still on a live control: this swap was not the redraw (the
         preview under the panel can land while the change is in flight), so
         keep the wish for the redraw that follows. */
      return;
    }
    var want = detPendingFocus;
    detPendingFocus = null;
    var twin = twinOf(panel, want);
    if (twin) {
      twin.focus();
    }
  });
})();
