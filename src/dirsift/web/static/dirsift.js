/* DirSift console behaviour.

   Everything here is progressive: the pages work without it, this only makes
   reading faster. No network calls live in this file. The scan itself is the
   only thing that talks to a target, and that happens on the server when the
   button is pressed. */

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

  /* Copy a hash or an indicator without selecting it by hand. */
  onClick("[data-copy]", function (button) {
    var value = button.getAttribute("data-copy");
    var say = function (text) {
      var previous = button.getAttribute("data-label") || button.textContent;
      button.setAttribute("data-label", previous);
      button.textContent = text;
      window.setTimeout(function () {
        button.textContent = button.getAttribute("data-label");
      }, 1200);
      toast(text, text === "blocked" ? "alert" : null);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(
        function () {
          say("copied");
        },
        function () {
          say("blocked");
        }
      );
      return;
    }
    var field = document.createElement("textarea");
    field.value = value;
    document.body.appendChild(field);
    field.select();
    try {
      document.execCommand("copy");
      say("copied");
    } catch (error) {
      say("blocked");
    }
    document.body.removeChild(field);
  });

  /* Preview tabs: contents, hex, links. */
  onClick(".tab", function (tab) {
    var group = tab.closest(".preview");
    if (!group) {
      return;
    }
    var wanted = tab.getAttribute("aria-controls");
    group.querySelectorAll(".tab").forEach(function (other) {
      other.setAttribute("aria-selected", String(other === tab));
    });
    group.querySelectorAll(".tab-panel").forEach(function (panel) {
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
    pre.querySelectorAll(".line").forEach(function (line) {
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
     the arrows scroll, as they should. Enter on a row's pick box opens the
     file, the same as Enter on its name. */
  document.addEventListener("keydown", function (event) {
    if (event.ctrlKey || event.altKey || event.metaKey || event.shiftKey) {
      return;
    }
    var body = event.target.closest && event.target.closest("[data-listing-rows]");
    if (!body) {
      return;
    }
    var row = event.target.closest("tr");
    var own = row && row.querySelector("[data-file-url]");
    if (!own) {
      return;
    }
    if (event.key === "Enter" && event.target !== own) {
      event.preventDefault();
      own.click();
      return;
    }
    var down = event.key === "j" || event.key === "ArrowDown";
    var up = event.key === "k" || event.key === "ArrowUp";
    if (!down && !up) {
      return;
    }
    var files = Array.prototype.slice.call(body.querySelectorAll("[data-file-url]"));
    var next = files.indexOf(own) + (down ? 1 : -1);
    if (next < 0 || next >= files.length) {
      return;
    }
    event.preventDefault();
    files[next].focus();
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

  /* Run page tabs. Without the script they are links down a page that carries
     every part of the run; with it, one part shows at a time and the address
     bar keeps which (?tab=), so a link to the Notes tab opens on the notes. The
     server reads ?tab= too and marks that part, so nothing jumps on load. */
  var showRunTab = null;
  var tablist = document.querySelector("[data-run-tablist]");
  if (tablist) {
    var runTabs = Array.prototype.slice.call(tablist.querySelectorAll("[data-tab]"));
    var panelOf = function (tab) {
      return document.getElementById(tab.getAttribute("data-tab"));
    };
    tablist.setAttribute("role", "tablist");
    tablist.setAttribute("aria-label", "Parts of this run");
    runTabs.forEach(function (tab) {
      var panel = panelOf(tab);
      tab.setAttribute("role", "tab");
      tab.setAttribute("aria-controls", panel.id);
      panel.setAttribute("role", "tabpanel");
      panel.setAttribute("aria-labelledby", tab.id);
    });

    var showTab = function (key, how) {
      var wanted = runTabs.filter(function (tab) {
        return tab.getAttribute("data-tab") === key;
      })[0];
      if (!wanted) {
        return;
      }
      runTabs.forEach(function (tab) {
        var on = tab === wanted;
        tab.setAttribute("aria-selected", String(on));
        tab.setAttribute("tabindex", on ? "0" : "-1");
        tab.classList.toggle("is-current", on);
        panelOf(tab).classList.toggle("is-current", on);
      });
      if (how && how.remember) {
        var url = new URL(window.location.href);
        url.searchParams.set("tab", key);
        url.hash = "";
        window.history.replaceState(window.history.state, "", url);
      }
      if (how && how.focus) {
        wanted.focus();
      }
    };
    showRunTab = showTab;

    var fromHash = window.location.hash.slice(1);
    var current = tablist.querySelector(".run-tab.is-current") || runTabs[0];
    showTab(
      runTabs.some(function (tab) { return tab.getAttribute("data-tab") === fromHash; })
        ? fromHash
        : current.getAttribute("data-tab")
    );

    onClick("[data-tab], [data-tab-link]", function (link, event) {
      event.preventDefault();
      var key = link.getAttribute("data-tab") || link.getAttribute("data-tab-link");
      showTab(key, { remember: true, focus: link.hasAttribute("data-tab-link") });
    });

    tablist.addEventListener("keydown", function (event) {
      var at = runTabs.indexOf(event.target);
      if (at === -1) {
        return;
      }
      var next = null;
      if (event.key === "ArrowRight") {
        next = (at + 1) % runTabs.length;
      } else if (event.key === "ArrowLeft") {
        next = (at - 1 + runTabs.length) % runTabs.length;
      } else if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = runTabs.length - 1;
      }
      if (next === null) {
        return;
      }
      event.preventDefault();
      showTab(runTabs[next].getAttribute("data-tab"), { remember: true, focus: true });
    });

    window.addEventListener("hashchange", function () {
      showTab(window.location.hash.slice(1), { remember: true });
    });
  }

  /* On a narrow screen the listing and the preview do not fit side by side, so
     the preview opens as a sheet over the listing. Without the script there is
     no sheet: the preview stays in the page, below the listing. The sheet takes
     one history entry when it opens, so the browser's back button closes it. */
  var narrow = window.matchMedia("(max-width: 1099px)");
  var sheet = document.querySelector("[data-sheet]");
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

  function focusPreviewHeading() {
    var heading = sheetHeading();
    if (heading) {
      heading.focus();
    }
  }

  /* The sheet lives inside the files panel. If some other tab is showing, the
     panel is display:none and the sheet would open invisibly, locking the page
     behind an inert backdrop. Open it only when its own panel is on screen. */
  function sheetPanelShown() {
    if (!sheet) {
      return false;
    }
    var panel = sheet.closest(".run-panel");
    return !panel || panel.classList.contains("is-current");
  }

  function setOutsideInert(on) {
    if (!on) {
      sheetInert.forEach(function (node) {
        node.inert = false;
      });
      sheetInert = [];
      return;
    }
    for (var node = sheet; node && node !== document.body; node = node.parentElement) {
      Array.prototype.forEach.call(node.parentElement.children, function (sibling) {
        if (sibling !== node && !sibling.inert && sibling.tagName !== "SCRIPT") {
          sibling.inert = true;
          sheetInert.push(sibling);
        }
      });
    }
  }

  function openSheet(returnTo) {
    if (!sheet || !narrow.matches || !sheetPanelShown()) {
      return;
    }
    if (!sheetIsOpen()) {
      sheetReturn = returnTo || null;
      sheet.classList.add("is-open");
      sheet.setAttribute("role", "dialog");
      sheet.setAttribute("aria-modal", "true");
      sheet.setAttribute("aria-label", "File preview");
      document.documentElement.classList.add("sheet-open");
      setOutsideInert(true);
    }
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
    setOutsideInert(false);
    sheetPushed = false;
    var back = sheetReturn && document.contains(sheetReturn) ? sheetReturn
      : document.querySelector("[data-listing-rows] .link-button.is-selected");
    sheetReturn = null;
    if (back && narrow.matches) {
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
    } else if (!sheetIsOpen() && hasFile && narrow.matches && sheet && sheetHeading()) {
      /* The forward button brought ?file= back: re-open the sheet so the screen
         matches the address bar. We sit on the pushed entry again, so the back
         button (or Esc) can step off it to close. */
      sheetPushed = true;
      openSheet(document.querySelector("[data-listing-rows] .link-button.is-selected"));
    }
  });

  onClick("[data-sheet-close]", function () {
    closeSheet();
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && sheetIsOpen()) {
      event.preventDefault();
      closeSheet();
    }
  });

  narrow.addEventListener("change", function () {
    if (!narrow.matches) {
      finishClose();
    }
  });

  /* Whatever lands in the preview (a file, a comparison, a rule) opens the
     sheet. htmx 4 reports the swap target, not the button, as the source when
     the button is removed by the swap (a link inside the preview), so the file
     that is now shown is read from the swapped-in panel, not from the trigger.
     The panel stamps its own file url (data-preview-file), and a 404 panel
     stamps data-preview-miss so the address bar is not pointed at a file the
     run does not have. */
  onSwap(function (trigger) {
    var preview = document.getElementById("preview");
    var panel = preview && preview.querySelector(".preview");
    /* Every swap on the run page lands in the preview; a page without one (the
       scan page's polling box) has nothing here to sync. */
    if (!panel) {
      return;
    }
    var fileUrl = panel.getAttribute("data-preview-file");
    var isMiss = Boolean(panel && panel.hasAttribute("data-preview-miss"));

    if (fileUrl && !isMiss) {
      var url = new URL(window.location.href);
      url.searchParams.set("file", fileUrl);
      if (narrow.matches && sheet && !sheetIsOpen()) {
        /* htmx 4 marks the entry it starts on and, on a back step to a marked
           entry, refetches the whole page. Unmark it: the sheet owns this step. */
        window.history.replaceState({}, "", window.location.href);
        window.history.pushState({ sheet: true }, "", url);
        sheetPushed = true;
      } else {
        window.history.replaceState({}, "", url);
      }
      document.querySelectorAll("[data-listing-rows] tr").forEach(function (row) {
        var own = row.querySelector("[data-file-url]");
        var on = Boolean(own && own.getAttribute("data-file-url") === fileUrl);
        row.classList.toggle("is-selected", on);
        if (own) {
          own.classList.toggle("is-selected", on);
        }
      });
    }

    /* Where focus returns when the sheet closes: the button that opened it,
       unless that button lives inside the sheet (a preview-internal link), in
       which case keep the listing row that opened the sheet. */
    var returnTo = trigger && trigger.tagName === "FORM"
      ? trigger.querySelector("[type=submit]")
      : trigger;
    if (returnTo && sheet && sheet.contains(returnTo)) {
      returnTo = null;
    }
    /* A preview-internal link was swapped out with the rest of the panel, so
       htmx hands back a button that is no longer in the document (or, in some
       builds, the preview target itself). Either way it means the move came
       from inside the preview, not from the listing. */
    var fromPreview = Boolean(
      trigger && (trigger === preview || preview.contains(trigger) || !document.contains(trigger))
    );
    if (narrow.matches && sheet) {
      openSheet(returnTo); /* moves focus to the panel heading */
    } else if (fromPreview) {
      /* Desktop: a listing click keeps focus on the row, but navigating from
         inside the preview moves focus to the new panel heading. */
      focusPreviewHeading();
    }
  });

  /* A narrow page opened with ?file= starts with the sheet up. The server
     already forces the files tab for a ?file= link; switch to it here too so
     the sheet never opens behind a hidden panel even if that is somehow off. */
  if (new URL(window.location.href).searchParams.get("file") && sheetHeading()) {
    if (showRunTab) {
      showRunTab("files");
    }
    if (narrow.matches) {
      openSheet(document.querySelector("[data-listing-rows] .link-button.is-selected"));
    }
  }
})();
