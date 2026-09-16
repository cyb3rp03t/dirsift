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

  /* Walk the listing from the keyboard: j and k, or the arrow keys. */
  document.addEventListener("keydown", function (event) {
    if (event.ctrlKey || event.altKey || event.metaKey) {
      return;
    }
    var tag = (event.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") {
      return;
    }
    var down = event.key === "j" || event.key === "ArrowDown";
    var up = event.key === "k" || event.key === "ArrowUp";
    if (!down && !up) {
      return;
    }
    var rows = Array.prototype.slice.call(
      document.querySelectorAll("[data-listing] .link-button")
    );
    if (!rows.length) {
      return;
    }
    var index = rows.indexOf(document.activeElement);
    var next = index === -1 ? 0 : index + (down ? 1 : -1);
    if (next < 0 || next >= rows.length) {
      return;
    }
    event.preventDefault();
    rows[next].focus();
  });

  /* Keep the open file in the address bar so a preview can be shared or reloaded. */
  document.body.addEventListener("htmx:afterOnLoad", function (event) {
    var trigger = event.detail && event.detail.elt;
    if (!trigger || !trigger.hasAttribute("data-file-url")) {
      return;
    }
    var url = new URL(window.location.href);
    url.searchParams.set("file", trigger.getAttribute("data-file-url"));
    window.history.replaceState({}, "", url);
    document.querySelectorAll("[data-listing] tr").forEach(function (row) {
      row.classList.toggle("is-selected", row.contains(trigger));
    });
    document.querySelectorAll("[data-listing] .link-button").forEach(function (button) {
      button.classList.toggle("is-selected", button === trigger);
    });
  });
})();
