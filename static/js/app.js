/*
 * app.js - small conveniences only. The site works without JavaScript.
 * IMPORTANT: none of this is security. Real validation and access control
 * happen on the server; anything done in the browser can be bypassed (try it in Burp!).
 *
 * The Content-Security-Policy only allows scripts from this file, so there are
 * no inline scripts or onclick="" attributes anywhere in the templates.
 */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  // Mobile menu button
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.getElementById("site-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // Ask before destructive actions: <form data-confirm="Are you sure?">
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Show / hide password buttons
  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    var input = document.getElementById(button.getAttribute("data-toggle-password"));
    if (!input) { return; }
    button.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
      button.setAttribute("aria-pressed", show ? "true" : "false");
    });
  });
})();
