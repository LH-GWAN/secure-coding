// 서버가 준 content 는 반드시 textContent 로만 삽입한다 (XSS 차단)
(function () {
  var log = document.getElementById("chat-log");
  var meEl = document.getElementById("me");
  if (!log || !meEl || typeof io === "undefined") return;
  var me = meEl.getAttribute("data-username");

  function appendMessage(m) {
    var empty = document.getElementById("chat-empty");
    if (empty) empty.remove();

    var wrap = document.createElement("div");
    wrap.className = "bubble " + (m.user === me ? "me" : "them");

    var who = document.createElement("div");
    var strong = document.createElement("strong");
    strong.textContent = m.user;
    who.appendChild(strong);

    var body = document.createElement("div");
    body.textContent = m.content;

    var meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = m.at;

    wrap.appendChild(who);
    wrap.appendChild(body);
    wrap.appendChild(meta);
    log.appendChild(wrap);
    log.scrollTop = log.scrollHeight;
  }

  var socket = io({ transports: ["websocket", "polling"] });

  socket.on("chat_message", appendMessage);
  socket.on("chat_error", function (e) {
    var note = document.getElementById("chat-note");
    if (note) { note.textContent = e.message; }
  });

  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var text = input.value.trim();
    if (!text) return;
    socket.emit("chat_message", { content: text });
    input.value = "";
    input.focus();
  });

  log.scrollTop = log.scrollHeight;
})();
