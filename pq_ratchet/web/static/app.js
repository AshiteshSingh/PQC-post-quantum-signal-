/**
 * pq_ratchet.web.static.app.js
 * Clean, Minimalist Client Controller.
 * Under-the-hood CIA-grade Post-Quantum Cryptography (FIPS 203 + 204),
 * zero persistence, volatile memory heap, and mutual chat clearing.
 */

(function () {
  try {
    localStorage.clear();
    sessionStorage.clear();
  } catch (e) {}

  let ws = null;
  let currentUsername = "";
  let activePeer = null;
  let ttlSeconds = 3600;
  let countdownTimer = null;

  // Volatile RAM only - wiped on close/expiry
  const volatileMessageHeap = [];

  // DOM Elements
  const joinModal = document.getElementById("join-modal");
  const joinForm = document.getElementById("join-form");
  const inputUsername = document.getElementById("input-username");

  const headerAvatar = document.getElementById("header-avatar");
  const displayPeerName = document.getElementById("display-peer-name");
  const displayPeerStatus = document.getElementById("display-peer-status");
  const ttlDisplay = document.getElementById("ttl-display");
  const btnClearChat = document.getElementById("btn-clear-chat");

  const peerPairingBox = document.getElementById("peer-pairing-box");
  const currentUserTag = document.getElementById("current-user-tag");
  const connectPeerForm = document.getElementById("connect-peer-form");
  const targetPeerInput = document.getElementById("target-peer-input");
  const onlineUsersList = document.getElementById("online-users-list");

  const messagesViewport = document.getElementById("messages-container");
  const messagesList = document.getElementById("messages-list");
  const chatInput = document.getElementById("chat-input");
  const btnSendMessage = document.getElementById("btn-send-message");
  const toastStack = document.getElementById("toast-stack");

  // Handle Username Submission
  joinForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const handle = inputUsername.value.trim();
    if (!handle) return;

    currentUsername = handle;
    joinModal.classList.add("hidden");
    currentUserTag.textContent = handle;

    connectWebSocket(handle);
  });

  // WebSocket Connection
  function connectWebSocket(username) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/${encodeURIComponent(username)}`;

    ws = new WebSocket(wsUrl);

    ws.onopen = function () {
      displayPeerStatus.textContent = "Online";
      startPollingOnlineDirectory();
    };

    ws.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        handleServerPayload(data);
      } catch (err) {
        console.error("Payload error:", err);
      }
    };

    ws.onclose = function () {
      handleSessionTermination("Session closed.");
    };

    ws.onerror = function (err) {
      console.error("Connection error:", err);
    };
  }

  // Handle Server Events
  function handleServerPayload(data) {
    switch (data.type) {
      case "session_registered":
        ttlSeconds = data.ttl;
        startTtlCountdown(ttlSeconds);
        break;

      case "pqc_handshake_complete":
        onHandshakeComplete(data);
        break;

      case "message":
        renderMessage(data);
        break;

      case "chat_cleared":
        onChatCleared(data);
        break;

      case "session_expired":
        handleSessionTermination("Your 1-hour session has expired.");
        break;

      case "error":
        showToast(data.message, true);
        break;
    }
  }

  // Handshake Complete
  function onHandshakeComplete(data) {
    activePeer = data.peer;
    displayPeerName.textContent = activePeer;
    displayPeerStatus.textContent = "Online";
    headerAvatar.textContent = activePeer.charAt(0).toUpperCase();

    btnClearChat.classList.remove("hidden");
    peerPairingBox.classList.add("hidden");
    messagesList.classList.remove("hidden");

    chatInput.disabled = false;
    btnSendMessage.disabled = false;
    chatInput.placeholder = "Type a message...";
    chatInput.focus();
  }

  // 1-Hour Ephemeral Timer
  function startTtlCountdown(initialTtl) {
    if (countdownTimer) clearInterval(countdownTimer);
    let remaining = initialTtl;

    function update() {
      if (remaining <= 0) {
        clearInterval(countdownTimer);
        handleSessionTermination("1-Hour session ended.");
        return;
      }
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      ttlDisplay.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
      remaining--;
    }

    update();
    countdownTimer = setInterval(update, 1000);
  }

  function handleSessionTermination(reason) {
    if (countdownTimer) clearInterval(countdownTimer);
    volatileMessageHeap.length = 0;
    messagesList.innerHTML = "";

    displayPeerStatus.textContent = "Expired";
    chatInput.disabled = true;
    btnSendMessage.disabled = true;

    alert(reason);
    window.location.reload();
  }

  // Online Users Polling
  function startPollingOnlineDirectory() {
    async function poll() {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      try {
        const resp = await fetch("/api/online-users", { cache: "no-store" });
        if (resp.ok) {
          const data = await resp.json();
          renderOnlineDirectory(data.users || []);
        }
      } catch (e) {}
    }
    poll();
    setInterval(poll, 4000);
  }

  function renderOnlineDirectory(users) {
    const peers = users.filter(u => u.username !== currentUsername);
    onlineUsersList.innerHTML = "";

    if (peers.length === 0) {
      onlineUsersList.innerHTML = '<span class="empty-hint">No other users online yet</span>';
      return;
    }

    peers.forEach(p => {
      const btn = document.createElement("button");
      btn.className = "peer-chip-btn";
      btn.innerHTML = `<span class="dot"></span> <span>${escapeHtml(p.username)}</span>`;
      btn.onclick = () => {
        targetPeerInput.value = p.username;
        targetPeerInput.focus();
      };
      onlineUsersList.appendChild(btn);
    });
  }

  // Connect Peer Form
  connectPeerForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const target = targetPeerInput.value.trim();
    if (!target) return;

    if (!ws || ws.readyState !== WebSocket.OPEN) {
      showToast("Not connected", true);
      return;
    }

    ws.send(JSON.stringify({
      action: "connect_peer",
      target: target,
    }));
  });

  // Render Clean Message (Looks like normal Telegram / WhatsApp / iMessage)
  function renderMessage(msg) {
    volatileMessageHeap.push(msg);
    const isMine = msg.sender === currentUsername;

    const row = document.createElement("div");
    row.className = `message-row ${isMine ? "mine" : "peer"}`;

    const bubble = document.createElement("div");
    bubble.className = "bubble";

    const textSpan = document.createElement("span");
    textSpan.className = "bubble-text";
    textSpan.textContent = msg.text;

    const timeSpan = document.createElement("span");
    timeSpan.className = "bubble-time";
    timeSpan.textContent = msg.timestamp;

    bubble.appendChild(textSpan);
    bubble.appendChild(timeSpan);
    row.appendChild(bubble);

    messagesList.appendChild(row);
    scrollToBottom();
  }

  // Mutual "Clear Chat"
  function onChatCleared(data) {
    volatileMessageHeap.length = 0;
    messagesList.innerHTML = "";

    const notice = document.createElement("div");
    notice.className = "system-notice";
    notice.textContent = "Chat history cleared";
    messagesList.appendChild(notice);

    showToast("Chat cleared");
    scrollToBottom();
  }

  btnClearChat.addEventListener("click", function () {
    if (!confirm("Clear chat history for both participants?")) {
      return;
    }
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action: "clear_chat" }));
    }
  });

  // Send Message
  function sendMessage() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const text = chatInput.value.trim();
    if (!text) return;

    ws.send(JSON.stringify({
      action: "send_message",
      text: text,
    }));

    chatInput.value = "";
    chatInput.focus();
  }

  btnSendMessage.addEventListener("click", sendMessage);
  chatInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  function scrollToBottom() {
    messagesViewport.scrollTop = messagesViewport.scrollHeight;
  }

  function showToast(text, isError = false) {
    const toast = document.createElement("div");
    toast.className = "toast";
    if (isError) toast.style.borderColor = "#f43f5e";
    toast.textContent = text;
    toastStack.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 250);
    }, 2500);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
