/**
 * pq_ratchet.web.static.app.js
 * Ephemeral Post-Quantum Messaging Controller.
 * Zero disk persistence, zero browser database storage, 1-hour volatile lifecycle.
 */

(function () {
  // Enforce zero plaintext browser DB storage
  try {
    localStorage.clear();
    sessionStorage.clear();
  } catch (e) {}

  let ws = null;
  let currentUsername = "";
  let activePeer = null;
  let ttlSeconds = 3600;
  let countdownTimer = null;

  // Purely Volatile RAM Heap - Wiped on tab close, reload, or expiration
  const volatileMessageHeap = [];

  // DOM Elements
  const joinModal = document.getElementById("join-modal");
  const joinForm = document.getElementById("join-form");
  const inputUsername = document.getElementById("input-username");

  const statusBeacon = document.getElementById("status-beacon");
  const securityStatusText = document.getElementById("security-status-text");
  const ttlDisplay = document.getElementById("ttl-display");
  const statTtlDrawer = document.getElementById("stat-ttl-drawer");
  const peerChip = document.getElementById("peer-chip");
  const displayPeerName = document.getElementById("display-peer-name");

  const btnClearChat = document.getElementById("btn-clear-chat");
  const btnToggleInspector = document.getElementById("btn-toggle-inspector");
  const btnCloseDrawer = document.getElementById("btn-close-drawer");
  const telemetryDrawer = document.getElementById("telemetry-drawer");

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

  // Telemetry DOM
  const statEpoch = document.getElementById("stat-epoch");
  const statSeq = document.getElementById("stat-seq");
  const statAeadTag = document.getElementById("stat-aead-tag");

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

    showToast(`Establishing ephemeral connection for ${username}...`);
    ws = new WebSocket(wsUrl);

    ws.onopen = function () {
      statusBeacon.className = "status-dot pulsing";
      securityStatusText.textContent = "Online (Awaiting Peer)";
      startPollingOnlineDirectory();
    };

    ws.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        handleServerPayload(data);
      } catch (err) {
        console.error("Malformed server frame:", err);
      }
    };

    ws.onclose = function () {
      handleSessionTermination("Disconnected from server. Memory zeroized.");
    };

    ws.onerror = function (err) {
      console.error("WebSocket error:", err);
    };
  }

  // Handle Inbound Server Events
  function handleServerPayload(data) {
    switch (data.type) {
      case "session_registered":
        ttlSeconds = data.ttl;
        startTtlCountdown(ttlSeconds);
        showToast(`Registered as '${data.username}'. Active for 1 hour.`);
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
        handleSessionTermination("Your 1-hour anonymous session has expired. All keys destroyed.");
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
    peerChip.classList.remove("hidden");
    btnClearChat.classList.remove("hidden");

    peerPairingBox.classList.add("hidden");
    messagesList.classList.remove("hidden");

    statusBeacon.className = "status-dot active";
    securityStatusText.textContent = `Quantum Safe with ${activePeer}`;

    chatInput.disabled = false;
    btnSendMessage.disabled = false;
    chatInput.placeholder = `Type a quantum-encrypted message to ${activePeer}...`;
    chatInput.focus();

    showToast(`Quantum handshake verified with ${activePeer} (${data.bits}-bit FTQC immune).`);
  }

  // 1-Hour Countdown Engine
  function startTtlCountdown(initialTtl) {
    if (countdownTimer) clearInterval(countdownTimer);
    let remaining = initialTtl;

    function update() {
      if (remaining <= 0) {
        clearInterval(countdownTimer);
        handleSessionTermination("1-Hour session expired. RAM wiped.");
        return;
      }
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      const formatted = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
      ttlDisplay.textContent = formatted;
      statTtlDrawer.textContent = `${formatted} Remaining`;
      remaining--;
    }

    update();
    countdownTimer = setInterval(update, 1000);
  }

  function handleSessionTermination(reason) {
    if (countdownTimer) clearInterval(countdownTimer);
    // Purge volatile RAM heap
    volatileMessageHeap.length = 0;
    messagesList.innerHTML = "";

    statusBeacon.className = "status-dot";
    securityStatusText.textContent = "Session Expired";
    chatInput.disabled = true;
    btnSendMessage.disabled = true;

    alert(reason);
    window.location.reload();
  }

  // Online Peer Directory Polling
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
      onlineUsersList.innerHTML = '<span class="empty-hint">No other peers online yet. Open a 2nd tab or invite a friend!</span>';
      return;
    }

    peers.forEach(p => {
      const btn = document.createElement("button");
      btn.className = "peer-chip-btn";
      btn.innerHTML = `<span class="dot"></span> <span>${escapeHtml(p.username)}</span> <small>(${Math.floor(p.ttl / 60)}m left)</small>`;
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
      showToast("WebSocket not connected.", true);
      return;
    }

    showToast(`Initiating ML-DSA-65 authenticated handshake with '${target}'...`);
    ws.send(JSON.stringify({
      action: "connect_peer",
      target: target,
    }));
  });

  // Render Encrypted Message
  function renderMessage(msg) {
    volatileMessageHeap.push(msg);
    const isMine = msg.sender === currentUsername;

    const row = document.createElement("div");
    row.className = `message-row ${isMine ? "mine" : "peer"}`;

    const header = document.createElement("div");
    header.className = "message-meta-header";
    header.innerHTML = `<span class="sender-name">${escapeHtml(msg.sender)}</span> <span>${msg.timestamp}</span>`;

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = msg.text;

    const meta = msg.pqc_meta;
    const tagRow = document.createElement("div");
    tagRow.className = "quantum-tag-row";

    if (meta.has_kem_rekey) {
      tagRow.innerHTML += `<span class="pqc-pill kem-turn">ML-KEM-768 Encap: ${meta.kem_bytes}B</span>`;
    }
    tagRow.innerHTML += `<span class="pqc-pill">Epoch ${meta.epoch} | Seq ${meta.seq}</span>`;
    tagRow.innerHTML += `<span class="pqc-pill">Tag: ${meta.aead_tag}...</span>`;

    row.appendChild(header);
    row.appendChild(bubble);
    row.appendChild(tagRow);

    messagesList.appendChild(row);
    scrollToBottom();

    // Update Telemetry Panel
    statEpoch.textContent = meta.epoch;
    statSeq.textContent = meta.seq;
    statAeadTag.textContent = `Poly1305 MAC: ${meta.aead_tag}...`;
  }

  // Mutual "Clear Chat for Both"
  function onChatCleared(data) {
    // 1. Wipe volatile RAM heap
    volatileMessageHeap.length = 0;

    // 2. Wipe DOM completely
    messagesList.innerHTML = "";

    // 3. Render verified system wipe banner
    const banner = document.createElement("div");
    banner.className = "system-banner";
    banner.innerHTML = `<strong>CHAT HISTORY PERMANENTLY ERASED</strong><br>Zeroized from both browser endpoints and ratchet keys rotated by <em>${escapeHtml(data.by)}</em> at ${data.timestamp}.`;
    messagesList.appendChild(banner);

    statSeq.textContent = "0";
    showToast(`Chat history wiped from both ends by ${data.by}.`);
    scrollToBottom();
  }

  btnClearChat.addEventListener("click", function () {
    if (!confirm("Permanently wipe chat history from BOTH devices and advance ratchet keys?")) {
      return;
    }
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action: "clear_chat" }));
    }
  });

  // Message Send
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

  // Telemetry Panel Toggle
  btnToggleInspector.addEventListener("click", function () {
    telemetryDrawer.classList.toggle("open");
  });
  btnCloseDrawer.addEventListener("click", function () {
    telemetryDrawer.classList.remove("open");
  });

  function scrollToBottom() {
    messagesViewport.scrollTop = messagesViewport.scrollHeight;
  }

  function showToast(text, isError = false) {
    const toast = document.createElement("div");
    toast.className = "toast";
    if (isError) toast.style.borderColor = "var(--accent-rose)";
    toast.textContent = text;
    toastStack.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
