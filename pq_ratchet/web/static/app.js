/**
 * pq_ratchet.web.static.app.js
 * Client-Side Controller for Real-Time Post-Quantum Encrypted WebSocket Chat.
 */

(function () {
  let ws = null;
  let currentUsername = "";
  let currentRoom = "lobby";
  let isHandshakeComplete = false;

  // DOM Elements
  const joinModal = document.getElementById("join-modal");
  const joinForm = document.getElementById("join-form");
  const inputUsername = document.getElementById("input-username");
  const inputRoom = document.getElementById("input-room");

  const displayRoomId = document.getElementById("display-room-id");
  const btnCopyRoom = document.getElementById("btn-copy-room");
  const btnClearChat = document.getElementById("btn-clear-chat");
  const btnToggleInspector = document.getElementById("btn-toggle-inspector");
  const btnCloseDrawer = document.getElementById("btn-close-drawer");
  const telemetryDrawer = document.getElementById("telemetry-drawer");

  const statusBeacon = document.getElementById("status-beacon");
  const securityStatusText = document.getElementById("security-status-text");
  const specPeer1 = document.getElementById("spec-peer-1");
  const specPeer2 = document.getElementById("spec-peer-2");

  const messagesViewport = document.getElementById("messages-container");
  const messagesList = document.getElementById("messages-list");
  const chatInput = document.getElementById("chat-input");
  const btnSendMessage = document.getElementById("btn-send-message");
  const toastStack = document.getElementById("toast-stack");

  // Telemetry DOM
  const statEpoch = document.getElementById("stat-epoch");
  const statSeq = document.getElementById("stat-seq");
  const statKemBytes = document.getElementById("stat-kem-bytes");
  const statAeadTag = document.getElementById("stat-aead-tag");

  // Check URL query parameters for auto-join
  const urlParams = new URLSearchParams(window.location.search);
  const paramUser = urlParams.get("user") || urlParams.get("name");
  const paramRoom = urlParams.get("room");

  if (paramRoom) {
    currentRoom = paramRoom;
    inputRoom.value = paramRoom;
    displayRoomId.textContent = paramRoom;
  }
  if (paramUser) {
    inputUsername.value = paramUser;
  }

  // Handle Join Form
  joinForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const user = inputUsername.value.trim();
    const room = inputRoom.value.trim() || "lobby";

    if (!user) return;

    currentUsername = user;
    currentRoom = room;
    displayRoomId.textContent = room;

    joinModal.classList.add("hidden");
    connectWebSocket(room, user);
  });

  // Connect WebSocket
  function connectWebSocket(room, user) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/${encodeURIComponent(room)}/${encodeURIComponent(user)}`;

    showToast(`Connecting to quantum room: ${room}...`);
    ws = new WebSocket(wsUrl);

    ws.onopen = function () {
      showToast("WebSocket connected. Generating ML-DSA-65 identity...");
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
      statusBeacon.className = "status-dot pulsing";
      securityStatusText.textContent = "Disconnected";
      chatInput.disabled = true;
      btnSendMessage.disabled = true;
      showToast("Disconnected from quantum room. Refresh to rejoin.");
    };

    ws.onerror = function (err) {
      console.error("WebSocket error:", err);
    };
  }

  // Handle Inbound Server Events
  function handleServerPayload(data) {
    switch (data.type) {
      case "peer_update":
        handlePeerUpdate(data);
        break;

      case "handshake_success":
        handleHandshakeSuccess(data);
        break;

      case "chat_message":
        renderChatMessage(data);
        break;

      case "chat_cleared":
        handleChatCleared(data);
        break;

      case "error":
        alert(data.message);
        break;
    }
  }

  function handlePeerUpdate(data) {
    if (data.peers && data.peers.length === 1) {
      specPeer1.textContent = `${data.peers[0]} (Local)`;
      specPeer2.textContent = "Waiting for peer to join...";
      statusBeacon.className = "status-dot pulsing";
      securityStatusText.textContent = "Waiting for peer";
    }
    if (data.message) {
      showToast(data.message);
    }
  }

  function handleHandshakeSuccess(data) {
    isHandshakeComplete = true;
    statusBeacon.className = "status-dot active";
    securityStatusText.textContent = "192-bit Quantum Safe (Active)";

    specPeer1.textContent = `${data.peer1.username} [${data.peer1.fingerprint}]`;
    specPeer2.textContent = `${data.peer2.username} [${data.peer2.fingerprint}]`;

    chatInput.disabled = false;
    btnSendMessage.disabled = false;
    chatInput.focus();

    showToast("Quantum Handshake verified! Channel is IND-CCA2 immune.");
  }

  function renderChatMessage(msg) {
    const isMine = msg.sender === currentUsername;
    const row = document.createElement("div");
    row.className = `message-row ${isMine ? "mine" : "peer"}`;

    const header = document.createElement("div");
    header.className = "message-meta-header";
    header.innerHTML = `<span class="sender-name">${escapeHtml(msg.sender)}</span> <span>${msg.timestamp}</span>`;

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = msg.text;

    // PQC Telemetry Badge below message
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

    // Update Live Telemetry Panel
    statEpoch.textContent = meta.epoch;
    statSeq.textContent = meta.seq;
    statKemBytes.textContent = meta.has_kem_rekey ? `${meta.kem_bytes} Bytes` : "Symmetric (0 B)";
    statAeadTag.textContent = `Poly1305 MAC: ${meta.aead_tag}...`;
  }

  // Handle Clear Chat Event (Executed simultaneously on both endpoints)
  function handleChatCleared(data) {
    // 1. Wipe all chat messages from screen
    messagesList.innerHTML = "";

    // 2. Append prominent system notification
    const banner = document.createElement("div");
    banner.className = "system-banner";
    banner.innerHTML = `<strong>CHAT HISTORY CLEARED</strong><br>Permanently zeroized and ratchet advanced by <em>${escapeHtml(data.by)}</em> at ${data.timestamp}.`;
    messagesList.appendChild(banner);

    // 3. Reset telemetry indicators
    statSeq.textContent = "0";
    showToast(`Chat cleared by ${data.by}. Keys rotated.`);
    scrollToBottom();
  }

  // Send Message Logic
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

  // Clear Chat for Both
  btnClearChat.addEventListener("click", function () {
    if (!confirm("Are you sure you want to permanently clear the chat history for BOTH endpoints? This will advance and zeroize all session keys.")) {
      return;
    }
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        action: "clear_chat",
      }));
    }
  });

  // Copy Room Link
  btnCopyRoom.addEventListener("click", function () {
    const url = new URL(window.location.href);
    url.searchParams.set("room", currentRoom);
    url.searchParams.delete("user");
    navigator.clipboard.writeText(url.toString()).then(function () {
      showToast("Room invite link copied to clipboard!");
    }).catch(function () {
      showToast(`Room ID: ${currentRoom}`);
    });
  });

  // Telemetry Drawer Controls
  btnToggleInspector.addEventListener("click", function () {
    telemetryDrawer.classList.toggle("open");
  });
  btnCloseDrawer.addEventListener("click", function () {
    telemetryDrawer.classList.remove("open");
  });

  function scrollToBottom() {
    messagesViewport.scrollTop = messagesViewport.scrollHeight;
  }

  function showToast(text) {
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = text;
    toastStack.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
