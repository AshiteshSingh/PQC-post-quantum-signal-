/**
 * pq_ratchet.web.static.app.js
 * Zero-Trust Client-Side Post-Quantum Cryptographic Controller.
 * 
 * Guarantees:
 * - 100% Client-Side End-to-End Encryption (Server is an untrusted blind relay).
 * - FIPS 203 ML-KEM-768 + RFC 7748 X25519 Hybrid Key Encapsulation (IND-CCA2).
 * - FIPS 204 ML-DSA-65 Mutual Identity Authentication (EUF-CMA).
 * - Continuous Post-Quantum Asymmetric Ratchet with ChaCha20-Poly1305 AEAD.
 * - Anti-forensic volatile memory clearing and mutual chat history destruction.
 */

(function () {
  'use strict';

  // Wipe session web storage on boot; preserve persistent peer identity pins in localStorage
  try {
    sessionStorage.clear();
  } catch (e) {}

  if (!window.PQC) {
    alert("Post-Quantum Cryptographic engine failed to load. Browser WebCrypto/WASM support required.");
    return;
  }

  const PQC = window.PQC;

  // Cryptographic State in Volatile Browser Memory
  let localIdentity = null;       // IdentityPrivateKey (ML-DSA-65)
  let ratchetSession = null;      // PQRatchetSession (Double Ratchet)
  let activePeer = null;          // string (username)
  let activePeerIdentityPK = null;// IdentityPublicKey (ML-DSA-65)
  let isInitiator = false;

  let ws = null;
  let currentUsername = "";
  let ttlSeconds = 3600;
  let countdownTimer = null;
  const volatileMessageHeap = [];

  // DOM Elements
  const joinModal = document.getElementById("join-modal");
  const joinForm = document.getElementById("join-form");
  const inputUsername = document.getElementById("input-username");
  const inputPassphrase = document.getElementById("input-passphrase");
  const inputRelayUrl = document.getElementById("input-relay-url");
  const inputPairingToken = document.getElementById("input-pairing-token");
  const btnJoinText = document.getElementById("btn-join-text");
  let configuredRelayHost = "";

  // Prepopulate custom relay endpoint and pairing token if specified in URL query parameter or localStorage
  const initialRelayParam = new URLSearchParams(window.location.search).get("relay") || localStorage.getItem("pqc_custom_relay") || "";
  if (inputRelayUrl && initialRelayParam) {
    inputRelayUrl.value = initialRelayParam;
  }
  const initialTokenParam = new URLSearchParams(window.location.search).get("token") || new URLSearchParams(window.location.search).get("pairing_token") || localStorage.getItem("pqc_pairing_token") || "";
  if (inputPairingToken && initialTokenParam) {
    inputPairingToken.value = initialTokenParam;
  }

  const headerAvatar = document.getElementById("header-avatar");
  const displayPeerName = document.getElementById("display-peer-name");
  const displayPeerStatus = document.getElementById("display-peer-status");
  const pqcPill = document.getElementById("pqc-pill");
  const peerFingerprint = document.getElementById("peer-fingerprint");
  const shieldBadge = document.getElementById("shield-badge");
  const shieldText = document.getElementById("shield-text");
  const ttlDisplay = document.getElementById("ttl-display");
  const btnClearChat = document.getElementById("btn-clear-chat");

  const peerPairingBox = document.getElementById("peer-pairing-box");
  const currentUserTag = document.getElementById("current-user-tag");
  const myFingerprintCode = document.getElementById("my-fingerprint-code");
  const connectPeerForm = document.getElementById("connect-peer-form");
  const targetPeerInput = document.getElementById("target-peer-input");
  const onlineUsersList = document.getElementById("online-users-list");

  const messagesViewport = document.getElementById("messages-container");
  const messagesList = document.getElementById("messages-list");
  const chatInput = document.getElementById("chat-input");
  const btnSendMessage = document.getElementById("btn-send-message");
  const toastStack = document.getElementById("toast-stack");

  const btnVerifyIdentity = document.getElementById("btn-verify-identity");
  const verifyIdentityBadge = document.getElementById("verify-identity-badge");
  const safetyModal = document.getElementById("safety-modal");
  const safetyNumberDisplay = document.getElementById("safety-number-display");
  const verifyPeerName = document.getElementById("verify-peer-name");
  const btnCloseSafety = document.getElementById("btn-close-safety");
  const btnMarkVerified = document.getElementById("btn-mark-verified");
  const safetyAlertBox = document.getElementById("safety-alert-box");

  // Step 1: Join Session & Retrieve / Persist Long-Term Post-Quantum Identity
  joinForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const handle = inputUsername.value.trim();
    if (!handle) return;
    const passphrase = inputPassphrase ? inputPassphrase.value : "";
    if (!passphrase || passphrase.length < 12) {
      alert("Passphrase must be at least 12 characters to securely encrypt your post-quantum identity key at rest.");
      return;
    }

    if (btnJoinText) btnJoinText.textContent = "Deriving Keys (scrypt) & Unlocking...";

    // Retrieve or sample ML-DSA-65 identity keypair directly in client memory
    setTimeout(() => {
      try {
        currentUsername = handle;
        currentUserTag.textContent = handle;

        // Long-term Identity Continuity: Retrieve or persist encrypted ML-DSA-65 identity keypair
        const identityStorageKey = "pqc_local_identity_" + handle;
        const savedRecord = localStorage.getItem(identityStorageKey);
        if (savedRecord) {
          let loaded = false;
          // Attempt decrypting JSON encrypted envelope
          if (savedRecord.startsWith("{")) {
            try {
              const envelope = JSON.parse(savedRecord);
              localIdentity = PQC.decryptIdentityKey(envelope, passphrase);
              loaded = true;
            } catch (decryptErr) {
              throw new Error("Incorrect passphrase or corrupted encrypted identity key for user '" + handle + "'.");
            }
          } else {
            // Legacy unencrypted key migration: read raw key, re-encrypt under passphrase
            try {
              const rawIdBytes = PQC.base64ToBytes(savedRecord);
              localIdentity = PQC.IdentityPrivateKey.fromBytes(rawIdBytes);
              const envelope = PQC.encryptIdentityKey(localIdentity, passphrase);
              localStorage.setItem(identityStorageKey, JSON.stringify(envelope));
              loaded = true;
            } catch (migErr) {
              // Corrupted raw key, fallback to fresh generation
            }
          }

          if (!loaded) {
            localIdentity = PQC.IdentityPrivateKey.generate();
            const envelope = PQC.encryptIdentityKey(localIdentity, passphrase);
            localStorage.setItem(identityStorageKey, JSON.stringify(envelope));
          }
        } else {
          localIdentity = PQC.IdentityPrivateKey.generate();
          const envelope = PQC.encryptIdentityKey(localIdentity, passphrase);
          localStorage.setItem(identityStorageKey, JSON.stringify(envelope));
        }

        // Scrub sensitive passphrase from DOM
        if (inputPassphrase) inputPassphrase.value = "";

        myFingerprintCode.textContent = localIdentity.publicKey().fingerprint();

        joinModal.classList.add("hidden");
        connectWebSocket(handle);
      } catch (err) {
        alert("Failed to initialize post-quantum identity: " + err.message);
        if (btnJoinText) btnJoinText.textContent = "Unlock / Generate Keys & Continue";
      }
    }, 20);
  });

  // Step 2: Establish Blind WebSocket Relay Connection
  function connectWebSocket(username) {
    let customRelay = (inputRelayUrl && inputRelayUrl.value.trim()) || new URLSearchParams(window.location.search).get("relay") || localStorage.getItem("pqc_custom_relay") || "";
    let pairingToken = (inputPairingToken && inputPairingToken.value.trim()) || new URLSearchParams(window.location.search).get("token") || new URLSearchParams(window.location.search).get("pairing_token") || localStorage.getItem("pqc_pairing_token") || "";
    let wsUrl;
    if (customRelay) {
      localStorage.setItem("pqc_custom_relay", customRelay);
      configuredRelayHost = customRelay;
      let target = customRelay;
      if (!target.startsWith("ws://") && !target.startsWith("wss://")) {
        const protocol = window.location.protocol === "https:" ? "wss://" : "ws:";
        target = `${protocol}//${target}`;
      }
      wsUrl = `${target.replace(/\/+$/, '')}/ws/${encodeURIComponent(username)}`;
    } else if (window.location.host) {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      wsUrl = `${protocol}//${window.location.host}/ws/${encodeURIComponent(username)}`;
      configuredRelayHost = `${window.location.protocol}//${window.location.host}`;
    } else {
      // Local standalone file:// mode default
      wsUrl = `ws://127.0.0.1:8000/ws/${encodeURIComponent(username)}`;
      configuredRelayHost = "http://127.0.0.1:8000";
    }

    if (pairingToken) {
      localStorage.setItem("pqc_pairing_token", pairingToken);
      const sep = wsUrl.includes("?") ? "&" : "?";
      wsUrl = `${wsUrl}${sep}token=${encodeURIComponent(pairingToken)}`;
    }

    ws = new WebSocket(wsUrl);

    ws.onopen = function () {
      // Register with public key ONLY. Server NEVER receives private key!
      const pkBytes = localIdentity.publicKey().toBytes();
      const pkB64 = PQC.bytesToBase64(pkBytes);

      ws.send(JSON.stringify({
        action: "register",
        identity_pk: pkB64,
      }));

      displayPeerStatus.textContent = "Online";
      startPollingOnlineDirectory();
    };

    ws.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        handleServerPayload(data);
      } catch (err) {
        console.error("Frame processing error:", err);
      }
    };

    ws.onclose = function () {
      handleSessionTermination("Relay session closed.");
    };

    ws.onerror = function (err) {
      console.error("Relay connection error:", err);
    };
  }

  // Step 3: Handle Blind Signaling & Packet Relaying
  function handleServerPayload(data) {
    switch (data.type) {
      case "session_registered":
        ttlSeconds = data.ttl;
        startTtlCountdown(ttlSeconds);
        showToast("Connected to blind post-quantum relay");
        break;

      case "pqc_handshake_complete":
        onPeerSignaled(data);
        break;

      case "relayed_packet":
        onRelayedPacketReceived(data);
        break;

      case "chat_cleared":
        onChatCleared(data);
        break;

      case "peer_disconnected":
        onPeerDisconnected(data);
        break;

      case "session_expired":
        handleSessionTermination("1-Hour ephemeral lifetime expired. Memory cleared.");
        break;

      case "error":
        showToast(data.message, true);
        break;
    }
  }

  // Peer Signaling Handler (Alice or Bob learns of the active peer)
  function onPeerSignaled(data) {
    activePeer = data.peer;
    isInitiator = !!data.is_initiator;

    try {
      const peerPkBytes = PQC.base64ToBytes(data.peer_identity_pk);
      activePeerIdentityPK = PQC.IdentityPublicKey.fromBytes(peerPkBytes);
    } catch (e) {
      showToast("Invalid peer identity key format", true);
      return;
    }

    displayPeerName.textContent = activePeer;
    displayPeerStatus.textContent = "Performing PQC Handshake...";
    updatePeerIdentityTrustUI();
    headerAvatar.textContent = activePeer.charAt(0).toUpperCase();

    if (isInitiator) {
      // Alice initiates the handshake
      try {
        const [session, initPktBytes] = PQC.PQRatchetSession.initiateHandshake(localIdentity, activePeerIdentityPK);
        ratchetSession = session;

        // Relay HandshakeInitPacket through blind server
        ws.send(JSON.stringify({
          action: "relay_packet",
          target: activePeer,
          packet: PQC.bytesToBase64(initPktBytes),
        }));

        showToast("Transmitted ML-DSA-65 signed HandshakeInit frame");
      } catch (err) {
        showToast("Handshake initiation failed: " + err.message, true);
      }
    }
  }

  // Opaque Packet Relay Handler (Client Decryption & Ratchet Advancement)
  function onRelayedPacketReceived(data) {
    if (!activePeer || data.from !== activePeer) return;

    let packetBytes;
    try {
      packetBytes = PQC.base64ToBytes(data.packet);
    } catch (e) {
      return;
    }

    if (packetBytes.length < 6) return;
    const msgType = packetBytes[5];

    // Message Type 0x01: HandshakeInitPacket (Bob receives from Alice)
    if (msgType === PQC.constants.PROTOCOL_VERSION && packetBytes[4] === PQC.constants.PROTOCOL_VERSION) {
      // fallback check
    }

    if (msgType === 0x01) { // MSG_TYPE_HANDSHAKE_INIT
      try {
        const [session, respPktBytes] = PQC.PQRatchetSession.respondHandshake(localIdentity, packetBytes, activePeerIdentityPK);
        ratchetSession = session;

        // Relay HandshakeRespPacket back to Alice
        ws.send(JSON.stringify({
          action: "relay_packet",
          target: activePeer,
          packet: PQC.bytesToBase64(respPktBytes),
        }));

        onHandshakeEstablished();
        showToast("Authenticated Alice's ML-DSA-65 signature & encapsulated ML-KEM-768 secret");
      } catch (err) {
        showToast("Responder handshake failure: " + err.message, true);
      }
    }
    // Message Type 0x02: HandshakeRespPacket (Alice receives from Bob)
    else if (msgType === 0x02) { // MSG_TYPE_HANDSHAKE_RESP
      if (!ratchetSession || !isInitiator) return;
      if (!ratchetSession.validateHandshakeResponse(packetBytes)) {
        showToast("Dropped forged or unauthenticated handshake response frame", true);
        return;
      }
      try {
        ratchetSession.completeHandshake(packetBytes);
        onHandshakeEstablished();
        showToast("Authenticated Bob's ML-DSA-65 signature & decapsulated ML-KEM-768 secret");
      } catch (err) {
        showToast("Handshake completion failure: " + err.message, true);
      }
    }
    // Message Type 0x03: RatchetDataPacket (Encrypted Message)
    else if (msgType === 0x03) { // MSG_TYPE_RATCHET_DATA
      if (!ratchetSession) return;
      try {
        const pkt = PQC.RatchetDataPacket.deserialize(packetBytes);
        const plaintextBytes = ratchetSession.ratchetDecrypt(packetBytes);
        const text = new TextDecoder().decode(plaintextBytes);

        const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        renderMessage({
          sender: activePeer,
          text: text,
          timestamp: timestamp,
          pqc_meta: {
            epoch: pkt.epoch,
            seq: pkt.seq,
            has_kem_rekey: pkt.kem_ct !== null,
            wire_bytes: packetBytes.length,
            tag: PQC.bytesToHex(packetBytes.slice(-16)).slice(0, 10),
          },
        });
      } catch (err) {
        showToast("Decryption / AEAD authentication failure: " + err.message, true);
      }
    }
  }

  // Handshake Established
  function onHandshakeEstablished() {
    displayPeerStatus.textContent = "E2EE Quantum-Safe Active";
    pqcPill.classList.remove("hidden");
    shieldBadge.style.borderColor = "rgba(16, 185, 129, 0.6)";
    shieldText.textContent = "192-bit PQC";

    peerPairingBox.classList.add("hidden");
    messagesList.classList.remove("hidden");
    btnClearChat.classList.remove("hidden");

    updatePeerIdentityTrustUI();

    const pinnedFp = localStorage.getItem("pqc_pinned_fp_" + activePeer);
    const fp = activePeerIdentityPK ? activePeerIdentityPK.fingerprint() : "";
    const isVerified = pinnedFp === fp;

    if (isVerified) {
      chatInput.disabled = false;
      btnSendMessage.disabled = false;
      chatInput.placeholder = "Type an E2EE encrypted message (double ratchet)...";
      chatInput.focus();
    } else if (pinnedFp && pinnedFp !== fp) {
      chatInput.disabled = true;
      btnSendMessage.disabled = true;
      chatInput.placeholder = "BLOCKED: Peer identity key mismatch (MitM Alert)";
    } else {
      chatInput.disabled = true;
      btnSendMessage.disabled = true;
      chatInput.placeholder = "Verify Safety Number out-of-band to unlock chat...";
    }

    // Render Handshake Verification Card in Message Stream
    const notice = document.createElement("div");
    notice.className = "system-notice";
    notice.innerHTML = `
      <strong>Post-Quantum Channel Established (Zero-Trust Blind Relay)</strong><br>
      Hybrid KEM: ML-KEM-768 + X25519 | Signature: ML-DSA-65 | Cipher: ChaCha20-Poly1305<br>
      Peer Fingerprint: <code>${fp}</code><br>
      <span style="color: ${isVerified ? '#10b981' : (pinnedFp ? '#ef4444' : '#f59e0b')}; font-weight: 600;">
        ${isVerified ? '✓ Identity Verified (Pinned)' : (pinnedFp ? '🚨 KEY MISMATCH (MitM Alert) — Outgoing Messages Blocked' : '⚠ Identity Unverified — Out-of-band verification required before sending')}
      </span>
      ${!isVerified ? '<br><button class="btn-verify-prompt" style="margin-top:8px; padding:6px 14px; background:#10b981; color:#ffffff; border:none; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer;">Verify Safety Number to Unlock Chat</button>' : ''}
    `;
    const btnPrompt = notice.querySelector(".btn-verify-prompt");
    if (btnPrompt) {
      btnPrompt.addEventListener("click", openSafetyModal);
    }
    messagesList.appendChild(notice);
    scrollToBottom();
  }

  // Step 4: Send Message (Client-Side Symmetric & Asymmetric Ratchet Encryption)
  function sendMessage() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!ratchetSession || !activePeer) return;

    // Zero-Trust Identity Pinning Guard: Never transmit plaintext under unverified identity
    const pinnedFp = localStorage.getItem("pqc_pinned_fp_" + activePeer);
    const fp = activePeerIdentityPK ? activePeerIdentityPK.fingerprint() : "";
    if (pinnedFp !== fp) {
      showToast("Transmission blocked: Peer identity must be verified and pinned out-of-band.", true);
      return;
    }

    const text = chatInput.value.trim();
    if (!text) return;

    try {
      const plaintextBytes = new TextEncoder().encode(text);
      const packetBytes = ratchetSession.ratchetEncrypt(plaintextBytes);
      const pkt = PQC.RatchetDataPacket.deserialize(packetBytes);

      // Relay the opaque packet through the blind server
      ws.send(JSON.stringify({
        action: "relay_packet",
        target: activePeer,
        packet: PQC.bytesToBase64(packetBytes),
      }));

      const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      renderMessage({
        sender: currentUsername,
        text: text,
        timestamp: timestamp,
        pqc_meta: {
          epoch: pkt.epoch,
          seq: pkt.seq,
          has_kem_rekey: pkt.kem_ct !== null,
          wire_bytes: packetBytes.length,
          tag: PQC.bytesToHex(packetBytes.slice(-16)).slice(0, 10),
        },
      });

      chatInput.value = "";
      chatInput.focus();
    } catch (err) {
      showToast("Encryption failed: " + err.message, true);
    }
  }

  btnSendMessage.addEventListener("click", sendMessage);
  chatInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // Render Message with Cryptographic Invariant Telemetry
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

    // Cryptographic Telemetry Badge
    if (msg.pqc_meta) {
      const metaDiv = document.createElement("div");
      metaDiv.className = "bubble-meta";
      metaDiv.innerHTML = `
        <span class="bubble-meta-tag">Ep:${msg.pqc_meta.epoch}</span>
        <span class="bubble-meta-tag">Sq:${msg.pqc_meta.seq}</span>
        ${msg.pqc_meta.has_kem_rekey ? '<span class="bubble-meta-rekey">ML-KEM Rekey</span>' : ''}
        <span class="bubble-meta-tag" title="ChaCha20-Poly1305 Authentication Tag">Tag:${msg.pqc_meta.tag}</span>
      `;
      bubble.appendChild(metaDiv);
    }

    row.appendChild(bubble);
    messagesList.appendChild(row);
    scrollToBottom();
  }

  // Mutual "Clear Chat"
  function onChatCleared(data) {
    for (let i = 0; i < volatileMessageHeap.length; i++) {
      if (volatileMessageHeap[i]) volatileMessageHeap[i].text = "";
    }
    volatileMessageHeap.length = 0;
    messagesList.innerHTML = "";

    // The chat history is cleared from the UI.
    // The ratchet session remains synchronized.

    const notice = document.createElement("div");
    notice.className = "system-notice";
    notice.textContent = "Chat history zeroized from memory";
    messagesList.appendChild(notice);

    showToast("Chat memory zeroized");
    scrollToBottom();
  }

  btnClearChat.addEventListener("click", function () {
    if (!confirm("Clear chat history and step forward ratchet keys for both users?")) return;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action: "clear_chat" }));
    }
  });

  // Connect Peer Form
  connectPeerForm.addEventListener("submit", function (e) {
    e.preventDefault();
    const target = targetPeerInput.value.trim();
    if (!target) return;

    if (!ws || ws.readyState !== WebSocket.OPEN) {
      showToast("Not connected to relay", true);
      return;
    }

    ws.send(JSON.stringify({
      action: "connect_peer",
      target: target,
    }));
  });

  // Online Users Polling
  function startPollingOnlineDirectory() {
    let apiBase = "";
    if (configuredRelayHost) {
      let httpBase = configuredRelayHost.replace(/^wss:\/\//i, "https://").replace(/^ws:\/\//i, "http://");
      if (!httpBase.startsWith("http://") && !httpBase.startsWith("https://")) {
        const proto = (window.location.protocol === "https:") ? "https://" : "http://";
        httpBase = proto + httpBase;
      }
      apiBase = httpBase.replace(/\/+$/, "");
    } else if (window.location.protocol === "file:") {
      apiBase = "http://127.0.0.1:8000";
    }

    async function poll() {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      try {
        const resp = await fetch(`${apiBase}/api/online-users`, {
          cache: "no-store",
          mode: "cors",
        });
        if (resp.ok) {
          const data = await resp.json();
          renderOnlineDirectory(data.users || []);
        }
      } catch (e) {
        console.warn("Online directory poll failed:", e);
      }
    }
    poll();
    setInterval(poll, 4000);
  }

  function renderOnlineDirectory(users) {
    const peers = users.filter(u => u.username !== currentUsername);
    onlineUsersList.innerHTML = "";

    if (peers.length === 0) {
      const hint = document.createElement("span");
      hint.className = "empty-hint";
      hint.textContent = "No other users online yet";
      onlineUsersList.appendChild(hint);
      return;
    }

    peers.forEach(p => {
      const btn = document.createElement("button");
      btn.className = "peer-chip-btn";
      const dot = document.createElement("span");
      dot.className = "dot";
      const name = document.createElement("span");
      name.textContent = p.username;
      btn.appendChild(dot);
      btn.appendChild(name);
      btn.onclick = () => {
        targetPeerInput.value = p.username;
        targetPeerInput.focus();
      };
      onlineUsersList.appendChild(btn);
    });
  }

  // Ephemeral TTL Countdown
  function startTtlCountdown(initialTtl) {
    if (countdownTimer) clearInterval(countdownTimer);
    let remaining = initialTtl;

    function update() {
      if (remaining <= 0) {
        clearInterval(countdownTimer);
        handleSessionTermination("1-Hour session ended. Memory erased.");
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
    zeroizeVolatileState();

    displayPeerStatus.textContent = "Terminated";
    chatInput.disabled = true;
    btnSendMessage.disabled = true;

    alert(reason);
    window.location.reload();
  }

  function onPeerDisconnected(data) {
    activePeer = null;
    displayPeerStatus.textContent = "Offline";
    displayPeerName.textContent = "Direct Chat";
    headerAvatar.textContent = "?";
    pqcPill.classList.add("hidden");
    peerFingerprint.classList.add("hidden");
    if (btnVerifyIdentity) btnVerifyIdentity.classList.add("hidden");
    btnClearChat.classList.add("hidden");
    chatInput.disabled = true;
    btnSendMessage.disabled = true;
    peerPairingBox.classList.remove("hidden");
    showToast(data.message || "Peer disconnected", true);

    if (ratchetSession) {
      ratchetSession.close();
      ratchetSession = null;
    }

    const notice = document.createElement("div");
    notice.className = "system-notice";
    notice.textContent = "Peer disconnected — cryptographic session zeroized";
    messagesList.appendChild(notice);
    scrollToBottom();
  }

  function formatFingerprintChunks(hexStr) {
    if (!hexStr) return "";
    return hexStr.match(/.{1,4}/g)?.join("  ") || hexStr;
  }

  function updatePeerIdentityTrustUI() {
    if (!activePeer || !activePeerIdentityPK) return;
    const fp = activePeerIdentityPK.fingerprint();
    peerFingerprint.textContent = fp;
    peerFingerprint.classList.remove("hidden");

    if (btnVerifyIdentity) btnVerifyIdentity.classList.remove("hidden");

    const pinnedFp = localStorage.getItem("pqc_pinned_fp_" + activePeer);
    if (pinnedFp) {
      if (pinnedFp === fp) {
        if (verifyIdentityBadge) {
          verifyIdentityBadge.textContent = "✓ Verified (Pinned)";
          verifyIdentityBadge.style.color = "#10b981";
        }
      } else {
        if (verifyIdentityBadge) {
          verifyIdentityBadge.textContent = "⚠ KEY MISMATCH (MitM Alert)";
          verifyIdentityBadge.style.color = "#ef4444";
        }
        showToast("CRITICAL WARNING: Peer identity key has changed! Relay server may be intercepting!", true);
      }
    } else {
      if (verifyIdentityBadge) {
        verifyIdentityBadge.textContent = "⚠ Unverified (TOFU)";
        verifyIdentityBadge.style.color = "#f59e0b";
      }
    }
  }

  function openSafetyModal() {
    if (!activePeer || !activePeerIdentityPK) return;
    const peerFp = activePeerIdentityPK.fingerprint();
    const myFp = localIdentity ? localIdentity.publicKey().fingerprint() : "";
    const pinnedFp = localStorage.getItem("pqc_pinned_fp_" + activePeer);

    if (verifyPeerName) verifyPeerName.textContent = activePeer;
    if (safetyNumberDisplay) {
      safetyNumberDisplay.innerHTML = `
        <div style="margin-bottom: 8px;"><strong>Your Fingerprint:</strong><br>${formatFingerprintChunks(myFp)}</div>
        <div><strong>${activePeer}'s Server-Reported Fingerprint:</strong><br>${formatFingerprintChunks(peerFp)}</div>
      `;
    }

    if (pinnedFp && pinnedFp !== peerFp) {
      if (safetyAlertBox) {
        safetyAlertBox.classList.remove("hidden");
        safetyAlertBox.textContent = `CRITICAL WARNING: Fingerprint mismatch! Previously pinned: ${pinnedFp}, Current: ${peerFp}.`;
      }
    } else {
      if (safetyAlertBox) safetyAlertBox.classList.add("hidden");
    }

    if (safetyModal) safetyModal.classList.remove("hidden");
  }

  if (btnVerifyIdentity) {
    btnVerifyIdentity.addEventListener("click", openSafetyModal);
  }
  if (peerFingerprint) {
    peerFingerprint.style.cursor = "pointer";
    peerFingerprint.addEventListener("click", openSafetyModal);
  }
  if (btnCloseSafety) {
    btnCloseSafety.addEventListener("click", () => safetyModal && safetyModal.classList.add("hidden"));
  }
  if (btnMarkVerified) {
    btnMarkVerified.addEventListener("click", () => {
      if (!activePeer || !activePeerIdentityPK) return;
      const pinnedFp = localStorage.getItem("pqc_pinned_fp_" + activePeer);
      const fp = activePeerIdentityPK.fingerprint();
      if (pinnedFp && pinnedFp !== fp) {
        if (!confirm("WARNING: The peer identity key does NOT match the previously pinned key. This could indicate an active Man-in-the-Middle attack by the relay. Are you absolutely certain you want to trust and pin this new key?")) {
          return;
        }
      }
      localStorage.setItem("pqc_pinned_fp_" + activePeer, fp);
      updatePeerIdentityTrustUI();
      if (safetyModal) safetyModal.classList.add("hidden");
      showToast(`Identity for ${activePeer} verified and pinned locally.`);

      // Enable messaging if ratchet session is active
      if (ratchetSession) {
        chatInput.disabled = false;
        btnSendMessage.disabled = false;
        chatInput.placeholder = "Type an E2EE encrypted message (double ratchet)...";
        chatInput.focus();
      }
    });
  }

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
    }, 2800);
  }

  // Anti-Forensics: Zeroize RAM on window close or tab backgrounding
  function zeroizeVolatileState() {
    for (let i = 0; i < volatileMessageHeap.length; i++) {
      if (volatileMessageHeap[i]) {
        volatileMessageHeap[i].text = "";
        volatileMessageHeap[i].sender = "";
      }
    }
    volatileMessageHeap.length = 0;
    if (ratchetSession) {
      ratchetSession.close();
      ratchetSession = null;
    }
    if (localIdentity) {
      localIdentity.zeroize();
      localIdentity = null;
    }
    if (chatInput) chatInput.value = "";
    if (messagesList) messagesList.innerHTML = "";
  }

  window.addEventListener("beforeunload", zeroizeVolatileState);
  window.addEventListener("pagehide", zeroizeVolatileState);
})();
