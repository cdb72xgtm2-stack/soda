const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// ── HTTP server ───────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const filePath = path.join(__dirname, 'public', 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(data);
  });
});

// ── WebSocket server ──────────────────────────────────────────────
const wss = new WebSocketServer({ server });

// rooms: { [roomId]: { id, name, hostId, hostName, hasPassword, passwordHash, salt, clients: Set<ws> } }
const rooms = {};
const clientMeta = new WeakMap(); // ws → { id, username, flair, color, roomId }

// ── Crypto helpers ────────────────────────────────────────────────
// The client sends SHA-256(roomId + "::soda::" + rawPassword) so the
// plaintext password never touches the network. The server then runs
// PBKDF2 over that client-hash + a random salt, so even if the DB
// were dumped the hashes couldn't be reversed cheaply.
function serverHash(clientHash, salt) {
  return crypto.pbkdf2Sync(clientHash, salt, 120_000, 32, 'sha256').toString('hex');
}
function makeSalt() {
  return crypto.randomBytes(32).toString('hex');
}

function send(ws, msg) {
  if (ws.readyState === 1) ws.send(JSON.stringify(msg));
}

function broadcast(roomId, msg, excludeWs = null) {
  const room = rooms[roomId];
  if (!room) return;
  const str = JSON.stringify(msg);
  room.clients.forEach(ws => {
    if (ws !== excludeWs && ws.readyState === 1) ws.send(str);
  });
}

function getLobbyList() {
  return Object.values(rooms).map(r => ({
    id: r.id, name: r.name,
    hostId: r.hostId, hostName: r.hostName,
    hasPassword: r.hasPassword,
    count: r.clients.size,
  }));
}

function broadcastLobbyList() {
  const msg = JSON.stringify({ type: 'LOBBY_LIST', lobbies: getLobbyList() });
  wss.clients.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

function leaveRoom(ws, roomId) {
  const room = rooms[roomId];
  if (!room) return;
  const meta = clientMeta.get(ws);
  room.clients.delete(ws);
  if (meta) clientMeta.set(ws, { ...meta, roomId: null });
  if (room.clients.size === 0) {
    delete rooms[roomId];
  } else {
    broadcast(roomId, { type: 'PLAYER_LEAVE', playerId: meta?.id });
  }
  broadcastLobbyList();
}

function joinRoom(ws, roomId, player) {
  const room = rooms[roomId];
  const prevMeta = clientMeta.get(ws);
  if (prevMeta?.roomId && prevMeta.roomId !== roomId) leaveRoom(ws, prevMeta.roomId);

  room.clients.add(ws);
  clientMeta.set(ws, { id: player.id, username: player.username, flair: player.flair, color: player.color, roomId });

  send(ws, { type: 'JOINED', roomId, roomName: room.name });
  broadcast(roomId, { type: 'PLAYER_JOIN', player }, ws);
  broadcast(roomId, { type: 'STATE_REQUEST', requesterId: player.id }, ws);
  broadcastLobbyList();
}

// ── Connection handler ────────────────────────────────────────────
wss.on('connection', (ws) => {
  send(ws, { type: 'LOBBY_LIST', lobbies: getLobbyList() });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'CREATE_LOBBY': {
        const { roomId, roomName, player, clientHash } = msg;
        if (rooms[roomId]) { send(ws, { type: 'ERROR', text: 'Room ID collision — try again.' }); return; }

        let passwordHash = null, salt = null, hasPassword = false;
        if (clientHash) {
          salt = makeSalt();
          passwordHash = serverHash(clientHash, salt);
          hasPassword = true;
        }

        rooms[roomId] = {
          id: roomId, name: roomName,
          hostId: player.id, hostName: player.username,
          hasPassword, passwordHash, salt,
          clients: new Set(),
        };

        joinRoom(ws, roomId, player);
        break;
      }

      case 'JOIN_LOBBY': {
        const { roomId, player, clientHash } = msg;
        const room = rooms[roomId];
        if (!room) { send(ws, { type: 'ERROR', text: 'Room not found.' }); return; }
        if (room.clients.size >= 6) { send(ws, { type: 'ERROR', text: 'Room is full (6/6).' }); return; }

        if (room.hasPassword) {
          if (!clientHash) { send(ws, { type: 'NEED_PASSWORD', roomId }); return; }
          const attempt = serverHash(clientHash, room.salt);
          if (attempt !== room.passwordHash) {
            send(ws, { type: 'WRONG_PASSWORD', roomId });
            return;
          }
        }

        joinRoom(ws, roomId, player);
        break;
      }

      case 'PLAYER_STATE': {
        const meta = clientMeta.get(ws);
        if (meta?.roomId) broadcast(meta.roomId, msg, ws);
        break;
      }

      case 'STATE_RESPONSE': {
        const { targetId } = msg;
        const meta = clientMeta.get(ws);
        if (!meta?.roomId) return;
        rooms[meta.roomId]?.clients.forEach(client => {
          if (clientMeta.get(client)?.id === targetId) send(client, msg);
        });
        break;
      }

      case 'SPEED_CHANGE':
      case 'FLAIR_UPDATE': {
        const meta = clientMeta.get(ws);
        if (meta?.roomId) broadcast(meta.roomId, msg, ws);
        break;
      }

      case 'CHAT': {
        const meta = clientMeta.get(ws);
        if (meta?.roomId) broadcast(meta.roomId, msg, ws);
        break;
      }

      case 'LEAVE': {
        const meta = clientMeta.get(ws);
        if (meta?.roomId) leaveRoom(ws, meta.roomId);
        send(ws, { type: 'LOBBY_LIST', lobbies: getLobbyList() });
        break;
      }
    }
  });

  ws.on('close', () => {
    const meta = clientMeta.get(ws);
    if (meta?.roomId) leaveRoom(ws, meta.roomId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🥤 Soda Shake running on :${PORT}`));
