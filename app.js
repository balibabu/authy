const STORAGE_KEY = 'auth_keys_data';
const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;

let keys = [];
let lastCounter = -1;

const cardsList = document.getElementById('cardsList');
const modal = document.getElementById('modal');
const openModalBtn = document.getElementById('openModalBtn');
const cancelModalBtn = document.getElementById('cancelModalBtn');
const addForm = document.getElementById('addForm');
const secretInput = document.getElementById('secretInput');
const toast = document.getElementById('toast');

function getStoredKeys() {
    const now = Date.now();
    let stored = [];
    try {
        stored = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
    } catch {
        stored = [];
    }
    const valid = stored.filter(item => (now - (item.updated || now)) < SEVEN_DAYS);
    valid.forEach(item => item.updated = now);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(valid));
    return valid;
}

function saveKeys() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

function base32ToBytes(str) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = str.replace(/[\s=-]/g, '').toUpperCase();
    let bits = 0;
    let val = 0;
    const bytes = [];
    for (let i = 0; i < cleaned.length; i++) {
        const idx = alphabet.indexOf(cleaned[i]);
        if (idx === -1) continue;
        val = (val << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((val >>> bits) & 0xff);
        }
    }
    return new Uint8Array(bytes);
}

async function generateTOTP(secret, counter) {
    try {
        const keyBytes = base32ToBytes(secret);
        if (keyBytes.length === 0) return '------';
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        view.setUint32(0, Math.floor(counter / 0x100000000), false);
        view.setUint32(4, counter >>> 0, false);
        const sig = await crypto.subtle.sign('HMAC', cryptoKey, buffer);
        const hmac = new Uint8Array(sig);
        const offset = hmac[hmac.length - 1] & 0x0f;
        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);
        return (code % 1000000).toString().padStart(6, '0');
    } catch {
        return '------';
    }
}

function formatOTP(otp) {
    if (otp.length === 6) {
        return `${otp.slice(0, 3)} ${otp.slice(3)}`;
    }
    return otp;
}

function showToast() {
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1500);
}

async function updateCardOTPs(cardElement, secret, counter) {
    const currentOTP = await generateTOTP(secret, counter);
    const upcomingOTP = await generateTOTP(secret, counter + 1);

    const currentEl = cardElement.querySelector('.otp-current');
    const upcomingEl = cardElement.querySelector('.otp-upcoming');

    if (currentEl) currentEl.textContent = formatOTP(currentOTP);
    if (upcomingEl) upcomingEl.textContent = `NEXT ${formatOTP(upcomingOTP)}`;
}

function renderCards() {
    cardsList.innerHTML = '';

    if (keys.length === 0) {
        cardsList.innerHTML = '<div class="empty-state">No keys added</div>';
        return;
    }

    const counter = Math.floor(Date.now() / 1000 / 30);

    keys.forEach((item, index) => {
        const card = document.createElement('div');
        card.className = 'card';
        card.dataset.id = item.id;

        const formattedSerial = `#${(index + 1).toString().padStart(2, '0')}`;

        card.innerHTML = `
            <div class="card-header">
                <span class="serial">${formattedSerial}</span>
                <button class="delete-btn">&times;</button>
            </div>
            <div class="otp-current">------</div>
            <div class="otp-upcoming">NEXT ------</div>
            <div class="progress-container">
                <div class="progress-bar"></div>
            </div>
        `;

        card.querySelector('.delete-btn').addEventListener('click', () => {
            keys = keys.filter(k => k.id !== item.id);
            saveKeys();
            renderCards();
        });

        card.querySelector('.otp-current').addEventListener('click', (e) => {
            const raw = e.currentTarget.textContent.replace(/\s+/g, '');
            if (raw && raw !== '------') {
                navigator.clipboard.writeText(raw).then(showToast);
            }
        });

        cardsList.appendChild(card);
        updateCardOTPs(card, item.secret, counter);
    });
}

function tick() {
    const now = Date.now();
    const sec = Math.floor(now / 1000);
    const ms = now % 1000;
    const currentCounter = Math.floor(sec / 30);
    const remainingTime = 30 - (sec % 30) - (ms / 1000);
    const progressPct = (remainingTime / 30) * 100;

    document.querySelectorAll('.progress-bar').forEach(bar => {
        bar.style.width = `${progressPct}%`;
    });

    if (currentCounter !== lastCounter) {
        lastCounter = currentCounter;
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            const id = card.dataset.id;
            const keyItem = keys.find(k => k.id === id);
            if (keyItem) {
                updateCardOTPs(card, keyItem.secret, currentCounter);
            }
        });
    }

    requestAnimationFrame(tick);
}

function openModal() {
    secretInput.value = '';
    modal.classList.add('open');
    secretInput.focus();
}

function closeModal() {
    modal.classList.remove('open');
    secretInput.value = '';
}

openModalBtn.addEventListener('click', openModal);
cancelModalBtn.addEventListener('click', closeModal);

modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
});

addForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const rawSecret = secretInput.value.replace(/[\s=-]/g, '').toUpperCase();
    if (!rawSecret) return;

    keys.push({
        id: Date.now().toString(36) + Math.random().toString(36).substring(2, 7),
        secret: rawSecret,
        updated: Date.now()
    });

    saveKeys();
    closeModal();
    renderCards();
});

keys = getStoredKeys();
renderCards();
requestAnimationFrame(tick);
