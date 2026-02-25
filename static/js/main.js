'use strict';

// Mirrors scanner.py ALLOWED_FLAGS — keep in sync if the server list changes.
const ALLOWED_FLAGS = new Set([
    '-sS', '-sT', '-sU', '-sV', '-sC', '-sn', '-sP',
    '-O', '-A', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5',
    '-p', '-F', '--top-ports', '-Pn', '-n', '-v', '-vv',
    '--open', '--version-intensity',
]);

// Mirrors scanner.py TARGET_PATTERN — only IP, CIDR, and hostname characters.
const TARGET_PATTERN = /^[a-zA-Z0-9.\-:/]+$/;

// ── Helpers ──────────────────────────────────────────────────────────────────

function showError(inputEl, message) {
    clearError(inputEl);
    const err = document.createElement('small');
    err.className = 'form-error';
    err.textContent = message;
    inputEl.parentNode.appendChild(err);
    inputEl.setAttribute('aria-invalid', 'true');
}

function clearError(inputEl) {
    const existing = inputEl.parentNode.querySelector('.form-error');
    if (existing) {
        existing.remove();
    }
    inputEl.removeAttribute('aria-invalid');
}

function validateTarget(value) {
    if (!value.trim()) {
        return 'Target is required.';
    }
    if (value.length > 255) {
        return 'Target must be 255 characters or fewer.';
    }
    if (!TARGET_PATTERN.test(value)) {
        return 'Target contains invalid characters. Use only IP addresses, CIDR ranges, or hostnames.';
    }
    return null;
}

function validateFlags(value) {
    if (!value.trim()) {
        return null;
    }
    const tokens = value.trim().split(/\s+/);
    for (const token of tokens) {
        if (!token.startsWith('-')) {
            continue; // value argument (e.g. port range after -p), skip
        }
        const flagName = token.split('=')[0];
        if (!ALLOWED_FLAGS.has(flagName)) {
            return `Flag not allowed: ${flagName}`;
        }
    }
    return null;
}

// ── Scan form ─────────────────────────────────────────────────────────────────

function initScanForm() {
    const form = document.getElementById('scan-form');
    if (!form) {
        return;
    }

    const targetInput = document.getElementById('target');
    const flagsInput = document.getElementById('flags');

    form.addEventListener('submit', function (event) {
        let valid = true;

        const targetError = validateTarget(targetInput.value);
        if (targetError) {
            showError(targetInput, targetError);
            valid = false;
        } else {
            clearError(targetInput);
        }

        const flagsError = validateFlags(flagsInput.value);
        if (flagsError) {
            showError(flagsInput, flagsError);
            valid = false;
        } else {
            clearError(flagsInput);
        }

        if (!valid) {
            event.preventDefault();
        }
    });
}

// ── Compare form ──────────────────────────────────────────────────────────────

function initCompareForm() {
    const form = document.getElementById('compare-form');
    if (!form) {
        return;
    }

    const scanA = document.getElementById('scan_a');
    const scanB = document.getElementById('scan_b');

    form.addEventListener('submit', function (event) {
        let valid = true;

        if (!scanA.value) {
            showError(scanA, 'Select a baseline scan.');
            valid = false;
        } else {
            clearError(scanA);
        }

        if (!scanB.value) {
            showError(scanB, 'Select a current scan.');
            valid = false;
        } else {
            clearError(scanB);
        }

        if (scanA.value && scanB.value && scanA.value === scanB.value) {
            showError(scanB, 'Select two different scans to compare.');
            valid = false;
        }

        if (!valid) {
            event.preventDefault();
        }
    });
}

// ── Flash dismiss ─────────────────────────────────────────────────────────────

function initFlashDismiss() {
    document.querySelectorAll('.flash').forEach(function (el) {
        el.addEventListener('click', function () {
            el.remove();
        });
    });
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    initScanForm();
    initCompareForm();
    initFlashDismiss();
});
