
// ── Global Custom Modal / Dialogs ──────────────────────────────────────────
let _rkGlobalModalInstance = null;

function _initRkModal() {
    let modalEl = document.getElementById('rkGlobalModal');
    if (!modalEl) {
        document.body.insertAdjacentHTML('beforeend', `
        <div class="modal fade" id="rkGlobalModal" tabindex="-1" aria-hidden="true" style="backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); z-index: 1055;">
          <div class="modal-dialog modal-dialog-centered" style="max-width: 420px;">
            <div class="modal-content" style="background: var(--rk-surface, transparent); color: var(--rk-text, #E6EDF3); border: 1px solid var(--rk-border, #30363d); border-radius: 16px; box-shadow: 0 16px 48px rgba(0,0,0,0.5);">
              <div class="modal-header align-items-center border-0" style="padding: 1.5rem 1.5rem 0.5rem;">
                <div class="d-flex align-items-center gap-3">
                  <div id="rkGlobalModalIconBox" style="width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.25rem;">
                    <i id="rkGlobalModalIcon"></i>
                  </div>
                  <h5 class="modal-title fw-bold m-0" id="rkGlobalModalTitle" style="color: var(--rk-text, #fff); font-size: 18px; letter-spacing: -0.3px;"></h5>
                </div>
              </div>
              <div class="modal-body fs-14" id="rkGlobalModalBody" style="padding: 1rem 1.5rem 1.5rem; color: var(--rk-text-muted, #8b949e); line-height: 1.5;">
              </div>
              <div class="modal-footer border-0" style="padding: 0 1.5rem 1.5rem; justify-content: flex-end; gap: 8px;">
                <button type="button" class="rk-btn" style="background: transparent; color: var(--rk-text-muted, #8b949e); padding: 8px 16px; border: 1px solid var(--rk-border, #30363d); font-weight: 500;" data-bs-dismiss="modal" id="rkGlobalModalCancel">Cancel</button>
                <button type="button" class="rk-btn" id="rkGlobalModalConfirm" style="padding: 8px 20px; font-weight: 600; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">Confirm</button>
              </div>
            </div>
          </div>
        </div>`);
        modalEl = document.getElementById('rkGlobalModal');
    }
    
    // Safety check for Bootstrap
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        if (!_rkGlobalModalInstance) {
            _rkGlobalModalInstance = new bootstrap.Modal(modalEl, { backdrop: 'static', keyboard: false });
        }
        return _rkGlobalModalInstance;
    } else {
        // Fallback for login.html which might not have bootstrap JS running
        return {
            show: () => {
                modalEl.classList.add('show');
                modalEl.style.display = 'block';
                document.body.insertAdjacentHTML('beforeend', '<div class="modal-backdrop fade show" id="rkModalBackdrop" style="backdrop-filter: blur(8px);"></div>');
            },
            hide: () => {
                modalEl.classList.remove('show');
                modalEl.style.display = 'none';
                const backdrop = document.getElementById('rkModalBackdrop');
                if (backdrop) backdrop.remove();
            }
        };
    }
}

function rkConfirm(message, title = 'Confirm Action', isDestructive = false) {
    return new Promise((resolve) => {
        const modal = _initRkModal();
        const el = document.getElementById('rkGlobalModal');
        
        document.getElementById('rkGlobalModalTitle').textContent = title;
        document.getElementById('rkGlobalModalBody').innerHTML = message;
        
        const iconBox = document.getElementById('rkGlobalModalIconBox');
        const icon = document.getElementById('rkGlobalModalIcon');
        const confirmBtn = document.getElementById('rkGlobalModalConfirm');
        const cancelBtn = document.getElementById('rkGlobalModalCancel');
        
        cancelBtn.style.display = 'inline-block';
        cancelBtn.textContent = 'Cancel';
        confirmBtn.textContent = isDestructive ? 'Delete' : 'Confirm';
        
        if (isDestructive) {
            iconBox.style.background = 'rgba(220, 38, 38, 0.15)'; // red light
            icon.className = 'bi bi-exclamation-triangle-fill text-danger';
            confirmBtn.style.background = '#DC2626';
            confirmBtn.style.color = '#FFF';
            confirmBtn.style.border = '1px solid #DC2626';
        } else {
            iconBox.style.background = 'rgba(249, 187, 26, 0.15)'; // yellow/accent
            icon.className = 'bi bi-question-circle-fill text-warning';
            confirmBtn.style.background = 'var(--rk-accent, #A3112E)';
            confirmBtn.style.color = '#FFF';
            confirmBtn.style.border = 'none';
        }

        const handleConfirm = () => { cleanup(); resolve(true); modal.hide(); };
        const handleCancel = () => { cleanup(); resolve(false); modal.hide(); };
        
        // Remove existing listeners by cloning node if necessary, but we can just override onclick since we only have one global modal instance
        confirmBtn.onclick = handleConfirm;
        cancelBtn.onclick = handleCancel;
        
        // Also handle the backdrop click / escape key closure (if using custom modal logic)
        const cleanup = () => {
            confirmBtn.onclick = null;
            cancelBtn.onclick = null;
        };
        modal.show();
    });
}

function rkAlert(message, title = 'Information', type = 'info') {
    return new Promise((resolve) => {
        const modal = _initRkModal();
        const el = document.getElementById('rkGlobalModal');
        
        document.getElementById('rkGlobalModalTitle').textContent = title;
        document.getElementById('rkGlobalModalBody').innerHTML = message;
        
        const iconBox = document.getElementById('rkGlobalModalIconBox');
        const icon = document.getElementById('rkGlobalModalIcon');
        const confirmBtn = document.getElementById('rkGlobalModalConfirm');
        const cancelBtn = document.getElementById('rkGlobalModalCancel');
        
        cancelBtn.style.display = 'none';
        confirmBtn.textContent = 'OK';
        confirmBtn.style.background = 'var(--rk-accent-bg, #f9bb1a)';
        confirmBtn.style.color = '#FFF';
        confirmBtn.style.border = 'none';

        if (type === 'success') {
            iconBox.style.background = 'rgba(34, 197, 94, 0.15)'; // green light
            icon.className = 'bi bi-check-circle-fill text-success';
        } else if (type === 'error') {
            iconBox.style.background = 'rgba(220, 38, 38, 0.15)'; // red light
            icon.className = 'bi bi-x-circle-fill text-danger';
        } else {
            iconBox.style.background = 'rgba(56, 189, 248, 0.15)'; // blue light
            icon.className = 'bi bi-info-circle-fill text-primary';
        }

        const handleConfirm = () => { confirmBtn.onclick = null; resolve(true); modal.hide(); };
        confirmBtn.onclick = handleConfirm;

        modal.show();
    });
}

window.rkConfirm = rkConfirm;
window.rkAlert = rkAlert;
