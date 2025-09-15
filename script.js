/* script.js - defensive, lint-safe, single file
   - Replaces previous script.js
   - Defensive DOM bindings and try/catch around main blocks
   - SHA-256 + salt, login/signup, admin, contact, CSV export
   - Add console.debug statements to help locate remaining issues
*/

/* ---------- Tiny helpers ---------- */
function $ (sel) { try { return document.querySelector(sel); } catch (e) { console.debug('Bad selector', sel); return null; } }
function $$ (sel) { try { return Array.from(document.querySelectorAll(sel)); } catch (e) { console.debug('Bad selector', sel); return []; } }

/* ---------- Crypto helpers ---------- */
function generateSalt(bytes) {
  bytes = bytes || 16;
  var arr = new Uint8Array(bytes);
  try { window.crypto.getRandomValues(arr); } catch (e) { for (var i=0;i<arr.length;i++) arr[i] = Math.floor(Math.random()*256); }
  return Array.prototype.map.call(arr, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
}
async function hashWithSalt(password, salt) {
  try {
    var enc = new TextEncoder();
    var data = enc.encode((salt || '') + (password || ''));
    var buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf)).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  } catch (err) {
    console.error('hashWithSalt failed', err);
    throw err;
  }
}

/* ---------- localStorage DB helpers ---------- */
var DB = {
  getUsers: function () { try { return JSON.parse(localStorage.getItem('ap_users') || '[]'); } catch (e) { console.warn('ap_users parse error', e); return []; } },
  saveUsers: function (u) { try { localStorage.setItem('ap_users', JSON.stringify(u)); } catch (e) { console.error('saveUsers failed', e); } },
  addUser: function (user) { var u = DB.getUsers(); u.push(user); DB.saveUsers(u); },
  getAnnouncements: function () { try { return JSON.parse(localStorage.getItem('ap_ann') || '[]'); } catch (e) { return []; } },
  saveAnnouncement: function (a) { try { var arr = DB.getAnnouncements(); arr.unshift(a); localStorage.setItem('ap_ann', JSON.stringify(arr)); } catch (e) { console.error('saveAnnouncement', e); } },
  logActivity: function (entry) { try { var logs = JSON.parse(localStorage.getItem('ap_logs') || '[]'); logs.unshift(entry); localStorage.setItem('ap_logs', JSON.stringify(logs.slice(0,200))); } catch (e) { console.error('logActivity error', e); } },
  getLogs: function () { try { return JSON.parse(localStorage.getItem('ap_logs') || '[]'); } catch (e) { return []; } }
};

/* ---------- Ensure admin exists (safe) ---------- */
async function ensureAdmin() {
  try {
    var users = DB.getUsers();
    var adminEmail = 'admin@portal';
    if (!users.find(function(u){ return u && u.email === adminEmail; })) {
      var salt = generateSalt(16);
      var passHash = await hashWithSalt('admin123', salt);
      var admin = { email: adminEmail, passHash: passHash, salt: salt, name: 'Administrator', disabled: false, created: new Date().toISOString(), lastLogin: null, role: 'admin' };
      users.push(admin);
      DB.saveUsers(users);
      DB.logActivity({ email: adminEmail, action: 'Admin account created', timestamp: new Date().toISOString() });
      console.debug('Default admin created');
    }
  } catch (e) {
    console.error('ensureAdmin failed', e);
  }
}

/* ---------- Utilities ---------- */
function evaluatePassword(password) {
  var res = { score:0, msg:'Too weak', valid:false };
  if (!password) { res.msg = 'Enter password'; return res; }
  var len = password.length;
  var hasUpper = /[A-Z]/.test(password);
  var hasLower = /[a-z]/.test(password);
  var hasDigit = /\d/.test(password);
  var hasSpecial = /[^A-Za-z0-9]/.test(password);
  if (len >= 8) res.score++;
  if (hasUpper && hasLower) res.score++;
  if (hasDigit) res.score++;
  if (hasSpecial) res.score++;
  if (res.score <= 1) res.msg = 'Weak — add length & varied chars';
  else if (res.score === 2) res.msg = 'Fair — add uppercase & digit';
  else if (res.score === 3) res.msg = 'Good — add special char';
  else res.msg = 'Strong password';
  res.valid = (len >= 8) && hasUpper && hasDigit;
  return res;
}

/* ---------- CSV helpers ---------- */
function arrayToCSV(rows, fields) {
  function esc(v) {
    if (v === null || v === undefined) return '';
    var s = String(v);
    s = s.replace(/"/g, '""');
    if (s.search(/("|,|\n)/g) >= 0) return '"' + s + '"';
    return s;
  }
  var header = fields.join(',');
  var out = [header];
  for (var i=0;i<rows.length;i++) {
    var r = rows[i];
    var row = [];
    for (var j=0;j<fields.length;j++) row.push(esc(r[fields[j]]));
    out.push(row.join(','));
  }
  return out.join('\n');
}
function downloadCSV(filename, csv) {
  try {
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } catch (e) { console.error('downloadCSV failed', e); alert('CSV download failed: ' + (e && e.message)); }
}

/* ---------- Password input helpers ---------- */
function getPasswordInputs(container) {
  container = container || document;
  var out = [];
  ['passwordField','confirmField'].forEach(function(id){
    try { var el = container.querySelector('#' + id); if (el && out.indexOf(el) === -1) out.push(el); } catch(e){}
  });
  try { container.querySelectorAll('input[type="password"]').forEach(function(el){ if (out.indexOf(el) === -1) out.push(el); }); } catch(e){}
  try { container.querySelectorAll('input[type="text"][data-pw="1"]').forEach(function(el){ if (out.indexOf(el) === -1) out.push(el); }); } catch(e){}
  return out;
}
function readPrimaryPassword(container) {
  container = container || document;
  try {
    var el = container.querySelector('#passwordField') || container.querySelector('input[data-pw="1"]') || container.querySelector('input[type="password"]');
    return el ? (el.value || '') : '';
  } catch (e) { return ''; }
}

/* ---------- Inline error helpers ---------- */
function showFieldError(id, msg) {
  try {
    var el = document.querySelector(id);
    if (!el) return;
    el.textContent = msg || '';
    el.style.display = msg ? 'block' : 'none';
    el.setAttribute('aria-hidden', msg ? 'false' : 'true');
  } catch (e) { console.error('showFieldError', id, e); }
}
function showFormError(message, selectorFallback) {
  try {
    var el = $('#formError') || $('#contactFormError') || (selectorFallback ? $(selectorFallback) : null);
    if (!el) {
      console.debug('showFormError: no element found for message', message);
      return;
    }
    el.textContent = message || '';
    el.style.display = message ? 'block' : 'none';
    el.setAttribute('aria-hidden', message ? 'false' : 'true');
  } catch (e) { console.error('showFormError', e); }
}

/* ---------- DOM ready ---------- */
document.addEventListener('DOMContentLoaded', function () {
  (async function main() {
    try {
      await ensureAdmin();
    } catch(e) { console.error('ensureAdmin error', e); }

    // Dark toggle
    try {
      var darkToggle = $('#darkToggle');
      if (darkToggle) {
        if (localStorage.getItem('ap_dark') === '1') document.body.classList.add('dark');
        darkToggle.addEventListener('click', function(){ document.body.classList.toggle('dark'); localStorage.setItem('ap_dark', document.body.classList.contains('dark') ? '1' : '0'); });
      }
    } catch (e) { console.error('dark toggle init failed', e); }

    // Mobile menu
    try {
      var menuBtn = $('#menuBtn'), navUl = $('nav ul');
      if (menuBtn && navUl) menuBtn.addEventListener('click', function(){ navUl.classList.toggle('show'); });
    } catch (e) { console.error('menu init failed', e); }

    // Render announcements on pages that have #announcements
    try {
      var annContainer = $('#announcements');
      if (annContainer) {
        var anns = DB.getAnnouncements();
        if (!anns || anns.length === 0) annContainer.innerHTML = '<p class="small-muted">No announcements yet.</p>';
        else annContainer.innerHTML = anns.map(function(a){
          return '<div class="card" style="text-align:left;margin-bottom:10px"><strong>' + (a.by||'') + '</strong> <span style="opacity:.6;font-size:.9rem">• ' + (new Date(a.timestamp).toLocaleString()) + '</span><div style="margin-top:6px">' + (a.text||'') + '</div></div>';
        }).join('');
      }
    } catch (e) { console.error('render announcements failed', e); }

    /* ---------- Login / Signup ---------- */
    try {
      var formBox = $('#formBox');
      if (formBox) {
        var emailField = $('#emailField');
        var formBtn = $('#formBtn');
        var toggleEye = $('#toggleEye');
        var toggleForm = $('#toggleForm');
        var formTitle = $('#formTitle');
        var confirmWrapper = $('#confirmWrapper');

        // Strength meter binding
        function bindStrength() {
          try {
            var pfs = getPasswordInputs(formBox);
            pfs.forEach(function(inp){
              try {
                inp.setAttribute('data-pw','1');
                var clone = inp.cloneNode(true);
                inp.parentNode.replaceChild(clone, inp);
                clone.addEventListener('input', function(){
                  var res = evaluatePassword(clone.value || '');
                  var pwdMsg = $('#pwdMsg'); var pwdBar = $('#pwdBar');
                  if (pwdMsg) pwdMsg.textContent = res.msg;
                  if (pwdBar) { pwdBar.style.width = Math.min(100, (res.score/4)*100) + '%'; pwdBar.style.background = res.score >= 3 ? '#28a745' : (res.score === 2 ? '#f39c12' : '#e74c3c'); }
                });
              } catch (e) { /* ignore individual input attach errors */ }
            });
          } catch (e) { console.error('bindStrength failed', e); }
        }
        bindStrength();

        // Eye toggle
        if (toggleEye) {
          try {
            toggleEye.addEventListener('click', function(){
              var showing = toggleEye.dataset.show === '1';
              var inputs = getPasswordInputs(formBox);
              inputs.forEach(function(inp){ try { if (showing) inp.type = 'password'; else { inp.type = 'text'; inp.setAttribute('data-pw','1'); } } catch(e){} });
              toggleEye.dataset.show = showing ? '0' : '1';
              toggleEye.textContent = showing ? '👁️' : '🙈';
            });
          } catch (e) { console.error('toggleEye init failed', e); }
        }

        // Toggle login / signup
        var loginMode = true;
        if (toggleForm) {
          toggleForm.addEventListener('click', function(){
            try {
              showFormError(''); showFieldError('#emailError',''); showFieldError('#passwordError',''); showFieldError('#confirmError','');
              if (loginMode) {
                formTitle.textContent = 'Sign Up'; formBtn.textContent = 'Register';
                if (!$('#nameField')) {
                  var emailRef = formBox.querySelector('input[type="email"]');
                  var nameInput = document.createElement('input'); nameInput.id = 'nameField'; nameInput.placeholder = 'Full name'; nameInput.setAttribute('aria-label','Full name');
                  formBox.insertBefore(nameInput, emailRef);
                }
                if (!$('#confirmField')) {
                  var confirm = document.createElement('input'); confirm.id = 'confirmField'; confirm.placeholder = 'Confirm password'; confirm.type = 'password';
                  if (confirmWrapper) confirmWrapper.innerHTML = ''; confirmWrapper.appendChild(confirm);
                }
                toggleForm.textContent = 'Already have an account? Login';
              } else {
                formTitle.textContent = 'Login'; formBtn.textContent = 'Login';
                var n = $('#nameField'); if (n) n.remove();
                var c = $('#confirmField'); if (c) c.remove();
                if (confirmWrapper) confirmWrapper.innerHTML = '';
                toggleForm.textContent = "Don't have an account? Sign Up";
              }
              loginMode = !loginMode;
              bindStrength();
              if (toggleEye && toggleEye.dataset.show === '1') { var pfs = getPasswordInputs(formBox); pfs.forEach(function(p){ try { p.type = 'text'; } catch(e){} }); }
            } catch (e) { console.error('toggleForm handler error', e); }
          });
        }

        function validateLoginInputs(isRegister) {
          try {
            showFormError(''); showFieldError('#emailError',''); showFieldError('#passwordError',''); showFieldError('#confirmError','');
            var email = emailField ? (emailField.value || '').trim() : '';
            var pass = readPrimaryPassword(formBox);
            var ok = true;
            if (!email) { showFieldError('#emailError','Email required'); ok = false; }
            else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showFieldError('#emailError','Enter a valid email'); ok = false; }
            if (!pass) { showFieldError('#passwordError','Password required'); ok = false; }
            if (isRegister) {
              var confirmVal = $('#confirmField') ? ($('#confirmField').value || '') : '';
              if (!confirmVal) { showFieldError('#confirmError','Confirm your password'); ok = false; }
              if (pass && confirmVal && pass !== confirmVal) { showFieldError('#confirmError','Passwords do not match'); ok = false; }
              var pr = evaluatePassword(pass);
              if (!pr.valid) { showFieldError('#passwordError','Password must be 8+ chars, include uppercase and digit'); ok = false; }
            }
            return ok;
          } catch (e) { console.error('validateLoginInputs failed', e); return false; }
        }

        if (formBtn) {
          formBtn.addEventListener('click', async function(ev){
            ev.preventDefault();
            try {
              var isRegister = (formBtn.textContent || '').toLowerCase().indexOf('register') >= 0;
              if (!validateLoginInputs(isRegister)) return;
              var email = emailField ? (emailField.value || '').trim() : '';
              var pass = readPrimaryPassword(formBox);
              if (isRegister) {
                var users = DB.getUsers();
                if (users.find(function(u){ return u.email === email; })) { showFormError('User already exists'); return; }
                var salt = generateSalt(16); var ph = await hashWithSalt(pass, salt);
                var nameVal = $('#nameField') ? ($('#nameField').value || 'User') : 'User';
                var newUser = { email: email, passHash: ph, salt: salt, name: nameVal, disabled: false, created: new Date().toISOString(), lastLogin: null, role: 'user' };
                DB.addUser(newUser); DB.logActivity({ email: email, action: 'Registered', timestamp: new Date().toISOString() }); showFormError('Registration successful. Please login.'); if (toggleForm) toggleForm.click();
              } else {
                var users = DB.getUsers(); var found = users.find(function(u){ return u.email === email; });
                if (!found) { showFormError('No account found. Register first.'); return; }
                if (found.disabled) { showFormError('Account disabled. Contact admin.'); return; }

                // legacy migration
                if (found.pass && !found.passHash && !found.salt) {
                  try {
                    var plain = atob(found.pass || '');
                    if (plain === pass) {
                      var salt2 = generateSalt(16); var hash2 = await hashWithSalt(pass, salt2);
                      found.salt = salt2; found.passHash = hash2; delete found.pass; DB.saveUsers(users); DB.logActivity({ email: email, action: 'Migrated legacy cred', timestamp: new Date().toISOString() });
                    } else { showFormError('Incorrect password'); return; }
                  } catch (e) { showFormError('Legacy migration failed'); return; }
                }

                if (found.salt && found.passHash) {
                  var chk = await hashWithSalt(pass, found.salt);
                  if (chk !== found.passHash) { showFormError('Incorrect password'); return; }
                } else { showFormError('Invalid account data'); return; }

                localStorage.setItem('ap_currentUser', JSON.stringify({ email: found.email, name: found.name, role: found.role }));
                found.lastLogin = new Date().toISOString(); DB.saveUsers(users);
                DB.logActivity({ email: found.email, action: 'Logged in', timestamp: new Date().toISOString() });
                window.location.href = 'index.html';
              }
            } catch (e) { console.error('formBtn click handler failed', e); showFormError('An unexpected error occurred'); }
          });
        }
      }
    } catch (e) { console.error('Login/Signup block error', e); }

    /* ---------- Admin page ---------- */
    try {
      var onAdmin = window.location.pathname.indexOf('admin.html') >= 0 || window.location.href.indexOf('admin.html') >= 0;
      if (onAdmin) {
        var adminLoginForm = $('#adminLoginForm'); var adminPanel = $('#adminPanel');
        async function renderAdmin() {
          try {
            var usersListDiv = $('#usersList'); var annListDiv = $('#annList'); var userCountEl = $('#userCount');
            if (!usersListDiv || !annListDiv || !userCountEl) return;
            usersListDiv.innerHTML = ''; var users = DB.getUsers(); userCountEl.innerText = users.length;
            users.forEach(function(u){
              var wrapper = document.createElement('div');
              wrapper.style.padding = '8px'; wrapper.style.borderBottom = '1px solid rgba(0,0,0,0.06)';
              wrapper.innerHTML = '<strong>' + (u.name||'') + '</strong> <span style="opacity:.7">(' + (u.email||'') + ')</span>' +
                '<div style="float:right"><button data-email="' + (u.email||'') + '" class="toggleDisable">' + (u.disabled ? 'Enable' : 'Disable') + '</button></div>' +
                '<div style="clear:both;font-size:.9rem;opacity:.7">Last: ' + (u.lastLogin || 'Never') + ' • Created: ' + (u.created ? new Date(u.created).toLocaleString() : '') + '</div>';
              usersListDiv.appendChild(wrapper);
            });

            $$('.toggleDisable').forEach(function(btn){
              btn.addEventListener('click', function(){
                try {
                  var email = btn.dataset.email; var users = DB.getUsers(); var u = users.find(function(x){ return x.email === email; }); if (!u) return;
                  u.disabled = !u.disabled; DB.saveUsers(users); DB.logActivity({ email: 'admin', action: (u.disabled ? 'Disabled ' : 'Enabled ') + email, timestamp: new Date().toISOString() }); renderAdmin();
                } catch (e) { console.error('toggleDisable handler', e); }
              });
            });

            annListDiv.innerHTML = '';
            var anns = DB.getAnnouncements();
            if (!anns || anns.length === 0) annListDiv.innerHTML = '<div class="small-muted">No announcements yet.</div>';
            else anns.forEach(function(a){
              var el = document.createElement('div'); el.style.padding = '8px'; el.style.borderBottom = '1px solid rgba(0,0,0,0.06)';
              el.innerHTML = '<strong>' + (a.by||'') + '</strong> <span style="opacity:.6">• ' + (new Date(a.timestamp).toLocaleString()) + '</span><div style="margin-top:6px">' + (a.text||'') + '</div>';
              annListDiv.appendChild(el);
            });
          } catch (e) { console.error('renderAdmin failed', e); }
        }

        if (adminLoginForm) {
          adminLoginForm.addEventListener('submit', async function(ev){
            ev.preventDefault();
            try {
              var em = $('#adminEmail') ? ($('#adminEmail').value || '').trim() : '';
              var pw = $('#adminPass') ? ($('#adminPass').value || '') : '';
              if (!em || !pw) { alert('Enter admin credentials'); return; }
              var adminUser = DB.getUsers().find(function(u){ return u.email === em && u.role === 'admin'; });
              if (!adminUser) { alert('Admin not found'); return; }

              if (adminUser.salt && adminUser.passHash) {
                var inHash = await hashWithSalt(pw, adminUser.salt);
                if (inHash !== adminUser.passHash) { alert('Incorrect admin password'); return; }
              } else if (adminUser.pass) {
                try {
                  if (atob(adminUser.pass) === pw) {
                    var s = generateSalt(16); var ph = await hashWithSalt(pw, s);
                    adminUser.salt = s; adminUser.passHash = ph; delete adminUser.pass; DB.saveUsers(DB.getUsers());
                  } else { alert('Incorrect admin password'); return; }
                } catch (e) { alert('Admin credentials invalid'); return; }
              } else {
                alert('Admin account corrupted'); return;
              }

              if (adminLoginForm) adminLoginForm.style.display = 'none';
              if (adminPanel) adminPanel.style.display = 'block';
              localStorage.setItem('ap_currentUser', JSON.stringify({ email: adminUser.email, role: 'admin', name: adminUser.name }));
              DB.logActivity({ email: adminUser.email, action: 'Admin logged in', timestamp: new Date().toISOString() });
              await renderAdmin();
            } catch (e) { console.error('admin login handler failed', e); alert('Admin login failed'); }
          });
        }

        var postBtn = $('#postAnn');
        if (postBtn) {
          postBtn.addEventListener('click', function(){
            try {
              var txt = $('#annText') ? ($('#annText').value || '').trim() : '';
              if (!txt) { alert('Enter announcement'); return; }
              var cur = JSON.parse(localStorage.getItem('ap_currentUser') || '{}');
              var ann = { text: txt, by: cur.name || cur.email || 'Admin', timestamp: new Date().toISOString() };
              DB.saveAnnouncement(ann); DB.logActivity({ email: cur.email || 'admin', action: 'Posted announcement', timestamp: new Date().toISOString() });
              if ($('#annText')) $('#annText').value = '';
              renderAdmin();
            } catch (e) { console.error('postAnn handler failed', e); alert('Could not post announcement'); }
          });
        }

        var exportUsersBtn = $('#exportUsersBtn'), exportLogsBtn = $('#exportLogsBtn');
        function ts() { var d = new Date(); return d.getFullYear() + String(d.getMonth()+1).padStart(2,'0') + String(d.getDate()).padStart(2,'0') + '_' + String(d.getHours()).padStart(2,'0') + String(d.getMinutes()).padStart(2,'0'); }
        if (exportUsersBtn) exportUsersBtn.addEventListener('click', function(){ try { var users = DB.getUsers(); var rows = users.map(function(u){ return { email: u.email||'', name: u.name||'', role: u.role||'user', disabled: u.disabled ? 'true' : 'false', created: u.created||'', lastLogin: u.lastLogin||'' }; }); var csv = arrayToCSV(rows, ['email','name','role','disabled','created','lastLogin']); downloadCSV('users_' + ts() + '.csv', csv); DB.logActivity({ email: 'admin', action: 'Exported users CSV', timestamp: new Date().toISOString() }); } catch (e) { console.error('exportUsers failed', e); alert('Export failed'); } });
        if (exportLogsBtn) exportLogsBtn.addEventListener('click', function(){ try { var logs = DB.getLogs(); var rows = logs.map(function(l){ return { email: l.email||'', action: l.action||'', timestamp: l.timestamp||'' }; }); var csv = arrayToCSV(rows, ['email','action','timestamp']); downloadCSV('activity_' + ts() + '.csv', csv); DB.logActivity({ email: 'admin', action: 'Exported activity CSV', timestamp: new Date().toISOString() }); } catch (e) { console.error('exportLogs failed', e); alert('Export failed'); } });
      }
    } catch (e) { console.error('Admin block failed', e); }

    /* ---------- Contact form ---------- */
    try {
      var contactFormEl = $('#contactForm');
      if (contactFormEl) {
        var nameInput = $('#name'), mailInput = $('#email'), msgInput = $('#message'), submitBtn = $('#submitBtn');

        function clearContactErrors() { try { showFieldError('#nameError',''); showFieldError('#emailError',''); showFieldError('#messageError',''); showFormError(''); } catch(e){} }

        if (submitBtn) submitBtn.addEventListener('click', function(ev){
          ev.preventDefault();
          try {
            clearContactErrors();
            var name = nameInput ? (nameInput.value || '').trim() : '';
            var mail = mailInput ? (mailInput.value || '').trim() : '';
            var msg = msgInput ? (msgInput.value || '').trim() : '';
            var ok = true;
            if (!name) { showFieldError('#nameError','Please enter your name'); ok = false; }
            if (!mail) { showFieldError('#emailError','Please enter your email'); ok = false; } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) { showFieldError('#emailError','Enter a valid email'); ok = false; }
            if (!msg) { showFieldError('#messageError','Please enter a message'); ok = false; }
            if (!ok) return;
            DB.logActivity({ email: mail, action: 'Contact form sent', timestamp: new Date().toISOString(), meta: { name: name } });
            showFormError('Message sent! Thank you — we will respond by email.');
            if (nameInput) nameInput.value = ''; if (mailInput) mailInput.value = ''; if (msgInput) msgInput.value = '';
          } catch (e) { console.error('contact submit failed', e); showFormError('Could not send message'); }
        });
      }
    } catch (e) { console.error('Contact block failed', e); }

  })().catch(function(e){ console.error('Main initialization error', e); });
}); // DOMContentLoaded end
