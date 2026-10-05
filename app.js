let signedInUser = null;

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  let body = options.body;
  if (body && !(body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }
  const response = await fetch(url, { ...options, body, headers, credentials: "same-origin" });
  if (response.status === 204) return null;
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}

function showFeedback(node, message, isError = false) {
  if (!node) return;
  node.textContent = message;
  node.hidden = false;
  node.classList.toggle("error-message", isError);
}

function setBusy(form, busy) {
  form.querySelectorAll("button[type=submit]").forEach((button) => {
    button.disabled = busy;
    if (busy) button.dataset.previousText = button.textContent;
    else if (button.dataset.previousText) button.textContent = button.dataset.previousText;
    if (busy) button.textContent = "Please wait…";
  });
}

function setupBackgroundVideo() {
  const video = document.createElement("video");
  video.className = "site-background-video";
  video.setAttribute("aria-hidden", "true");
  video.setAttribute("tabindex", "-1");
  video.autoplay = true;
  video.muted = true;
  video.loop = true;
  video.playsInline = true;
  video.preload = "auto";
  const source = document.createElement("source");
  source.src = "/background.mp4";
  source.type = "video/mp4";
  video.append(source);
  document.body.prepend(video);
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) video.pause();
  else video.play().catch(() => {});
}

function setupMobileNavigation() {
  const nav = document.querySelector("nav");
  const wrap = document.querySelector(".nav-wrap");
  if (!nav || !wrap || nav.querySelector(".nav-toggle")) return;
  const toggle = document.createElement("button");
  toggle.className = "nav-toggle";
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", "false");
  toggle.setAttribute("aria-label", "Toggle navigation");
  toggle.textContent = "Menu";
  wrap.insertBefore(toggle, nav);
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", String(open));
  });
}

function renderNavigation() {
  const nav = document.querySelector("nav[data-account-nav]");
  if (!nav) return;
  nav.querySelectorAll("[data-auth-link]").forEach((link) => link.remove());
  const links = signedInUser
    ? `<a data-auth-link href="account.html">${escapeHtml(signedInUser.username)} · Account</a>${signedInUser.role === "admin" ? '<a data-auth-link href="admin.html">Admin panel</a>' : ""}<button data-auth-link class="link-button" type="button" data-logout>Log out</button>`
    : '<a data-auth-link href="login.html">Log in</a><a data-auth-link href="signup.html">Sign up</a>';
  nav.insertAdjacentHTML("beforeend", links);
  nav.querySelector("[data-logout]")?.addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* Navigate out even if the network is down. */ }
    location.href = "/index.html";
  });
}

function setupAuthForms() {
  const signup = document.querySelector("#signup-form");
  signup?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const feedback = signup.parentElement.querySelector("[data-feedback]");
    const data = new FormData(signup);
    const password = String(data.get("password") || "");
    if (password !== data.get("confirm-password")) return showFeedback(feedback, "Passwords do not match.", true);
    setBusy(signup, true);
    try {
      const result = await api("/api/auth/register", { method: "POST", body: {
        fullName: data.get("fullname"), email: data.get("email"), username: data.get("username"), password,
      } });
      signedInUser = result.user;
      location.href = "/dashboard.html";
    } catch (error) { showFeedback(feedback, error.message, true); setBusy(signup, false); }
  });

  const login = document.querySelector("#login-form");
  login?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const feedback = login.parentElement.querySelector("[data-feedback]");
    const data = new FormData(login);
    setBusy(login, true);
    try {
      const result = await api("/api/auth/login", { method: "POST", body: { identity: data.get("login"), password: data.get("password") } });
      signedInUser = result.user;
      location.href = "/dashboard.html";
    } catch (error) { showFeedback(feedback, error.message, true); setBusy(login, false); }
  });
}

async function setupAccount() {
  const form = document.querySelector("#account-form");
  if (!form) return;
  if (!signedInUser) {
    form.innerHTML = '<p>Please <a href="/login.html">log in</a> to manage your account.</p>';
    return;
  }
  form.querySelector("[name=fullname]").value = signedInUser.fullName;
  form.querySelector("[name=username]").value = signedInUser.username;
  form.querySelector("[name=email]").value = signedInUser.email;
  form.querySelector("[name=bio]").value = signedInUser.bio || "";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const feedback = form.querySelector("[data-feedback]");
    setBusy(form, true);
    try {
      const result = await api("/api/account", { method: "PATCH", body: {
        fullName: data.get("fullname"), username: data.get("username"), email: data.get("email"), bio: data.get("bio"),
      } });
      signedInUser = result.user;
      renderNavigation();
      showFeedback(feedback, "Account details saved.");
    } catch (error) { showFeedback(feedback, error.message, true); }
    finally { setBusy(form, false); }
  });
  form.querySelector("[data-delete-account]")?.addEventListener("click", async () => {
    if (!confirm("Delete your account and saved progress? This cannot be undone.")) return;
    try { await api("/api/account", { method: "DELETE" }); location.href = "/index.html"; }
    catch (error) { showFeedback(form.querySelector("[data-feedback]"), error.message, true); }
  });
  const passwordForm = document.querySelector("#password-form");
  passwordForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(passwordForm);
    const feedback = passwordForm.querySelector("[data-feedback]");
    if (data.get("new-password") !== data.get("confirm-password")) return showFeedback(feedback, "New passwords do not match.", true);
    setBusy(passwordForm, true);
    try {
      await api("/api/account/password", { method: "PATCH", body: { currentPassword: data.get("current-password"), newPassword: data.get("new-password") } });
      passwordForm.reset();
      showFeedback(feedback, "Password changed.");
    } catch (error) { showFeedback(feedback, error.message, true); }
    finally { setBusy(passwordForm, false); }
  });
}

function setupAdminPanel() {
  const root = document.querySelector("[data-admin-root]");
  if (!root) return;
  let allUsers = [];
  let query = "";
  const draw = () => {
    const list = allUsers.filter((user) => `${user.fullName} ${user.username} ${user.email} ${user.role} ${user.status}`.toLowerCase().includes(query.toLowerCase()));
    root.innerHTML = `<div class="admin-summary"><article class="dashboard-stat"><span>${allUsers.length}</span><p>Total accounts</p></article><article class="dashboard-stat"><span>${allUsers.filter((user) => user.status === "active").length}</span><p>Active</p></article><article class="dashboard-stat"><span>${allUsers.filter((user) => user.role === "admin").length}</span><p>Administrators</p></article></div><section class="content-panel"><div class="admin-heading"><div><p class="eyebrow">Full account control</p><h2>User management</h2></div><button type="button" data-export>Export user list</button></div><label for="user-search">Search accounts</label><input id="user-search" type="search" placeholder="Name, username, email, status…" value="${escapeHtml(query)}"><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Joined</th><th>Actions</th></tr></thead><tbody>${list.map((user) => `<tr><td><strong>${escapeHtml(user.fullName)}</strong><small>@${escapeHtml(user.username)} · ${escapeHtml(user.email)}</small></td><td><select data-role="${user.id}" aria-label="Role for ${escapeHtml(user.username)}"><option value="user" ${user.role === "user" ? "selected" : ""}>User</option><option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option></select></td><td><span class="status-pill ${user.status}">${escapeHtml(user.status)}</span></td><td>${new Date(user.createdAt).toLocaleDateString()}</td><td class="admin-actions"><button type="button" data-status="${user.id}" data-current="${user.status}">${user.status === "active" ? "Suspend" : "Restore"}</button><button type="button" data-edit="${user.id}">Edit details</button><button type="button" data-reset="${user.id}">Set password</button><button class="danger-button" type="button" data-delete="${user.id}" ${user.id === signedInUser?.id ? "disabled" : ""}>Delete</button></td></tr>`).join("") || '<tr><td colspan="5">No accounts found.</td></tr>'}</tbody></table></div><p class="upload-note">Changes are enforced by the server. You cannot remove your own active administrator access or delete the last active administrator.</p></section>`;
    root.querySelector("#user-search").addEventListener("input", (event) => { query = event.target.value; draw(); });
    root.querySelector("[data-export]").addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(allUsers, null, 2)], { type: "application/json" });
      const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "cypher-school-users.json"; link.click(); URL.revokeObjectURL(link.href);
    });
    root.querySelectorAll("[data-role]").forEach((select) => select.addEventListener("change", () => mutateUser(select.dataset.role, { role: select.value })));
    root.querySelectorAll("[data-status]").forEach((button) => button.addEventListener("click", () => mutateUser(button.dataset.status, { status: button.dataset.current === "active" ? "suspended" : "active" })));
    root.querySelectorAll("[data-edit]").forEach((button) => button.addEventListener("click", async () => {
      const user = allUsers.find((item) => item.id === button.dataset.edit);
      const fullName = prompt("Full name", user.fullName); if (fullName === null) return;
      const username = prompt("Username", user.username); if (username === null) return;
      const userEmail = prompt("Email", user.email); if (userEmail === null) return;
      await mutateUser(user.id, { fullName, username, email: userEmail });
    }));
    root.querySelectorAll("[data-reset]").forEach((button) => button.addEventListener("click", async () => {
      const password = prompt("Set a temporary password (10+ characters):");
      if (!password) return;
      try { await api(`/api/admin/users/${button.dataset.reset}/password`, { method: "PATCH", body: { password } }); alert("Password updated."); }
      catch (error) { alert(error.message); }
    }));
    root.querySelectorAll("[data-delete]").forEach((button) => button.addEventListener("click", async () => {
      const user = allUsers.find((item) => item.id === button.dataset.delete);
      if (!confirm(`Permanently delete ${user.username} and their saved progress?`)) return;
      try { await api(`/api/admin/users/${user.id}`, { method: "DELETE" }); allUsers = allUsers.filter((item) => item.id !== user.id); draw(); }
      catch (error) { alert(error.message); }
    }));
  };
  async function mutateUser(id, changes) {
    try {
      const result = await api(`/api/admin/users/${id}`, { method: "PATCH", body: changes });
      allUsers = allUsers.map((user) => user.id === id ? result.user : user);
      draw();
    } catch (error) { alert(error.message); load(); }
  }
  async function load() {
    try { const result = await api("/api/admin/users"); allUsers = result.users; draw(); }
    catch (error) { root.innerHTML = `<section class="content-panel"><h2>Admin access required</h2><p>${escapeHtml(error.message)}</p><a class="button" href="/login.html">Log in</a></section>`; }
  }
  load();
}

function setupResourceSubmission() {
  const form = document.querySelector("#resource-submission");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const file = data.get("resource-file");
    const feedback = document.querySelector("#submission-message");
    if (!(file instanceof File) || !file.size) return showFeedback(feedback, "Choose a PDF file to submit.", true);
    if (file.size > 12 * 1024 * 1024) return showFeedback(feedback, "PDFs must be smaller than 12 MB.", true);
    const uploadData = new FormData();
    uploadData.set("title", data.get("resource-title"));
    uploadData.set("category", data.get("resource-category"));
    uploadData.set("description", data.get("resource-note"));
    uploadData.set("file", file);
    setBusy(form, true);
    try {
      await api("/api/resources", { method: "POST", body: uploadData });
      form.reset();
      feedback.hidden = false;
      feedback.classList.remove("error-message");
      feedback.querySelector("span").textContent = "Your resource is waiting for administrator review.";
    } catch (error) { showFeedback(feedback, error.message, true); }
    finally { setBusy(form, false); }
  });
}

function setupResourceReview() {
  const root = document.querySelector("[data-resource-review]");
  if (!root) return;
  const load = async () => {
    try {
      const { resources } = await api("/api/admin/resources");
      root.innerHTML = resources.length ? `<div class="table-wrap"><table><thead><tr><th>Resource</th><th>Submitted by</th><th>Status</th><th>Submitted</th><th>Review</th></tr></thead><tbody>${resources.map((item) => `<tr><td><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.category)} · ${escapeHtml(item.description)}</small><a href="/api/resources/${item.id}/file" target="_blank" rel="noopener">Preview PDF</a></td><td>${escapeHtml(item.uploader || "Deleted account")}</td><td><span class="status-pill ${item.status}">${escapeHtml(item.status)}</span></td><td>${new Date(item.created_at).toLocaleDateString()}</td><td>${item.status === "pending" ? `<button type="button" data-review="${item.id}" data-decision="approved">Approve</button><button type="button" class="danger-button" data-review="${item.id}" data-decision="rejected">Reject</button>` : escapeHtml(item.review_note || "—")}</td></tr>`).join("")}</tbody></table></div>` : '<div class="upload-note">No resource submissions yet.</div>';
      root.querySelectorAll("[data-review]").forEach((button) => button.addEventListener("click", async () => {
        const note = prompt(button.dataset.decision === "approved" ? "Optional review note" : "Reason for rejection (optional)", "") ?? "";
        try { await api(`/api/admin/resources/${button.dataset.review}`, { method: "PATCH", body: { status: button.dataset.decision, reviewNote: note } }); load(); }
        catch (error) { alert(error.message); }
      }));
    } catch (error) { root.innerHTML = `<div class="upload-note">${escapeHtml(error.message)} <a href="/login.html">Log in as an administrator.</a></div>`; }
  };
  load();
}

function setupPublishedResources() {
  const root = document.querySelector("[data-library-resources]");
  if (!root) return;
  if (!signedInUser) { root.innerHTML = '<p>Log in to view approved community resources.</p>'; return; }
  api("/api/resources").then(({ resources }) => {
    root.innerHTML = resources.length ? `<div class="section-heading"><p class="eyebrow">Community library</p><h2>Approved learner resources</h2></div><div class="resource-grid">${resources.map((item) => `<article class="resource-card"><span class="tag">${escapeHtml(item.category)}</span><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.description)}</p><a class="button" href="/api/resources/${item.id}/file" target="_blank" rel="noopener">Read PDF</a></article>`).join("")}</div>` : '<div class="upload-note"><strong>Community resources</strong><p>Approved learner submissions will appear here.</p></div>';
  }).catch((error) => { root.textContent = error.message; });
}

function setupCourseFilter() {
  const filter = document.querySelector("[data-course-filter]");
  const cards = document.querySelectorAll("[data-course-card]");
  const empty = document.querySelector("[data-course-empty]");
  if (!filter) return;
  filter.addEventListener("input", () => {
    let count = 0;
    cards.forEach((card) => { const visible = card.textContent.toLowerCase().includes(filter.value.trim().toLowerCase()); card.hidden = !visible; if (visible) count += 1; });
    if (empty) empty.hidden = count > 0;
  });
}

function setupProgress() {
  const progress = signedInUser?.progress || {};
  const done = Object.values(progress).filter(Boolean).length;
  const percentage = Math.min(100, Math.round((done / 4) * 100));
  document.querySelectorAll("[data-progress-value]").forEach((node) => { node.textContent = `${percentage}%`; });
  document.querySelectorAll("[data-progress-bar]").forEach((node) => { node.style.width = `${percentage}%`; });
  document.querySelectorAll("[data-progress-count]").forEach((node) => { node.textContent = `${done} of 4 lessons complete`; });
  const button = document.querySelector("[data-complete-lesson]");
  if (!button) return;
  const lessonId = button.dataset.completeLesson;
  const render = () => {
    const complete = Boolean(signedInUser?.progress?.[lessonId]);
    button.textContent = complete ? "Lesson completed" : "Mark lesson complete";
    button.classList.toggle("is-complete", complete);
    button.setAttribute("aria-pressed", String(complete));
  };
  render();
  button.addEventListener("click", async () => {
    if (!signedInUser) { location.href = "/login.html"; return; }
    button.disabled = true;
    try {
      const completed = !signedInUser.progress?.[lessonId];
      const result = await api(`/api/account/progress/${encodeURIComponent(lessonId)}`, { method: "PATCH", body: { completed } });
      signedInUser = { ...signedInUser, progress: result.progress };
      const done = Object.values(signedInUser.progress || {}).filter(Boolean).length;
      const percentage = Math.min(100, Math.round((done / 4) * 100));
      document.querySelectorAll("[data-progress-value]").forEach((node) => { node.textContent = `${percentage}%`; });
      document.querySelectorAll("[data-progress-bar]").forEach((node) => { node.style.width = `${percentage}%`; });
      document.querySelectorAll("[data-progress-count]").forEach((node) => { node.textContent = `${done} of 4 lessons complete`; });
      render();
    } catch (error) { alert(error.message); }
    finally { button.disabled = false; }
  });
}

function setupQuiz() {
  const form = document.querySelector("#linux-quiz");
  const result = document.querySelector("#quiz-result");
  if (!form || !result) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const answers = new FormData(form);
    const score = ["q1", "q2", "q3"].reduce((total, key) => total + Number(answers.get(key) === "1"), 0);
    let message = score === 3 ? "Excellent work — you scored 3 out of 3. Lesson complete!" : `You scored ${score} out of 3. Review the lesson and try again.`;
    if (score === 3 && signedInUser) {
      try {
        const response = await api("/api/account/progress/linux-quiz", { method: "PATCH", body: { completed: true } });
        signedInUser = { ...signedInUser, progress: response.progress };
      } catch { message += " Your score could not be saved."; }
    } else if (score === 3) message += " Log in to save your progress.";
    result.innerHTML = `<strong>QUIZ RESULT</strong><span>${escapeHtml(message)}</span>`;
    result.style.display = "flex";
  });
}

function personalizeDashboard() {
  const heading = document.querySelector("[data-welcome]");
  if (signedInUser && heading) heading.textContent = `Welcome, ${signedInUser.username}.`;
}

function setupOpsScreen() {
  const clock = document.querySelector("[data-live-clock]");
  if (!clock) return;
  const lines = [
    ["[ OK ]", "Sandbox heartbeat received from lab node."], ["[INFO]", "Refreshing simulated network telemetry."],
    ["[SCAN]", "Training services responding normally."], ["[ OK ]", "Learning portal integrity check passed."],
    ["[INFO]", "Defensive monitoring rules loaded."], ["[SAFE]", "No action required · training environment stable."],
  ];
  const tick = () => { clock.textContent = new Date().toLocaleTimeString([], { hour12: false }); };
  tick(); window.setInterval(tick, 1000);
  let index = 0;
  window.setInterval(() => {
    if (document.hidden) return;
    const output = document.querySelector("[data-terminal-output]");
    if (output) {
      const [label, message] = lines[index++ % lines.length];
      const row = document.createElement("p");
      const tag = document.createElement("b"); tag.textContent = label;
      row.append(tag, ` ${message}`);
      output.insertBefore(row, output.querySelector(".terminal-prompt"));
      while (output.querySelectorAll("p:not(.terminal-prompt)").length > 5) output.querySelector("p:not(.terminal-prompt)").remove();
    }
    const inbound = document.querySelector("[data-inbound]");
    const outbound = document.querySelector("[data-outbound]");
    if (inbound) inbound.textContent = (1.8 + Math.random() * 1.4).toFixed(1);
    if (outbound) outbound.textContent = (1.2 + Math.random() * 1.2).toFixed(1);
    const events = document.querySelector("[data-event-count]");
    if (events) events.textContent = (Number(events.textContent.replaceAll(",", "")) + Math.floor(1 + Math.random() * 5)).toLocaleString();
  }, 2800);
}

async function initialize() {
  setupBackgroundVideo();
  setupMobileNavigation();
  try { const result = await api("/api/auth/me"); signedInUser = result.user; }
  catch { signedInUser = null; }
  renderNavigation();
  setupAuthForms();
  await setupAccount();
  setupAdminPanel();
  setupResourceSubmission();
  setupResourceReview();
  setupPublishedResources();
  setupCourseFilter();
  setupProgress();
  setupQuiz();
  personalizeDashboard();
  setupOpsScreen();
}

initialize();
