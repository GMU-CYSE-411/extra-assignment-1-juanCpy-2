(async function bootstrapAdmin() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      document.getElementById("admin-warning").textContent = "Please log in first.";
      return;
    }

    if (user.role !== "admin") {
      document.getElementById("admin-warning").textContent =
        "The client says this is not your area, but the page still tries to load admin data.";
    } else {
      document.getElementById("admin-warning").textContent = "Authenticated as admin.";
    }
    //InnerHTML was used here, which could have be used for XSS. Switched to textContent, which is safe.
    const result = await api("/api/admin/users");
    const escapeHtml = s => s.
    replace(/&/g, "&amp;").
    replace(/</g, "&lt;").
    replace(/>/g, "&gt;").
    replace(/"/g, "&quot;").
    replace(/'/g, "&#39;");
    //Escaping fields to make sure that XSS is not possibe. While this is also prevented in the server, this is another layer.
    document.getElementById("admin-users").textContent = result.users
      .map(
        (entry) => `
          <tr>
            <td>${escapeHtml(String(entry.id))}</td>
            <td>${escapeHtml(entry.username)}</td>
            <td>${escapeHtml(entry.role)}</td>
            <td>${escapeHtml(entry.displayName)}</td>
            <td>${escapeHtml(String(entry.noteCount))}</td>
          </tr>
        `
      )
      .join("");
  } catch (error) {
    document.getElementById("admin-warning").textContent = error.message;
  }
})();
