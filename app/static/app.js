/* Intentionally insecure UI:
 * - Renders assistant output via innerHTML (XSS by design for demo checks)
 */

const chatEl = document.getElementById("chat");
const promptEl = document.getElementById("prompt");
const sendEl = document.getElementById("send");

function addMsg(role, text, { html = false } = {}) {
  const row = document.createElement("div");
  row.className = `msg ${role}`;

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (html) {
    // VULNERABLE: do not do this in real apps.
    bubble.innerHTML = text;
  } else {
    bubble.textContent = text;
  }

  row.appendChild(bubble);
  chatEl.appendChild(row);
  chatEl.scrollTop = chatEl.scrollHeight;
}

async function send() {
  const msg = (promptEl.value || "").trim();
  if (!msg) return;

  addMsg("user", msg);
  promptEl.value = "";
  promptEl.focus();

  sendEl.disabled = true;
  const started = Date.now();
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: msg }),
    });
    const data = await res.json();
    const reply = data.reply || "(no reply)";

    // VULNERABLE: render as HTML so ThreatDrill can detect improper output handling.
    addMsg("assistant", reply, { html: true });
  } catch (e) {
    addMsg("assistant", `Error: ${String(e)}`);
  } finally {
    sendEl.disabled = false;
    // keep UI responsive if model is slow
    const dur = Date.now() - started;
    if (dur > 1500) {
      // no-op marker; useful for manual debugging
      console.debug("slow response", { ms: dur });
    }
  }
}

sendEl.addEventListener("click", () => send());

promptEl.addEventListener("keydown", (ev) => {
  // Enter submits, Shift+Enter adds newline.
  if (ev.key === "Enter" && !ev.shiftKey) {
    ev.preventDefault();
    send();
  }
});

