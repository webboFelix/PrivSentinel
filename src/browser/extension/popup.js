const status = document.getElementById("status");
const site = document.getElementById("site");
const allowButton = document.getElementById("allow");
const refreshButton = document.getElementById("refresh");
let currentDomain = "";

function request(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError?.message || response?.error;
      if (error) reject(new Error(error));
      else resolve(response);
    });
  });
}

chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  try {
    currentDomain = new URL(tab.url).hostname;
    site.textContent = currentDomain;
    allowButton.hidden = !currentDomain;
  } catch {
    site.textContent = "No website tab is active.";
  }
  chrome.storage.local.get(["lastRulesSync", "ruleCount", "nativeHostError"]).then((result) => {
    status.textContent = result.nativeHostError
      ? `Connector unavailable: ${result.nativeHostError}`
      : result.lastRulesSync
        ? `Local protection active · ${result.ruleCount || 0} rules`
        : "Block list has not synchronized yet.";
  });
});

allowButton.addEventListener("click", async () => {
  allowButton.disabled = true;
  try {
    await request({ type: "allow_domain", domain: currentDomain });
    status.textContent = `${currentDomain} allowed. Reload the site to continue.`;
  } catch (error) {
    status.textContent = error.message;
    allowButton.disabled = false;
  }
});

refreshButton.addEventListener("click", async () => {
  refreshButton.disabled = true;
  try {
    const response = await request({ type: "refresh_rules" });
    status.textContent = `${response.count} local rules refreshed.`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    refreshButton.disabled = false;
  }
});
