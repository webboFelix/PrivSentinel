const title = document.getElementById("title");
const domainLabel = document.getElementById("domain");
const detail = document.getElementById("detail");
const allowButton = document.getElementById("allow");
const errorLabel = document.getElementById("error");
let context = null;

function request(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError?.message || response?.error;
      if (error) reject(new Error(error));
      else resolve(response);
    });
  });
}

async function loadContext() {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      const result = await request({ type: "get_block_context" });
      if (result.domain) {
        context = result;
        break;
      }
    } catch (error) {
      errorLabel.textContent = error.message;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!context) {
    errorLabel.textContent = "PrivSentinel could not load the block reason. Do not proceed until you review the domain.";
    allowButton.disabled = true;
    return;
  }
  title.textContent = context.action === "review" ? "Website needs review" : "Website blocked";
  domainLabel.textContent = context.domain;
  detail.textContent = `${context.detail} Source: ${context.provider}.`;
  allowButton.hidden = false;
}

allowButton.addEventListener("click", async () => {
  allowButton.disabled = true;
  try {
    await request({ type: "allow_domain", domain: context.domain });
    window.location.assign(context.url);
  } catch (error) {
    errorLabel.textContent = error.message;
    allowButton.disabled = false;
  }
});

document.getElementById("back").addEventListener("click", () => history.back());
loadContext();
