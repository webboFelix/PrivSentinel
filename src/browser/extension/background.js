const HOST_NAME = "com.privsentinel.browser";
const RULES_REFRESH_MINUTES = 2;
const REQUEST_TIMEOUT_MS = 10000;
let nativePort = null;
let nextRequestId = 1;
const pendingRequests = new Map();

function browserName() {
  const agent = navigator.userAgent;
  if (agent.includes("Firefox")) return "Firefox";
  if (agent.includes("Edg/")) return "Edge";
  if (navigator.brave) return "Brave";
  return "Chrome";
}

function connectNativeHost() {
  if (nativePort) return nativePort;
  nativePort = chrome.runtime.connectNative(HOST_NAME);
  nativePort.onMessage.addListener((message) => {
    const request = pendingRequests.get(message.requestId);
    if (!request) return;
    clearTimeout(request.timer);
    pendingRequests.delete(message.requestId);
    if (message.error) request.reject(new Error(message.error));
    else request.resolve(message);
  });
  nativePort.onDisconnect.addListener(() => {
    const reason = chrome.runtime.lastError?.message || "Native host disconnected.";
    nativePort = null;
    for (const request of pendingRequests.values()) {
      clearTimeout(request.timer);
      request.reject(new Error(reason));
    }
    pendingRequests.clear();
  });
  return nativePort;
}

function nativeRequest(payload) {
  return new Promise((resolve, reject) => {
    const requestId = String(nextRequestId++);
    const timer = setTimeout(() => {
      pendingRequests.delete(requestId);
      reject(new Error("PrivSentinel did not respond to the browser request."));
    }, REQUEST_TIMEOUT_MS);
    pendingRequests.set(requestId, { resolve, reject, timer });
    try {
      connectNativeHost().postMessage({
        ...payload,
        browser: browserName(),
        requestId
      });
    } catch (error) {
      clearTimeout(timer);
      pendingRequests.delete(requestId);
      reject(error);
    }
  });
}

async function refreshRules() {
  const rules = await nativeRequest({ type: "get_rules" });
  const blocked = rules.blocked_domains || [];
  const allowed = rules.allowed_domains || [];
  const review = rules.review_domains || [];
  const addRules = [];
  allowed.slice(0, 1500).forEach((domain, index) => {
    addRules.push({
      id: index + 1,
      priority: domain.length * 10 + 1,
      action: { type: "allow" },
      condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
    });
  });
  blocked.slice(0, 2500).forEach((domain, index) => {
    addRules.push({
      id: 2001 + index,
      priority: domain.length * 10,
      action: {
        type: "redirect",
        redirect: { extensionPath: "/blocked.html?kind=blocked" }
      },
      condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
    });
  });
  review.slice(0, 1000).forEach((domain, index) => {
    addRules.push({
      id: 5001 + index,
      priority: domain.length * 10,
      action: {
        type: "redirect",
        redirect: { extensionPath: "/blocked.html?kind=review" }
      },
      condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
    });
  });
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: Array.from({ length: 6000 }, (_, index) => index + 1),
    addRules
  });
  await chrome.storage.local.set({
    lastRulesSync: new Date().toISOString(),
    ruleCount: addRules.length
  });
  await chrome.storage.local.remove("nativeHostError");
  return addRules.length;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("refreshRules", { periodInMinutes: RULES_REFRESH_MINUTES });
  refreshRules().catch(async (error) => {
    await chrome.storage.local.set({ nativeHostError: error.message });
    console.error("PrivSentinel rule refresh failed:", error);
  });
});

chrome.runtime.onStartup.addListener(() => {
  refreshRules().catch(async (error) => {
    await chrome.storage.local.set({ nativeHostError: error.message });
    console.error("PrivSentinel rule refresh failed:", error);
  });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "refreshRules") {
    refreshRules().catch(async (error) => {
      await chrome.storage.local.set({ nativeHostError: error.message });
      console.error("PrivSentinel rule refresh failed:", error);
    });
  }
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || !/^https?:\/\//i.test(details.url)) return;
  nativeRequest({ type: "visit", url: details.url })
    .then(async (result) => {
      if (result.action !== "block" && result.action !== "review") return;
      const key = `blocked-${details.tabId}`;
      await chrome.storage.local.set({
        [key]: {
          url: details.url,
          domain: result.domain,
          action: result.action,
          provider: result.provider,
          detail: result.detail,
          savedAt: Date.now()
        }
      });
      await chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(`blocked.html?kind=${result.action}`)
      });
    })
    .catch((error) => {
      chrome.storage.local.set({ nativeHostError: error.message });
      console.error("PrivSentinel site check failed:", error);
    });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "get_block_context") {
    const tabPromise = typeof sender.tab?.id === "number"
      ? Promise.resolve(sender.tab)
      : chrome.tabs.query({ active: true, lastFocusedWindow: true }).then(([tab]) => tab);
    tabPromise.then((tab) => {
      if (typeof tab?.id !== "number") {
        sendResponse({ error: "The blocked tab could not be identified." });
        return;
      }
      chrome.storage.local.get(`blocked-${tab.id}`).then((result) => {
        sendResponse(result[`blocked-${tab.id}`] || {
          error: "The blocked-site details are unavailable. Refresh the rules and try again."
        });
      });
    });
    return true;
  }
  if (message?.type === "allow_domain") {
    nativeRequest({ type: "allow_domain", domain: message.domain })
      .then(async (rules) => {
        await refreshRulesFromResponse(rules);
        sendResponse({ success: true });
      })
      .catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  if (message?.type === "refresh_rules") {
    refreshRules()
      .then((count) => sendResponse({ count }))
      .catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  return false;
});

async function refreshRulesFromResponse(rules) {
  const allowed = rules.allowed_domains || [];
  const blocked = rules.blocked_domains || [];
  const review = rules.review_domains || [];
  const addRules = [];
  allowed.slice(0, 1500).forEach((domain, index) => addRules.push({
    id: index + 1,
    priority: domain.length * 10 + 1,
    action: { type: "allow" },
    condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
  }));
  blocked.slice(0, 2500).forEach((domain, index) => addRules.push({
    id: 2001 + index,
    priority: domain.length * 10,
    action: { type: "redirect", redirect: { extensionPath: "/blocked.html?kind=blocked" } },
    condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
  }));
  review.slice(0, 1000).forEach((domain, index) => addRules.push({
    id: 5001 + index,
    priority: domain.length * 10,
    action: { type: "redirect", redirect: { extensionPath: "/blocked.html?kind=review" } },
    condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] }
  }));
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: Array.from({ length: 6000 }, (_, index) => index + 1),
    addRules
  });
  await chrome.storage.local.set({
    lastRulesSync: new Date().toISOString(),
    ruleCount: addRules.length
  });
}
