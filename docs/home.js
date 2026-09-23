/* Both languages are static HTML. This only remembers a reader's choice. */
(() => {
  const key = "iorec.home.language";
  const url = new URL(window.location.href);
  const explicit = url.searchParams.get("lang");
  const language = document.documentElement.lang === "en" ? "en" : "zh";
  const valid = value => value === "zh" || value === "en";
  const remember = value => {
    try { window.localStorage.setItem(key, value); } catch { /* Storage is optional. */ }
  };
  const target = value => {
    const current = new URL(window.location.href);
    const next = new URL(value === "en" ? "index.en.html" : "./", current);
    next.search = current.search;
    next.searchParams.set("lang", value);
    next.hash = current.hash;
    return next;
  };
  let preferred = null;
  try { preferred = window.localStorage.getItem(key); } catch { /* Keep the static page. */ }
  if (valid(explicit)) {
    remember(explicit);
    if (explicit !== language) {
      window.location.replace(target(explicit).href);
      return;
    }
  } else if (language === "zh" && !url.searchParams.has("lang") && preferred === "en") {
    window.location.replace(target("en").href);
    return;
  }
  const links = document.querySelectorAll("[data-language]");
  const updateLinks = () => links.forEach(link => { link.href = target(link.dataset.language).href; });
  updateLinks();
  window.addEventListener("hashchange", updateLinks);
  window.addEventListener("popstate", updateLinks);
  links.forEach(link => {
    const value = link.dataset.language;
    link.addEventListener("click", event => {
      link.href = target(value).href;
      if (event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
        remember(value);
      }
    });
  });
})();
