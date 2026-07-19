import { useEffect, useState } from "react";

const routeEvent = "trustdb:navigate";

export function normalizePath(pathname) {
  if (!pathname || pathname === "/") return "/";
  return pathname.replace(/\/+$/, "") || "/";
}

export function navigate(href) {
  const url = new URL(href, window.location.origin);
  if (url.origin !== window.location.origin) {
    window.location.assign(url.href);
    return;
  }
  window.history.pushState({}, "", `${url.pathname}${url.search}${url.hash}`);
  window.dispatchEvent(new Event(routeEvent));
}

export function useRoute() {
  const readRoute = () => normalizePath(window.location.pathname);
  const [location, setLocation] = useState(() => ({ route: readRoute(), navigationKey: 0 }));

  useEffect(() => {
    if ("scrollRestoration" in window.history) window.history.scrollRestoration = "manual";
    const update = () => setLocation((current) => ({ route: readRoute(), navigationKey: current.navigationKey + 1 }));
    window.addEventListener("popstate", update);
    window.addEventListener(routeEvent, update);
    return () => {
      window.removeEventListener("popstate", update);
      window.removeEventListener(routeEvent, update);
    };
  }, []);

  return location;
}

export function Link({ href, onClick, children, ...props }) {
  const handleClick = (event) => {
    onClick?.(event);
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      props.target === "_blank"
    ) return;

    const url = new URL(href, window.location.origin);
    if (url.origin !== window.location.origin) return;
    event.preventDefault();
    navigate(href);
  };

  return <a href={href} onClick={handleClick} {...props}>{children}</a>;
}
