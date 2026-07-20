import { useEffect, useLayoutEffect, useRef } from "react";
import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { ArrowRight } from "@phosphor-icons/react";
import { SiteFooter, SiteHeader, PageHero } from "./components/SiteChrome";
import { useRoute, Link } from "./router";
import { HomePage } from "./pages/HomePage";
import { CliDocsPage, DesktopDocsPage, DesktopInstallPage, DocsIndexPage, MissingDocsPage, QuickStartPage, SdkDocsPage, ServerDocsPage, SourceBuildPage } from "./pages/DocsPages";
import { PerformancePage } from "./pages/PerformancePage";
import { SproofPage } from "./pages/SproofPage";
import { ChangelogPage, DownloadsPage } from "./pages/ReleasePages";
import { t, useLocale } from "./i18n";

gsap.registerPlugin(ScrollTrigger, useGSAP);

const titles = {
  "/": "TrustDB · 可验证证据数据库",
  "/docs": "文档中心 · TrustDB",
  "/docs/quick-start": "快速开始 · TrustDB 文档",
  "/docs/server": "服务器 · TrustDB 文档",
  "/docs/cli": "CLI · TrustDB 文档",
  "/docs/sdk": "Go SDK · TrustDB 文档",
  "/docs/desktop": "桌面客户端 · TrustDB 文档",
  "/docs/desktop-install": "安装桌面客户端 · TrustDB 文档",
  "/docs/source-build": "从源码构建 · TrustDB 文档",
  "/performance": "性能基线 · TrustDB",
  "/sproof": ".sproof v1 · TrustDB",
  "/changelog": "版本与开发日志 · TrustDB",
  "/downloads": "下载 · TrustDB",
};

function RouteView({ route }) {
  if (route === "/") return <HomePage />;
  if (route === "/docs") return <DocsIndexPage />;
  if (route === "/docs/quick-start") return <QuickStartPage route={route} />;
  if (route === "/docs/server") return <ServerDocsPage route={route} />;
  if (route === "/docs/cli") return <CliDocsPage route={route} />;
  if (route === "/docs/sdk") return <SdkDocsPage route={route} />;
  if (route === "/docs/desktop") return <DesktopDocsPage route={route} />;
  if (route === "/docs/desktop-install") return <DesktopInstallPage route={route} />;
  if (route === "/docs/source-build") return <SourceBuildPage route={route} />;
  if (route.startsWith("/docs/")) return <MissingDocsPage />;
  if (route === "/performance") return <PerformancePage />;
  if (route === "/sproof") return <SproofPage />;
  if (route === "/changelog") return <ChangelogPage />;
  if (route === "/downloads") return <DownloadsPage />;
  return <PageHero eyebrow="404 / Not found" title={<>这里没有<br />证据。</>} lead="这个页面不存在，或者地址已经发生变化。"><div className="page-hero__actions"><Link className="button button--solid" href="/">返回首页 <ArrowRight /></Link></div></PageHero>;
}

export function App() {
  const { route, navigationKey } = useRoute();
  const locale = useLocale();
  const root = useRef(null);

  useEffect(() => {
    document.title = t(titles[route] || "页面未找到 · TrustDB");
  }, [route, locale]);

  useLayoutEffect(() => {
    const rootElement = document.documentElement;
    const previousBehavior = rootElement.style.scrollBehavior;
    let cancelled = false;
    let userMoved = false;
    rootElement.style.scrollBehavior = "auto";
    ScrollTrigger.clearScrollMemory("manual");

    const markUserMoved = () => { userMoved = true; };
    const placePage = (force = false) => {
      if (cancelled || (!force && userMoved)) return;
      const targetId = decodeURIComponent(window.location.hash.slice(1));
      if (targetId) document.getElementById(targetId)?.scrollIntoView({ block: "start" });
      else window.scrollTo(0, 0);
    };

    ["wheel", "touchstart", "pointerdown", "keydown"].forEach((eventName) => window.addEventListener(eventName, markUserMoved, { passive: true }));
    placePage(true);
    const frame = window.requestAnimationFrame(() => placePage(true));
    const settle = window.setTimeout(placePage, 140);
    const restore = window.setTimeout(() => {
      placePage();
      rootElement.style.scrollBehavior = previousBehavior;
    }, 260);

    const images = Array.from(root.current?.querySelectorAll("img") || []);
    const imagesReady = Promise.allSettled(images.map((image) => {
      if (image.complete) return image.decode?.() || Promise.resolve();
      return new Promise((resolve) => {
        image.addEventListener("load", resolve, { once: true });
        image.addEventListener("error", resolve, { once: true });
      });
    }));
    imagesReady.then(() => window.requestAnimationFrame(() => placePage()));
    document.fonts?.ready.then(() => window.requestAnimationFrame(() => placePage()));

    return () => {
      cancelled = true;
      window.cancelAnimationFrame(frame);
      window.clearTimeout(settle);
      window.clearTimeout(restore);
      ["wheel", "touchstart", "pointerdown", "keydown"].forEach((eventName) => window.removeEventListener(eventName, markUserMoved));
      rootElement.style.scrollBehavior = previousBehavior;
    };
  }, [route, navigationKey]);

  useGSAP(() => {
    const media = gsap.matchMedia();
    media.add("(prefers-reduced-motion: no-preference)", () => {
      const intro = gsap.timeline({ defaults: { ease: "power3.out" } });
      intro.from(".site-header", { y: -24, opacity: 0, duration: .65 });

      if (route === "/") {
        intro.from(".hero__eyebrow, .hero__title, .hero__copy, .hero__actions", { y: 42, opacity: 0, duration: .82, stagger: .08 }, "-=.3");
      } else {
        intro.from(".page-hero__eyebrow, .page-hero h1, .page-hero__lead, .page-hero__meta, .page-hero__actions, .docs-title > *", { y: 34, opacity: 0, duration: .72, stagger: .065 }, "-=.28");
      }

      gsap.utils.toArray("[data-reveal]").forEach((element) => {
        gsap.from(element, {
          scrollTrigger: { trigger: element, start: "top 86%", once: true },
          y: 42,
          opacity: 0,
          duration: .82,
          ease: "power3.out",
        });
      });

      if (root.current.querySelector(".proof-step")) {
        gsap.from(".proof-step", {
          scrollTrigger: { trigger: ".proof-rail", start: "top 78%", once: true },
          opacity: 0,
          y: 28,
          stagger: .1,
          duration: .68,
          ease: "power2.out",
        });
      }

      if (root.current.querySelector(".journey__image")) {
        gsap.to(".journey__image", {
          scrollTrigger: { trigger: ".journey", start: "top bottom", end: "bottom top", scrub: 1.1 },
          yPercent: 8,
          ease: "none",
        });
      }

      if (root.current.querySelector(".metric-bar__fill")) {
        gsap.fromTo(".metric-bar__fill", { scaleX: 0 }, {
          scaleX: (index, element) => Number(element.style.getPropertyValue("--metric-scale")),
          transformOrigin: "left center",
          duration: 1.25,
          stagger: .1,
          ease: "power3.out",
          scrollTrigger: { trigger: ".metric-bars", start: "top 82%", once: true },
        });
      }

      if (root.current.querySelector(".why-trustdb__art img")) {
        gsap.from(".why-trustdb__art img", {
          clipPath: "inset(0 100% 0 0)",
          duration: 1.35,
          ease: "power3.inOut",
          scrollTrigger: { trigger: ".why-trustdb__art", start: "top 82%", once: true },
        });
        gsap.from(".why-trustdb__art figcaption span", {
          opacity: 0,
          y: 12,
          stagger: .12,
          duration: .55,
          ease: "power2.out",
          scrollTrigger: { trigger: ".why-trustdb__art", start: "top 76%", once: true },
        });
      }
    });

    const refresh = window.setTimeout(() => ScrollTrigger.refresh(), 80);
    return () => {
      window.clearTimeout(refresh);
      media.revert();
    };
  }, { scope: root, dependencies: [route], revertOnUpdate: true });

  return (
    <div ref={root} className={`site site--${route === "/" ? "home" : "inner"}`}>
      <SiteHeader route={route} />
      <main key={route}><RouteView route={route} /></main>
      <SiteFooter />
    </div>
  );
}
