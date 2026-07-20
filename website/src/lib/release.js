export const release = {
  version: "1.0.0-beta",
  tag: "v1.0.0-beta",
  published: "2026.07.20",
  pageUrl: "https://github.com/ryan-wong-coder/trustdb/releases/tag/v1.0.0-beta",
  dockerUrl: "https://hub.docker.com/r/wsy19990317/trustdb",
};

const releaseBase = "https://github.com/ryan-wong-coder/trustdb/releases/download/v1.0.0-beta";

export function assetUrl(filename) {
  return `${releaseBase}/${filename}`;
}

export const checksumsAsset = {
  label: "SHA256SUMS",
  filename: "SHA256SUMS",
  url: assetUrl("SHA256SUMS"),
};

const desktopAsset = (os, arch, extension, label) => ({
  label,
  filename: `trustdb-desktop-${release.version}-${os}-${arch}.${extension}`,
  url: assetUrl(`trustdb-desktop-${release.version}-${os}-${arch}.${extension}`),
});

const desktopNamedAsset = (os, arch, suffix, label) => ({
  label,
  filename: `trustdb-desktop-${release.version}-${os}-${arch}-${suffix}`,
  url: assetUrl(`trustdb-desktop-${release.version}-${os}-${arch}-${suffix}`),
});

const binaryAsset = (os, arch, extension, label) => ({
  label,
  filename: `trustdb-${release.version}-${os}-${arch}.${extension}`,
  url: assetUrl(`trustdb-${release.version}-${os}-${arch}.${extension}`),
});

export const desktopDownloads = [
  {
    platform: "macOS",
    arch: "Apple Silicon · arm64",
    format: "DMG",
    description: "桌面客户端",
    primary: desktopAsset("darwin", "arm64", "dmg", "下载 DMG"),
    extras: [
      desktopAsset("darwin", "arm64", "zip", "ZIP"),
      desktopAsset("darwin", "arm64", "cer", "证书"),
      desktopNamedAsset("darwin", "arm64", "certificate.txt", "证书指纹"),
    ],
  },
  {
    platform: "macOS",
    arch: "Intel · x86-64",
    format: "DMG",
    description: "桌面客户端",
    primary: desktopAsset("darwin", "amd64", "dmg", "下载 DMG"),
    extras: [
      desktopAsset("darwin", "amd64", "zip", "ZIP"),
      desktopAsset("darwin", "amd64", "cer", "证书"),
      desktopNamedAsset("darwin", "amd64", "certificate.txt", "证书指纹"),
    ],
  },
  {
    platform: "Windows",
    arch: "ARM64",
    format: "SETUP.EXE",
    description: "桌面客户端",
    primary: desktopNamedAsset("windows", "arm64", "setup.exe", "下载安装程序"),
    extras: [
      desktopAsset("windows", "arm64", "msi", "MSI"),
      desktopAsset("windows", "arm64", "exe", "便携 EXE"),
      desktopAsset("windows", "arm64", "zip", "ZIP"),
      desktopAsset("windows", "arm64", "cer", "证书"),
      desktopNamedAsset("windows", "arm64", "certificate.txt", "证书指纹"),
    ],
  },
  {
    platform: "Windows",
    arch: "Intel / AMD · x86-64",
    format: "SETUP.EXE",
    description: "桌面客户端",
    primary: desktopNamedAsset("windows", "amd64", "setup.exe", "下载安装程序"),
    extras: [
      desktopAsset("windows", "amd64", "msi", "MSI"),
      desktopAsset("windows", "amd64", "exe", "便携 EXE"),
      desktopAsset("windows", "amd64", "zip", "ZIP"),
      desktopAsset("windows", "amd64", "cer", "证书"),
      desktopNamedAsset("windows", "amd64", "certificate.txt", "证书指纹"),
    ],
  },
];

export const binaryDownloads = [
  { platform: "Linux", arch: "amd64", format: "tar.gz", description: "服务器 · CLI", primary: binaryAsset("linux", "amd64", "tar.gz", "下载") },
  { platform: "Linux", arch: "arm64", format: "tar.gz", description: "服务器 · CLI", primary: binaryAsset("linux", "arm64", "tar.gz", "下载") },
  { platform: "macOS", arch: "Apple Silicon · arm64", format: "tar.gz", description: "服务器 · CLI", primary: binaryAsset("darwin", "arm64", "tar.gz", "下载") },
  { platform: "macOS", arch: "Intel · x86-64", format: "tar.gz", description: "服务器 · CLI", primary: binaryAsset("darwin", "amd64", "tar.gz", "下载") },
  { platform: "Windows", arch: "ARM64", format: "ZIP", description: "服务器 · CLI", primary: binaryAsset("windows", "arm64", "zip", "下载") },
  { platform: "Windows", arch: "Intel / AMD · x86-64", format: "ZIP", description: "服务器 · CLI", primary: binaryAsset("windows", "amd64", "zip", "下载") },
];

export const homeDownloadGroups = [
  {
    eyebrow: "Desktop / macOS",
    title: "Mac 客户端",
    description: "适用于 Apple Silicon 与 Intel Mac。",
    downloads: desktopDownloads.slice(0, 2).map(({ arch, primary }) => ({ ...primary, label: arch })),
  },
  {
    eyebrow: "Desktop / Windows",
    title: "Windows 客户端",
    description: "适用于 Windows ARM64 与 x86-64。",
    downloads: desktopDownloads.slice(2).map(({ arch, primary }) => ({ ...primary, label: arch })),
  },
  {
    eyebrow: "Server · CLI / Linux",
    title: "Linux",
    description: "压缩包内含服务器、CLI、配置和 Admin Web。",
    downloads: binaryDownloads.slice(0, 2).map(({ arch, primary }) => ({ ...primary, label: arch })),
  },
  {
    eyebrow: "Server · CLI / More",
    title: "macOS 与 Windows",
    description: "用于本机服务、自动化任务和离线验证。",
    downloads: [binaryDownloads[2], binaryDownloads[3], binaryDownloads[4], binaryDownloads[5]].map(({ platform, arch, primary }) => ({ ...primary, label: `${platform} ${arch}` })),
  },
];
