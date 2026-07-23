# TrustDB brand assets

The canonical TrustDB mark is the green check icon used by the desktop application:

[`clients/desktop/build/appicon.png`](../../clients/desktop/build/appicon.png)

Do not redraw the check, change its proportions, or introduce a separate repository logo. Product surfaces may resize the canonical PNG while preserving its aspect ratio and transparent background.

## Repository social preview

[`social-preview.png`](social-preview.png) is the 1280×640 image uploaded in the GitHub repository settings. It places the canonical mark on the same deep-green background used by the icon border.

To regenerate it on macOS:

```sh
preview_dir=$(mktemp -d)
sips -Z 360 clients/desktop/build/appicon.png --out "$preview_dir/mark.png"
sips --padToHeightWidth 640 1280 --padColor 07110B \
  "$preview_dir/mark.png" --out assets/brand/social-preview.png
rm -rf "$preview_dir"
```

The GitHub organization avatar should use the canonical `appicon.png`, not the padded social-preview image.
