import os
import requests

BASE_DIR = r"c:\project\net-ops\offline version\project-root\static"
JS_DIR = os.path.join(BASE_DIR, "js")
CSS_DIR = os.path.join(BASE_DIR, "css")
FONTS_DIR = os.path.join(BASE_DIR, "webfonts")

os.makedirs(JS_DIR, exist_ok=True)
os.makedirs(CSS_DIR, exist_ok=True)
os.makedirs(FONTS_DIR, exist_ok=True)

assets = [
    {
        "url": "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js",
        "path": os.path.join(JS_DIR, "chart.min.js")
    },
    {
        "url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
        "path": os.path.join(CSS_DIR, "fontawesome.all.min.css")
    },
    # Essential Webfonts
    {
        "url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-solid-900.woff2",
        "path": os.path.join(FONTS_DIR, "fa-solid-900.woff2")
    },
    {
        "url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-solid-900.ttf",
        "path": os.path.join(FONTS_DIR, "fa-solid-900.ttf")
    },
    {
        "url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-regular-400.woff2",
        "path": os.path.join(FONTS_DIR, "fa-regular-400.woff2")
    },
     {
        "url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/fa-brands-400.woff2",
        "path": os.path.join(FONTS_DIR, "fa-brands-400.woff2")
    }
]

for asset in assets:
    print(f"Downloading {asset['url']}...")
    try:
        r = requests.get(asset['url'], timeout=10)
        if r.status_code == 200:
            with open(asset['path'], 'wb') as f:
                f.write(r.content)
            print(f"✅ Saved to {asset['path']}")
        else:
            print(f"❌ Failed to download {asset['url']}: Status {r.status_code}")
    except Exception as e:
        print(f"❌ Error downloading {asset['url']}: {e}")
