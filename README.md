# Social Publisher MVP

URL + başlık + metin ile çoklu sosyal ağ paylaşımı yapan temel bir servis.

## Bu sürümde olanlar

- Çoklu provider seçimi ve tek seferde gönderim
- Provider bazlı config saklama (SQLite)
- Gönderim logları (başarılı/başarısız)
- Basit web paneli
- Render deploy dosyası (`render.yaml`)

## Fazlar (Yol Haritasi)

- Phase 1 (hedef: stabil): Mastodon, Bluesky, Facebook Page
- Phase 2 (beta): LinkedIn, Pinterest
- Phase 3 (beta): Instagram, Reddit
- Phase 4 (placeholder): TikTok, Tumblr
- Phase 5 (operasyon): queue, retry, zamanlama, rate-limit yonetimi

## Dahil edilen providerlar

- LinkedIn
- Facebook Page
- Pinterest
- TikTok (placeholder)
- Mastodon
- Bluesky
- Reddit
- Instagram
- Tumblr (placeholder)
- Digg (manual/share fallback)

Not: `TikTok`, `Tumblr`, `Digg` tarafında bu MVP'de tam otomatik yayın yerine kısıt/placeholder/manual akışı var.

## Lokal çalıştırma

```bash
cd /Users/ramay/Documents/New\ project/social-publisher
python3 server.py
```

Arayüz: [http://127.0.0.1:8081](http://127.0.0.1:8081)

## API özet

- `GET /api/health`
- `GET /api/providers`
- `GET /api/deliveries`
- `POST /api/provider-config`
- `GET /api/provider-config-template?provider=<key>`
- `POST /api/provider-test`
- `POST /api/publish-validate`
- `POST /api/publish`

## Örnek publish

```bash
curl -X POST http://127.0.0.1:8081/api/publish \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Yeni içerik",
    "url": "https://example.com/yazi",
    "text_body": "Kısa açıklama",
    "image_url": "",
    "providers": ["mastodon", "bluesky"]
  }'
```

## Önemli notlar

- Gerçek gönderim için ilgili provider access token/app password bilgilerini `Provider Config` ekranından kaydetmelisin.
- Her platformun oran limiti, izin kapsamı ve kullanım koşulları farklıdır.
