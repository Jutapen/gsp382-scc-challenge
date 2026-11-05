# GSP382 – Security Command Center Challenge Lab (Referensi Belajar)

Author: **Jutapen** · MIT License

> ⚠️ **DISCLAIMER**
> Repo ini hanya untuk **pembelajaran**. Gunakan dengan bijak.
> Menjalankan script di challenge lab dapat dianggap menyimpang dari
> ketentuan Google Cloud Skills Boost. **Penulis tidak bertanggung jawab**
> atas akun yang diblokir/banned, badge yang dicabut, atau konsekuensi
> lain. Risiko sepenuhnya ada pada pengguna.
> **Disarankan: kerjakan manual dulu, pakai script hanya untuk membandingkan.**

## Status
Belum diverifikasi penuh. Task 4 (API Web Security Scanner) dan Task 5
(export lewat `gcloud scc findings list`, bukan tombol Export console) bisa
berbeda hasilnya. Selalu cek manual dan klik *Check my progress*.

## Yang dipelajari per task
| Task | Konsep |
|------|--------|
| 1 | Atur time range SCC ke 180 hari (manual di UI, tidak bisa lewat script) |
| 2 | Static mute rule: filter finding berdasarkan `category` |
| 3 | Firewall rule terbuka 0.0.0.0/0 untuk SSH (22) / RDP (3389) → batasi ke `35.235.240.0/20` (range IAP) |
| 4 | Reserve static IP, lalu jalankan Web Security Scanner ke `http://IP:8080` |
| 5 | Export findings ke bucket GCS (regional, `us-west1`) sebagai `findings.jsonl` |

## Cara pakai
1. Buka Cloud Shell dengan **akun student lab** (bukan akun pribadi).
2. Kerjakan Task 1 manual.
3. Jalankan:
   ```bash
   bash scc_lab.sh            # Project ID otomatis dari gcloud
   bash scc_lab.sh PROJECT_ID # atau tentukan manual
   ```
4. Di setiap jeda, klik *Check my progress*, lalu tekan ENTER.

Script idempotent: resource yang sudah ada akan di-`[skip]`.

## Jangan commit
Username, password, dan Project ID dari panel lab.
