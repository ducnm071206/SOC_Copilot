# Data provenance & profiling — tap alert goc

- Nguon file: `data/raw/alerts_temp.json`
- Sinh boi: `eval/profile_alerts.py` luc 2026-09-20T02:17:11
- Tong so alert: **15055**
- Khoang thoi gian: `2026-08-28T03:13:48.828+0700` -> `2026-08-28T17:03:49.746+0700`
- So rule.id khac nhau: **35**

## ⚠️ Nguon goc du lieu — CAN GHI RO TRUOC KHI DUNG DE DANH GIA

- [ ] Ai chay cong cu gi, luc nao de sinh ra file nay? (dien tay sau khi hoi nguoi da chay lab — script khong biet duoc.)
- Toan bo alert chi den tu **1 agent** va **2 srcip khac nhau** (xem bang ben duoi). Neu chi co 1 srcip tan cong -> day rat co the la 1 phien lab don, khong phai du lieu san xuat that.

- **Canh bao mat can bang nhan**: rule `31101` ("Web server 400 error code.") chiem **12798/15055 (85.0%)** tong so alert. Neu lay mau ngau nhien thuan tuy, ~85% mau se roi vao dung 1 rule nay (dung dieu D3 da canh bao) -> **bat buoc lay mau phan tang theo rule.id**, khong lay ngau nhien.

- **Dau hieu quet tu dong (scanner)**: phat hien cac chu ky sau trong full_log/user-agent. Day la TIN HIEU, khong phai ket luan cuoi — can doi chieu thu cong truoc khi ghi vao bao cao la "day khong phai tan cong thuc":
    - `nikto_default_ua`: 11898 alert — xuat hien o rule 31101 (x10973), rule 31151 (x905), rule 31516 (x15), rule 31104 (x5)
    - `nikto_literal`: 11 alert — xuat hien o rule 31101 (x4), rule 31105 (x3), rule 31103 (x2), rule 31154 (x1), rule 31104 (x1)
    - `shellshock_poc`: 122 alert — xuat hien o rule 31166 (x117), rule 31168 (x4), rule 31151 (x1)
    - Rieng chu ky User-Agent mac dinh cua Nikto xuat hien **11898 lan** trong tong so **12798** alert cua rule `31101` -> phan lon (co the gan nhu toan bo) so alert 'web attack' nay nhieu kha nang la **traffic quet tu dong cua Nikto**, khong phai tan cong thu cong thuc su. **Phai ghi ro dieu nay trong bao cao, khong duoc goi day la 'tan cong SQLi/XSS/Shellshock thuc te'** neu khong doi chieu duoc bang chung khac.
- Khong phat hien alert trung lap hoan toan (sha256 toan bo record) va khong trung truong `id` trong tap alert goc nay.

- Thieu du lieu: 166 alert khong co truong `data`; 63 alert co `data` nhung thieu `srcip`.

## Phan bo theo rule.id

| rule.id | so luong | % | level | mo ta |
|---|---:|---:|---|---|
| 31101 | 12798 | 85.01% | 5 | Web server 400 error code. |
| 31151 | 1056 | 7.01% | 10 | Multiple web server 400 error codes from same source ip. |
| 5710 | 460 | 3.06% | 5 | sshd: Attempt to login using a non-existent user |
| 31105 | 163 | 1.08% | 6 | XSS (Cross Site Scripting) attempt. |
| 31166 | 117 | 0.78% | 6 | Shellshock attack attempt |
| 31104 | 69 | 0.46% | 6 | Common web attack. |
| 2502 | 60 | 0.40% | 10 | syslog: User missed the password more than one time |
| 5503 | 58 | 0.39% | 5 | PAM: User login failed. |
| 5758 | 52 | 0.35% | 8 | Maximum authentication attempts exceeded. |
| 550 | 24 | 0.16% | 7 | Integrity checksum changed. |
| 30305 | 21 | 0.14% | 5 | Apache: Attempt to access forbidden file or directory. |
| 5501 | 18 | 0.12% | 3 | PAM: Login session opened. |
| 31516 | 18 | 0.12% | 6 | Suspicious URL access. |
| 5502 | 17 | 0.11% | 3 | PAM: Login session closed. |
| 31154 | 17 | 0.11% | 10 | Multiple XSS (Cross Site Scripting) attempts from same source ip. |
| 5402 | 13 | 0.09% | 3 | Successful sudo to ROOT executed. |
| 533 | 12 | 0.08% | 7 | Listened ports status (netstat) changed (new port opened or closed). |
| 510 | 10 | 0.07% | 7 | Host-based anomaly detection event (rootcheck). |
| 31121 | 10 | 0.07% | 4 | Web server 501 error code (Not Implemented). |
| 5551 | 9 | 0.06% | 10 | PAM: Multiple failed logins in a small period of time. |
| 31153 | 7 | 0.05% | 10 | Multiple common web attacks from same source ip. |
| 31106 | 6 | 0.04% | 6 | A web attack returned code 200 (success). |
| 80730 | 5 | 0.03% | 3 | Auditd: SELinux permission check. |
| 554 | 5 | 0.03% | 5 | File added to the system. |
| 5712 | 5 | 0.03% | 10 | sshd: brute force trying to get access to the system. Non existent user. |
| 502 | 4 | 0.03% | 3 | Wazuh server started. |
| 553 | 4 | 0.03% | 7 | File deleted. |
| 31168 | 4 | 0.03% | 15 | Shellshock attack detected |
| 5301 | 3 | 0.02% | 5 | User missed the password to change UID (user id). |
| 591 | 2 | 0.01% | 3 | Log file rotated. |
| 5760 | 2 | 0.01% | 5 | sshd: authentication failed. |
| 40112 | 2 | 0.01% | 12 | Multiple authentication failures followed by a success. |
| 31103 | 2 | 0.01% | 7 | SQL injection attempt. |
| 5403 | 1 | 0.01% | 4 | First time user executed sudo. |
| 5715 | 1 | 0.01% | 3 | sshd: authentication success. |

## Phan bo theo level

| level | so luong |
|---|---:|
| 10 | 1154 |
| 12 | 2 |
| 15 | 4 |
| 3 | 60 |
| 4 | 11 |
| 5 | 13347 |
| 6 | 373 |
| 7 | 52 |
| 8 | 52 |

## Phan bo theo agent

| agent | so luong |
|---|---:|
| siftworkstation | 15055 |

## Phan bo theo srcip (top 20)

| srcip | so luong |
|---|---:|
| 192.168.26.10 | 14822 |
| ? | 4 |

## Top groups (rule.groups)

| group | so luong |
|---|---:|
| web | 14288 |
| accesslog | 14249 |
| attack | 13201 |
| web_scan | 1056 |
| recon | 1056 |
| syslog | 701 |
| authentication_failed | 635 |
| sshd | 520 |
| invalid_login | 460 |
| pam | 102 |
| ossec | 61 |
| access_control | 60 |
| syscheck | 33 |
| syscheck_file | 33 |
| syscheck_entry_modified | 24 |
| apache | 21 |
| access_denied | 21 |
| authentication_success | 19 |
| appsec | 18 |
| sudo | 14 |

## Ghi chu ky quy tinh lai so nhom dang dung (muc 0)

So lieu ben tren la ket qua tinh lai truc tiep tu file goc bang script nay (khong copy tay), dung de doi chieu voi cac con so 'nhom' da dung truoc do trong de cuong/bao cao. Neu lech nhau, uu tien so lieu trong file nay (co the tai lap) va cap nhat lai bao cao cu.

---
_File nay duoc sinh tu dong boi `eval/profile_alerts.py`. Phan '⚠️ Nguon goc du lieu' can nguoi phu trach dien tay muc dau tien (ai chay cong cu gi, luc nao) va xac nhan lai cac canh bao truoc khi dua vao bao cao chinh thuc._