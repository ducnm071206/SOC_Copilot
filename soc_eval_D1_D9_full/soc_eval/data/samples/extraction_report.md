# Bao cao trich mau (D2) — doi chieu voi checklist

- Seed: 42
- Raw pool: `data/raw/alerts_temp.json` (15055 alert, 35 rule.id)
- Curated dir (mauN cu): `data/samples_curated_original`

## 1. Cac rule checklist yeu cau bo sung

| rule.id | co trong pool that? | so luong that | da lay | ghi chu |
|---|---|---:|---:|---|
| 31103 | CO | 2 | 2 | SQLi - checklist D2 yeu cau bo sung |
| 31105 | CO | 163 | 3 | XSS - checklist D2 yeu cau bo sung |
| 550 | CO | 24 | 3 | Integrity checksum changed - checklist yeu cau tren duong dan LANH TINH; PHAI KIEM TRA THU CONG path/uid/gname truoc khi gan nhan, script khong tu suy ra lanh tinh hay khong |
| 40112 | CO | 2 | 2 | Multiple auth failures followed by success (level 12) - checklist yeu cau bo sung |
| 31168 | CO | 4 | 3 | Shellshock attack detected (level 15) - checklist yeu cau bo sung |
| 510 | CO | 10 | 3 | NGHI FALSE POSITIVE cua rootcheck - XAC MINH THU CONG TRUOC KHI GAN NHAN, khong duoc gan nhan tu dong |

## 2. Mau bo sung cho cac rule khac trong pool (khong bat buoc, de da dang)

- Da lay them 56 mau tu 29 rule con lai (toi da 2 mau/rule).

## 3. Doi chieu va sua cac file mau cu (mauN...)

**Luu y quan trong ve nguon goc**: nhieu file trong `mauN...` truoc day duoc mo ta la "mot so log duoc viet boi AI dua tren log that", nhung kiem tra sha256 cho thay phan lon thuc ra la BAN COPY NGUYEN VAN 100% tu pool that (khong phai AI tong hop). Xem cot cuoi.

| file cu | rule theo TEN file | rule THAT trong noi dung | khop ten/rule? | quyet dinh & nguon that su |
|---|---|---|---|---|
| mau10_portscan_100200.json | 100200 | 100200 (Possible port scan detected: multiple po) | KHOP | doi ten -> 100200_1.json (AI/thu cong MOI) |
| mau11_priv_esc_5407.json | 5407 | 5403 (First time user executed sudo.) | LECH | doi ten -> 5403_2.json ; GAN NHAN GOI Y = lanh tinh (nguoi gan nhan van phai tu quyet dinh cuoi cung) (COPY THAT) |
| mau12_malware_clamav_52505.json | 52505 | 52505 (ClamAV: Virus detected: Eicar-Test-Signa) | KHOP | doi ten -> 52505_1.json (AI/thu cong MOI) |
| mau14_webshell_100210.json | 100210 | 100210 (Web shell command execution detected via) | KHOP | doi ten -> 100210_1.json (AI/thu cong MOI) |
| mau16_web_login_bruteforce_100220.json | 100220 | 100220 (Multiple failed login attempts to web ap) | KHOP | doi ten -> 100220_1.json (AI/thu cong MOI) |
| mau1_ssh_invalid_user_5716.json | 5716 | 5710 (sshd: Attempt to login using a non-exist) | LECH | doi ten -> 5710_3.json (COPY THAT) |
| mau2_ssh_bad_password_5711.json | 5711 | 5760 (sshd: authentication failed.) | LECH | doi ten -> 5760_3.json (COPY THAT) |
| mau3_ssh_bruteforce_5712.json | 5712 | 5712 (sshd: brute force trying to get access t) | KHOP | doi ten -> 5712_3.json (COPY THAT) |
| mau4_sqli_31101.json | 31101 | 31106 (A web attack returned code 200 (success)) | LECH | doi ten -> 31106_3.json (COPY THAT) |
| mau5_xss_31105.json | 31105 | 31106 (A web attack returned code 200 (success)) | LECH | doi ten -> 31106_4.json (COPY THAT) |
| mau6_fim_file_added_554.json | 554 | 554 (File added to the system.) | KHOP | doi ten -> 554_3.json (COPY THAT) |
| mau7_fim_file_modified_550.json | 550 | 550 (Integrity checksum changed.) | KHOP | doi ten -> 550_4.json (COPY THAT) |
| mau8_ssh_success_5715.json | 5715 | 5715 (sshd: authentication success.) | KHOP | doi ten -> 5715_2.json (COPY THAT) |
| mau9_web_path_scan_31151.json | 31151 | 31151 (Multiple web server 400 error codes from) | KHOP | doi ten -> 31151_3.json (COPY THAT) |

## 4. SOP/rule ma pool that KHONG CO alert nao (quyet dinh (a)/(b) can nguoi lam)

- **Port scan (SOP)** (rule `100200`): 0 alert that trong pool. Co mau curated/AI thay the. Theo checklist D2, can chon: (a) tao du lieu lab moi (vd chay nmap that, kem log firewall co decoder), hoac (b) ghi ro la gioi han va loai SOP nay khoi danh gia theo lop. Script nay khong tu quyet dinh thay - **can nguoi phu trach chon va ghi vao day**.
- **Privilege escalation (SOP) - LUU Y: 5407 khong phai ma rule Wazuh chuan tung thay; kiem tra xem co phai nham voi 5402/5403 khong** (rule `5407`): 0 alert that trong pool. KHONG co mau nao ca. Theo checklist D2, can chon: (a) tao du lieu lab moi (vd chay nmap that, kem log firewall co decoder), hoac (b) ghi ro la gioi han va loai SOP nay khoi danh gia theo lop. Script nay khong tu quyet dinh thay - **can nguoi phu trach chon va ghi vao day**.
- Ghi chu rieng: rule `5402` ("Successful sudo to ROOT executed") co 13 alert THAT trong pool va co the la ung vien gan hon cho SOP 'leo thang dac quyen' so voi rule 5403 (chi la lan dau dung sudo, khong dong nghia voi tan cong). Neu chon dung 5402 lam dai dien cho SOP nay, can lay mau tu day thay vi chi dung file curated 'priv_esc' cu.

## 5. Kiem tra hai mau 'giong het nhau' do thieu truong url

- Khong phat hien cap nao trong tap mau da trich lan nay.

## 6. Trung lap sha256 (toan bo record)

- So mau bi loai vi trung lap hoan toan voi mau da ghi truoc do: **5**
- Test yeu cau cua checklist ('khong co hai file trung sha256') coi nhu PASS neu so nay = 0 sau khi loai bo cac dong '(bo qua - trung lap)' khoi thu muc data/samples.
