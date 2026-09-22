# Bao cao metric (D4/D6 so bo)

**CANH BAO BAT BUOC** (checklist D4): vi co mau nho, moi con so duoi day duoc bao cao dang `k/n` kem khoang tin cay Wilson 95%, KHONG duoc doc/trich dan nhu ty le phan tram chinh xac tuyet doi (vd khong noi 'model dat 93,4% chinh xac'). KET QUA CHI PHAN ANH DU LIEU CUA 1 LAB NAY, KHONG duoc khai quat ra ngoai pham vi du lieu da thu thap.

> **LUU Y**: `data/labels.csv` hien CHUA CO nhan nao duoc dien (Duc/Binh chua gan nhan). Cac metric can nhan (recommended_action, is_true_positive, severity) deu hien thi `0/0` duoi day - day la HANH VI DUNG (khong bia so), khong phai loi. Sau khi co nhan that, chay lai script nay.

## Tong quan tat ca ket qua da nap

- Tong so dong ket qua (moi to hop model/mode/run): 361
- Loi hoac khong parse duoc JSON: 47
- Khop duoc voi it nhat 1 nhan that trong labels.csv: 0

## Ket qua theo tung to hop (model, mode)

| model | mode | recommended_action | is_true_positive | severity (khop dung) | severity (lech <=1 bac) |
|---|---|---|---|---|---|
| mock-model | full_context | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |
| mock-model | none | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |
| mock-model | rag | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |
| mock-model | rule_map | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |

## Do tre (giay) - DA LOAI BO lan goi dau tien/cold-start cho tung (model, mode)

| model | mode | n (loai cold-start) | n (goc, gom cold-start) | mean | median | p95 |
|---|---|---:|---:|---:|---:|---:|
| mock-model | full_context | 74 | 76 | 0.076s | 0.078s | 0.098s |
| mock-model | none | 74 | 76 | 0.076s | 0.078s | 0.098s |
| mock-model | rag | 74 | 76 | 0.076s | 0.078s | 0.098s |
| mock-model | rule_map | 83 | 86 | 0.076s | 0.078s | 0.098s |

## Ca sai (mismatches) - de D6 phan tich 10 ca sai nang nhat

- Tong so ca sai (tren tat ca truong/to hop): 0
- Chi tiet tung ca nam trong `docs/figures/metrics_report.json` (khoa `mismatches` trong tung to hop model/mode) - dung file JSON de loc/sap xep khi viet D6.

---
_Sinh boi `eval/metrics.py`. Ket qua am tinh (vd mode nao do KHONG tot hon mode khac) van la ket qua hop le va PHAI duoc bao cao trung thuc, khong chi bao cao ket qua co loi._