# eval/REPORT.md - Bao cao ket qua danh gia (D6)

**Nhac lai nguyen tac bao cao (checklist D4/D6)**: du lieu tu MOT lab, mau nho -> moi con so bao cao dang k/n kem khoang tin cay Wilson (xem `docs/figures/metrics_report.md`), KHONG khai quat ra ngoai pham vi du lieu nay. Ket qua AM TINH (vd mode nao do khong tot hon mode khac) VAN duoc bao cao trung thuc ben duoi, khong bi bo qua.

> ## ⚠️ CHUA CO NHAN THAT
> `data/labels.csv` hien chua co dong nao duoc Duc/Binh gan nhan, nen TOAN BO metric ben duoi deu la `0/0`. Day la trang thai DUNG (khong bia so), khong phai loi. File nay se TU DONG co so lieu that khi chay lai (`python3 eval/metrics.py ... && python3 eval/report.py ...`) sau khi lao dong gan nhan (D3, phan phu thuoc nguoi khac) hoan tat.

## Bieu do

![accuracy_by_group.png](figures/accuracy_by_group.png)
![latency_by_group.png](figures/latency_by_group.png)

## Bang tong hop theo to hop (model, mode)

| model\|mode | tong dong | loi/khong parse | khop hanh dong | khop TP/FP | severity dung | severity lech<=1 |
|---|---:|---:|---|---|---|---|
| mock-model|full_context | 87 | 11 | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |
| mock-model|none | 87 | 11 | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |
| mock-model|rag | 87 | 11 | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |
| mock-model|rule_map | 100 | 14 | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) | 0/0 (khong co du lieu) |

## 10 ca sai nang nhat + goi y nguyen nhan goc

Goi y nguyen nhan duoi day la HEURISTIC TU DONG (dua tren mode, nguon du lieu, do lech severity) - **PHAI xem lai tung ca thu cong** truoc khi ket luan chinh thuc. 4 nhom nguyen nhan theo checklist: **truy xuat sai** (retrieval dua sai/thieu ngu canh SOP), **model sai** (co du ngu canh nhung model van suy luan/tra loi sai), **SOP thieu** (SOP goc khong co huong dan ro cho tinh huong nay), **nhan sai** (nguoi gan nhan co the nham, dac biet voi cac alert mo ho o ranh gioi severity).

_Chua co ca sai nao de phan tich (chua co nhan that - xem canh bao o dau file). Muc nay se tu dong dien khi chay lai script sau khi co nhan._

## Do tre

Xem bang chi tiet (mean/median/p95, da loai cold-start) trong `docs/figures/metrics_report.md`.

## Ket luan tam thoi

_Chua the ket luan gi ve do chinh xac vi chua co nhan that. Sau khi Duc/Binh gan nhan xong (D3 phan phu thuoc) va chay lai pipeline, dien phan nay bang tay dua tren so lieu that, kem ca ket qua am tinh neu co (vd 'RAG khong cho thay cai thien ro ret so voi rule_map trong du lieu nay')._

---
_Sinh boi `eval/report.py`. Doi chieu voi `docs/figures/metrics_report.md` (JSON: `docs/figures/metrics_report.json`) de xem chi tiet day du hon._