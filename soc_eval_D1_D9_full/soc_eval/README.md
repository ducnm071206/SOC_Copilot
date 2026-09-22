# Tien do D1 -> D9 (tru phan phu thuoc Duc/Binh)

## Da xong toan bo cac phan TU LAM DUOC

- **D1** eval/profile_alerts.py -> docs/data_provenance.md
- **D2** eval/extract_samples.py, eval/generate_lab_data.py -> data/samples/, data/lab/
- **D3 (phan tu lam)** eval/generate_adversarial.py, eval/build_labeling_set.py
  -> data/adversarial/, data/labels.csv
- **D4** eval/run_eval.py, analyzer.py, retrieval.py, metrics.py -> harness eval day du
- **D5** eval/run_matrix.py -> dieu phoi E1 (3 mode) + E5 (quet nguong)
- **D6** eval/report.py -> docs/figures/*.png + eval/REPORT.md
- **D7** eval/capture_environment.py -> docs/environment.md (TU DONG thu thap OS/Python/
  pip freeze/git/seed; phan Ollama se "KHONG LAY DUOC" cho toi khi chay tren may that co
  Ollama - da test dung hanh vi nay trong sandbox khong co Ollama)
- **D8** soc_copilot/triage.py -> gom nhom alert theo (rule.id, srcip), sap theo uu tien.
  DA TEST TREN DU LIEU THAT: **15055 alert -> 37 nhom (giam 99.8%)**. Cong thuc uu tien
  dung level lam trong so chinh nen Shellshock (level 15, chi 4 lan) dung len #1, con
  rule Nikto on ao (31101, 12798 lan, level 5) bi day xuong #15 - khop voi phat hien D1
  rang rule nay chu yeu la traffic quet, khong phai tan cong that.
  Da test them voi ca ca adversarial (thieu srcip, JSON la) - KHONG crash.
- **D9** docs/references.md -> 9 nguon hoc thuat DA KIEM CHUNG qua web search

## Con lai (PHU THUOC NGUOI KHAC hoac can may that)

- **D3 phan phu thuoc**: Duc gan nhan data/labels.csv, Binh cham kappa 22 mau, tag freeze-v1
- **D7 hoan chinh**: chay lai `eval/capture_environment.py --models <ten_model_that>`
  TREN MAY THAT co Ollama de dien phan digest/version (hien dang ghi "KHONG LAY DUOC"
  vi may chay script nay khong co Ollama)
- Sau khi co nhan that: chay lai eval/metrics.py + eval/report.py de co so lieu thay vi 0/0
- Rule 100230 (privilege escalation lab), protected_ips.example.txt, data/sop/* - can
  Tai/Binh xac nhan/thay bang du lieu that

## Cach dung soc_copilot/triage.py (D8) - cho Tai lam tab "Hang doi"

    from soc_copilot.triage import load_alerts_ndjson, group_alerts
    alerts = load_alerts_ndjson("data/raw/alerts_temp.json")
    queue = group_alerts(alerts)   # da sap theo uu tien, list[AlertGroup]

Hoac CLI: `python3 soc_copilot/triage.py --input data/raw/alerts_temp.json --out-json <file>`
de xuat JSON cho UI doc truc tiep khong can goi Python.
