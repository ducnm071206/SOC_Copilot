# docs/references.md — Tai lieu tham khao (D9)

Moi nguon duoi day da duoc TU KIEM CHUNG bang web search truoc khi dua vao (tac gia,
nam, noi dang) theo dung yeu cau checklist D9. Sap xep theo 3 nhom: (A) LLM trong
triage/phan tich alert SOC, (B) danh gia RAG, (C) OWASP Top 10 for LLM Applications.
Voi moi nguon: tom tat 1-2 dong VA lien he truc tiep toi phan nao cua du an nay.

---

## A. LLM trong triage / phan tich alert SOC

### A1. Khao sat tong quan
**Habibzadeh, A., Feyzi, F., Atani, R. E. (2025).** "Large Language Models for Security
Operations Centers: A Comprehensive Survey." *arXiv:2509.10858* [cs.CR]. Xuat ban chinh
thuc: *Journal of Electrical and Computer Engineering*, 2026, Art. 3383674.
DOI: 10.1155/jece/3383674. — https://arxiv.org/abs/2509.10858

> Khao sat toan dien dau tien (theo loi tac gia tu nhan) ve tich hop LLM vao quy trinh
> SOC: log analysis, triage, threat intelligence. Dung de trich dan boi canh chung khi
> mo dau bao cao (D6) - vi sao du an nay lam eval cho "LLM triage" la huong nghien cuu
> dang duoc quan tam.

### A2. Nghien cuu thuc nghiem gan nhat voi du an nay (dung Wazuh + RAG)
**Kurnia, R., Widyatama, F., Wibawa, I. M., Brata, Z. A., Nelistiani, G. A., Kim, H.
(2025).** "Enhancing Security Operations Center: Wazuh Security Event Response with
Retrieval-Augmented-Generation-Driven Copilot." *Sensors*, 25(3), 870.
DOI: 10.3390/s25030870. — https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11820992/

> **QUAN TRONG NHAT trong danh sach nay** - day la mot "copilot" dung dung Wazuh SIEM +
> RAG + MITRE ATT&CK, gan nhu cung kien truc voi soc_copilot cua nhom. NEN DOC TOAN VAN
> truoc khi viet phan "cong trinh lien quan" cua bao cao, vi co the copy duoc ca cach ho
> thiet ke prompt/kien truc RAG va so sanh truc tiep voi ket qua E1 (D5) cua nhom.

### A3. Ket qua thuc nghiem gan voi cau hoi cua D5 (RAG co hon khong, do chinh xac triage)
**Rieger, M., Shah, A., Alam, A., Hossain, M. J. (2026).** "Possibilities and
limitations of using large language models (LLMs) for alert classification and
prioritisation in security operations centers (SOCs)." *Expert Systems with
Applications* (ScienceDirect), Art. S0957417426021032.
— https://www.sciencedirect.com/science/article/pii/S0957417426021032

> Dung 178 alert gan nhan tay, 8 model LLM (OpenAI/DeepSeek/Ai2) + baseline ML co dien
> (Logistic Regression, Random Forest, SVM). KET QUA CHINH: LLM co **recall cao (>90%)
> cho phan loai TP/FP** nhung **precision thap, nhieu nhieu cho uu tien hoa (severity)**;
> SVM co dien dat F1 tot nhat cho bai toan phan loai nhi phan. **Lien he truc tiep**: neu
> ket qua D4/D5 cua nhom cho thay pattern tuong tu (khop TP/FP tot hon khop severity),
> day la bang chung doc lap ung ho phat hien do, khong phai loi rieng cua pipeline nay.

### A4. Nghien cuu thuc dia quy mo lon (nguoi dung that, khong phai benchmark)
**Singh, R., Tariq, S., Jalalvand, F., Chhetri, M. B., Nepal, S., Paris, C., Lochner,
M. (2025).** "LLMs in the SOC: An Empirical Study of Human-AI Collaboration in Security
Operations Centres." *arXiv:2508.18947*. — https://arxiv.org/abs/2508.18947

> Nghien cuu doc hoc 3090 cau hoi tu 45 SOC analyst that trong 10 thang. Phat hien: nha
> phan tich dung LLM de "sensemaking/context-building" chu KHONG giao quyet dinh cuoi
> cho LLM. **Lien he**: cung co dinh huong cua checklist goc rang SOP/prompt PHAI giu
> con nguoi o vi tri quyet dinh (recommended_action la GOI Y, khong phai lenh tu dong).

### A5. Mot vi du khac dung Wazuh + CALDERA (CANH BAO: PREPRINT, CHUA PEER-REVIEW)
**Singh, Y., Patel, N. D., Shandilya, S. K. (2024).** "Enhancing Security Operations
Center Efficiency through Multi-Model Integration of Large Language Models and SIEM
Systems." *Research Square preprint*. DOI: 10.21203/rs.3.rs-5615639/v1.
— https://www.researchsquare.com/article/rs-5615639/v1

> ⚠️ Day la PREPRINT tren Research Square, CHUA qua binh duyet (peer review) - trich dan
> voi than trong, ghi ro trang thai preprint neu dua vao bao cao chinh thuc. Noi dung:
> so sanh GPT-4/GPT-3.5/LLaMA3/Mixtral/OpenHermes tren Wazuh+CALDERA, GPT-4 dat F1 93%.
> Con so nay KHONG duoc trich dan nhu "ket qua da kiem chung" vi chua peer-review.

---

## B. Danh gia RAG (Retrieval-Augmented Generation)

### B1. Bai bao goc dinh nghia RAG
**Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., Küttler,
H., Lewis, M., Yih, W., Rocktäschel, T., Riedel, S., Kiela, D. (2020).**
"Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *Advances in
Neural Information Processing Systems (NeurIPS) 33*, pp. 9459–9474.
— https://proceedings.neurips.cc/paper/2020/hash/6b493230205f780e1bc26945df7481e5-Abstract.html

> Bai bao dat ten va dinh nghia kien truc RAG (ket hop retriever + generator). Dung de
> trich dan dinh nghia khi giai thich vi sao D5/E1 so sanh `rule_map` / `full_context` /
> `rag` - day la 3 cach khac nhau de dua "non-parametric memory" vao prompt.

### B2. Khung danh gia RAG khong can nhan tham chieu (reference-free)
**Es, S., James, J., Espinosa-Anke, L., Schockaert, S. (2023).** "RAGAS: Automated
Evaluation of Retrieval Augmented Generation." *arXiv:2309.15217*. Ban rut gon xuat
ban tai *Proceedings of the 18th Conference of the European Chapter of the ACL (EACL
2024): System Demonstrations*, pp. 150–158. — https://arxiv.org/abs/2309.15217

> RAGAS danh gia RAG qua 3 truc: context relevance, faithfulness, answer relevance -
> KHONG can nhan nguoi (reference-free). **Lien he**: `eval/metrics.py` cua nhom hien
> dung nhan nguoi (labels.csv) de cham diem - RAGAS la huong mo rong tiem nang cho D5/E1
> khi can danh gia RIENG chat luong buoc truy xuat (retrieval) tach khoi chat luong
> cau tra loi cuoi cung, thay vi chi cham k/n dau ra cuoi nhu hien tai.

### B3. Khao sat tong hop cac phuong phap danh gia RAG (de chon them metric neu can)
**"Evaluation of Retrieval-Augmented Generation: A Survey."** *arXiv:2405.07437*
(2024). — https://arxiv.org/pdf/2405.07437

> Tong hop 12 khung danh gia RAG khac nhau (RAGAS, ARES, TruLens RAG Triad...). Dung
> lam diem tra cuu neu nhom muon nang cap `metrics.py` vuot ra ngoai k/n don gian hien
> tai (vd them do "groundedness" - cau tra loi co bam sat SOP that duoc truy xuat hay
> khong, chu khong chi dung/sai o output cuoi).

---

## C. OWASP Top 10 for LLM Applications

### C1. Tai lieu chinh thuc
**OWASP Foundation (2025).** *OWASP Top 10 for LLM Applications 2025* (phien ban
v4.2.0a, cong bo 2025, cap nhat gan nhat ghi nhan thang 8/2026 tren trang du an chinh).
— PDF chinh thuc: https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf
— Trang du an: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/

> Nguon chinh thuc, khong phai bai blog thu 3. Hang muc lien quan truc tiep den du an:
> - **LLM01:2025 Prompt Injection** — day chinh la co so ly thuyet cho `data/adversarial/`
>   (D3) va cac ca `01_`, `02_`, `03_` trong bo do (URL/username/tham so chua chi thi
>   gia mao). OWASP khuyen nghi "tach biet noi dung khong dang tin va gioi han anh huong
>   len prompt he thong" - dung nguyen tac nay khi thiet ke system prompt trong
>   `eval/analyzer.py` (SYSTEM_PROMPT_TEMPLATE khong duoc coi noi dung trong alert la
>   chi thi).
> - **LLM02:2025 Sensitive Information Disclosure** (tang tu hang 6 len hang 2 trong ban
>   2025) — lien quan truc tiep den D1 (quet thong tin nhay cam trong file alert truoc
>   khi dua vao pool danh gia) va viec KHONG duoc de model tu bia/lo thong tin cau hinh
>   he thong khi tra loi.
> - Khung "RAG Triad" (context relevance, groundedness, QA relevance) ma OWASP de xuat
>   de danh gia dau ra chong doc hai trung voi huong mo rong cua RAGAS (xem B2).

---

## Ghi chu phuong phap (ap dung chung cho ca danh sach)

- Moi nguon deu duoc kiem tra qua web search TRUOC khi dua vao day (khong bia tac gia/
  nam/noi dang). URL kem theo la de nguoi doc tu doi chieu lai.
- Nguon A5 la PREPRINT chua peer-review - da ghi chu ro, khong dung con so cua no nhu
  "da kiem chung" trong phan ket luan cua bao cao chinh (docs/data_provenance.md,
  eval/REPORT.md).
- Danh sach nay UU TIEN nguon 2024-2026 vi day la linh vuc thay doi nhanh; cac bai cu
  hon (vd Lewis et al. 2020 cho RAG goc) duoc giu lai vi la nguon nen tang, khong phai
  vi tinh thoi su.
- Neu D6/eval/REPORT.md sau nay trich dan so lieu tu cac nguon nay (vd "Rieger et al.
  cung thay LLM yeu o prioritisation"), PHAI ghi ro day la so sanh voi nghien cuu KHAC
  tren du lieu KHAC, khong phai bang chung cho cung mot he thong.
