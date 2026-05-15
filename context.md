# MASTER CONTEXT: AUTOMATED DFIR TRIAGE ENGINE
> **Phiên bản:** v8.6 — Principled, Reproducible, and Temporal Architecture
> **Mục tiêu:** Vừa tối ưu Recall vừa đảm bảo minh bạch khoa học, khả năng tái hiện và phát hiện APT Slow-and-Low.
> **Trạng thái:** Production-ready (config-driven)
> **Ngôn ngữ:** Rust (L0) + Python (L1–L4)

---

## 1. MỤC TIÊU HỆ THỐNG

| # | Mục tiêu | Mô tả |
|---|----------|-------|
| 1 | **Giải quyết Alert Fatigue** | Tự động hóa Triage, gạn lọc tiến trình rác để SOC Tier 1/Tier 2 chỉ xử lý các mối đe dọa thực sự. |
| 2 | **Phát hiện APT & LOLBins** | Bắt các kỹ thuật Living-off-the-Land thông qua dị thường chuỗi hành vi (Sequence) và ngữ cảnh (Context), không phụ thuộc chữ ký. |
| 3 | **Plug-and-Play** | Chạy ngay lập tức trên bất kỳ môi trường Windows nào. **Tuyệt đối không cần dữ liệu sạch (Benign baseline) từ trước.** |

---

## 2. YÊU CẦU PHI CHỨC NĂNG

| Tiêu chí | Đặc tả |
|----------|--------|
| **Hiệu năng** | Xử lý file `.evtx` ≥ 1GB trong thời gian tính bằng phút. Giao tiếp L0-L1 thông qua C-binding (PyO3) để đạt Zero-copy memory, xóa bỏ bottleneck I/O. |
| **Explainability (XAI)** | Mọi `Final_Score` phải phân rã được thành các thành phần P, C, S, Seq, Col, CI và trạng thái `effective_weights`. Nghiêm cấm Black-box model. Zero-Whitelist: không check chữ ký, không Trust Factor. |
| **Toàn vẹn Dữ liệu** | Không được làm đứt gãy chuỗi phả hệ tiến trình. Signal Preservation Guarantee: node có `Sigma_Score > 0` hoặc behavioral signal active (`has_network`, `has_injection`, `has_file_drop`, `has_reg_mod`) tuyệt đối không bị dedup. |
| **Key định danh** | Dùng `ProcessGuid` (Sysmon field) làm primary key cho mọi node, **không dùng PID** — PID bị Windows tái sử dụng trên log dài. |

---

## 3. TRIẾT LÝ THIẾT KẾ

| Triết lý | Mô tả |
|----------|-------|
| **Zero Pre-training** | Tự học Baseline trực tiếp trên file log đang phân tích bằng HDBSCAN. Không cần dataset sạch bên ngoài. |
| **Zero-Whitelist / Zero-Blacklist** | Mọi phán quyết đều dựa trên xác suất thống kê nội tại của chính log đó. Không có danh sách cứng, không check chữ ký số, không Trust Factor. Ngoại lệ duy nhất là định luật vật lý của OS (Vd: Shell wrappers). |
| **One-way Pipeline** | Dữ liệu chảy một chiều: L0 → L1 → L2-A → L2-B → L2-C → L3 → L4. L2-C giữ trạng thái liên-run cho chiến dịch dài ngày. |
| **White-box XAI** | Định lượng bằng phương trình toán học tuyến tính. Analyst phải đọc được báo cáo và hiểu ngay tại sao một process bị flag. |
| **Single Source of Truth** | Toàn bộ tham số vận hành nằm trong `config.toml`; code và báo cáo đọc từ cùng nguồn để tránh lệch thực nghiệm. |

---

## 4. KIẾN TRÚC PIPELINE 6 TẦNG

---

### LAYER 0 — DATA INGESTION & PARSER (Lõi Rust)

**Nhiệm vụ:** Tiêu hóa thư mục/danh sách file nhị phân Sysmon, sort theo thời gian, xuất luồng event vào RAM Python.

**Tại sao Rust + PyO3?** Python với GIL không thể đa luồng thực sự khi parse binary I/O. Rust parse cực nhanh, sau đó thông qua `PyO3` truyền thẳng các object Dictionary vào vùng nhớ của Python (Zero-copy). Bỏ qua hoàn toàn chi phí Serialize/Deserialize JSON qua `stdout`.

**9 Event ID được lọc:**
1 (Process), 3 (Network), 8 (CreateRemoteThread), 10 (ProcessAccess - chỉ flag có WRITE_PROCESS_MEMORY 0x0020), 11 (FileDrop), 13 (RegMod), 17 & 18 (Pipe Create/Connect), 22 (DNS).

**Multi-file & Path Normalization:** Đầu vào có thể là Folder. L0 tự động merge các `.evtx`, sort theo UTC. Chuẩn hóa tất cả path về lowercase, forward-slash, resolve `%SystemRoot%`. (Lưu ý: Layer 1 sẽ convert ngược lại sang backslash cho Sigma compatibility).

---

### LAYER 1 — STATIC / SIGMA ENGINE

**Nhiệm vụ:** Quét Known-Threats bằng luật tĩnh SigmaHQ, xuất `Sigma_Score ∈ [0, 10]`.

**Tại sao Max Override thay vì Additive?** Cộng dồn điểm gây Score Explosion. Max Override bám theo triết lý CVSS.
$$S = \max_{i}\bigl(Base\_Score_i \times Confidence\_Multiplier_i\bigr) + 0.25 \times \log_2\bigl(1 + N_{rules\_matched}\bigr)$$

**Cơ chế tương thích & Giảm FP (v8.4.2):**
- **Path Normalization Compatibility:** Trước khi so khớp, L1 convert `Image` và `ParentImage` ngược về backslash format (`c:\windows\...`) để tương thích hoàn toàn với logic SigmaHQ.
- **Confidence Override:** Sử dụng `confidence_override.json` để ghi đè `Confidence_Multiplier` cho từng Rule ID cụ thể. Dùng để "bóp" điểm những rule sinh quá nhiều FP (Vd: Rule `Execution Of Non-Existing File` hạ xuống 0.3).
- **Default Multiplier:** Fallback theo level (Critical=1.0, High=0.9, Medium=0.7, Low=0.5).

---

### LAYER 2-A — GRAPH BUILD & LOSSLESS STRUCTURAL DEDUPLICATION

**Nhiệm vụ:** Xây dựng Directed Graph. Thay thế Pruning cứng bằng nguyên lý "Bảo tồn tính mới".

**Nguyên lý v8.5 — Lossless Structural Deduplication:**
1. **Deduplication (Nén nhiễu):** Một node bị coi là "dư thừa" nếu nó lặp lại một cặp (Cha -> Con) đã tồn tại trong cùng một host/dataset với cùng trạng thái chữ ký và không có hành vi. Ta chỉ giữ lại 1-2 đại diện để gạt bỏ nhiễu lặp (Vd: svchost x1000).
2. **Novelty Preservation (Bảo tồn tính mới):** Tuyệt đối KHÔNG xóa bất kỳ node nào nếu nó là "Duy nhất" (Unique branch). Nếu cặp (Cha -> Con) chỉ xuất hiện 1 lần -> GIỮ LẠI để Layer 3 chấm điểm.
3. **Recon-Awareness:** Các lệnh trinh sát (whoami, ipconfig) thường chỉ chạy 1 lần -> Tự động được bảo vệ bởi nguyên lý Novelty mà không cần whitelist tên file.

**Luật giữ lại (Keep Rules v8.5):**
- **Bridge Protection:** Có tiến trình con (Duy trì cấu trúc cây).
- **Active Signal:** Có Sigma match hoặc có hành vi (Network, File, Registry...).
- **Structural Novelty:** Tần suất cặp (Cha -> Con) <= 1 trong dataset.
- **Shell Preservation:** Các tiến trình thuộc danh sách `SHELL_WRAPPERS`.

---

### LAYER 2-B — BASELINE BUILDER (ĐỘNG CƠ TỰ HỌC)

**Nhiệm vụ:** Xây dựng Behavioral Baseline từ chính log đang phân tích bằng HDBSCAN.

#### 2-B.1 — Sub-pass 0: Đếm tần suất toàn cục (NIF)
Quét toàn bộ EID 1 một lần để tính **NIF (Normalized Inverse Frequency)** — tự động co giãn theo data, bỏ hoàn toàn các threshold cứng 1%, 0.5%:
$$NIF = 1.0 - \frac{\log(Count)}{\log(Count_{max})}$$

#### 2-B.2 — Sub-pass 1: Vector hóa & Clustering ($V_{10}$)
| Dim | Feature | Phân loại |
|-----|---------|-----------|
| v₁-v₄ | `has_network`, `has_injection`, `has_file_drop`, `has_reg_mod` | Binary {0,1} |
| v₅-v₆ | `nif_binary`, `nif_pair` | Continuous [0,1] |
| v₇-v₉ | `entropy_bin`, `cmd_len_bin`, `child_count_bin` | Discrete {0,1,2} |
| v₁₀ | `parent_sigma_bin` (Cha có Sigma >= 3.0) | Binary {0,1} |

**HDBSCAN Clustering:**
- Sampling nếu N > 50,000 để chống OOM, dùng `approximate_predict()`.
- Cluster Ceiling: Gộp vi mô vào cụm lớn bằng Euclidean distance nếu K > 30.
- **VÙNG ĐẤT THÁNH (CLUSTER -1):** Tuyệt đối KHÔNG gộp -1 đi đâu, và không gộp ai vào -1.

**Graceful Degradation Stack:**
- Ưu tiên `hdbscan` khi khả dụng.
- Fallback `dbscan` khi thiếu dependency.
- Cuối cùng `disabled` (all cluster 0) nếu không còn lựa chọn.
- Mỗi run phải xuất `clustering_mode` trong health report.

---

### LAYER 2-C — TEMPORAL AGGREGATION (MỚI)

Persistent state lưu trên SQLite để tích lũy tín hiệu theo thời gian cho mỗi `ProcessGuid`.

$$CS_{new} = CS_{prev}\cdot e^{-\lambda \Delta t} + Event\_Score$$

Trong đó:
- `lambda` (decay constant) lấy từ `config.toml` (`temporal.decay_lambda`).
- Output song song `Event_Score` và `Campaign_Score`.
- Health state của tầng này phải khai báo `AVAILABLE` hoặc `COLD_START`.

---

### LAYER 3 — RISK EVALUATOR & SEQUENCE SCORER

#### 3.1 — P: Point Anomaly Score (MAD + IPAS)
**Công thức 1: MAD Z-robust (Dị thường toàn cục)**
Chống nhiễu tuyệt đối, tự động scale.
$$MAD = Median(|X_i - Median(X)|)$$
$$Z_{robust} = \frac{0.6745 \times (X_i - Median(X))}{MAD}$$
*Gate:* Nếu $Z_{max} \le 2.5 \rightarrow P_{MAD} = 0.0$. Nếu $> 2.5 \rightarrow P_{MAD} = \min(10.0, (Z_{max} - 2.5) \times \frac{10}{2.5})$.

**Công thức 2: IPAS - Intra-binary Population Anomaly Score (Dị thường nội bộ)**
Bắt tiến trình bị weaponized (Vd: 1 php-cgi.exe bị exploit vs 499 php-cgi.exe sạch). Population $\ge 5$.
$$IPAS_{raw} = Mean\left(\frac{|V_{10} - Mean(V_{10})|}{Std(V_{10}) + 1e-6}\right)$$
$IPAS = \min(10.0, IPAS_{raw} \times 2.5)$.

**Tổng hợp P Score:**
$P\_Score = \min(10.0,\ P_{MAD} \times 0.7 + IPAS \times 0.3)$
*(Processes của cluster -1 nhận thêm `P_bonus = +4.0`)*

#### 3.2 — C: Contextual Anomaly Score
Chấm điểm theo Cụm hành vi thay vì theo Tên.

**v8.3 — One-sided Z-score normalization (thay thế min-max):**
$$risk_k = dot(Centroid_k,\ W_{sus})$$
$$\mu = Mean(risk_k),\ \sigma = Std(risk_k)$$
$$z_k = (risk_k - \mu) / \sigma$$
$$C\_profile[k] = \begin{cases} 0 & z_k \le 0 \\ \min(10,\ z_k \times 3.33) & z_k > 0 \end{cases}$$
*Khi $\sigma \approx 0$ (tất cả clusters đồng nhất) → $C = 0$ cho tất cả.*

- Process thuộc cluster $k \ge 0$: `C_score = C_profile[k]`
- Process thuộc cluster `-1`:
  - Nếu mang hành vi "Động" (`has_network, injection, file, reg`): `C_score = 10.0 × (1 - nif_binary)` (v8.4)
  - Nếu chỉ là Nhiễu thụ động: `C_score = 4.0 + 3.0 × nif_binary` (v8.3)

#### 3.3 — S: Sigma Score (Lấy từ L1)

#### 3.4 — Seq: Sequence Anomaly Score (Markov Chain Order 2)
Build Transition Matrix từ UNPRUNED GRAPH, chấm điểm trên PRUNED GRAPH.
$$Seq\_raw = \frac{-1}{N-2} \sum \log_2(P_{laplace})$$
**Vá điểm mù N=2:** Nếu chuỗi chỉ dài 2 node (Vd: `A -> B`), nhân đôi node đầu thành `(A, A, B)` để Order 2 Markov có thể đánh giá transition.

**v8.3 — MAD Z-robust normalization (thay thế ceiling lý thuyết log₂(K+1)):**

*2-pass: Pass 1 build transition matrix. Pass 2 calibrate population statistics trên PRUNED paths:*
$$Median_{seq} = Median(\{Seq\_raw_i\}),\quad MAD_{seq} = Median(|Seq\_raw_i - Median_{seq}|)$$
$$Z_{seq} = \frac{0.6745 \times (Seq\_raw - Median_{seq})}{MAD_{seq}}$$
$$Seq = \begin{cases} 0 & Z_{seq} \le 2.5 \\ \min\bigl(10,\ (Z_{seq}-2.5)\times\frac{10}{2.5}\bigr) & Z_{seq} > 2.5 \end{cases}$$
*Gate = 2.5 nhất quán với MAD_GATE của P_score (§3.1). Tự hiệu chỉnh theo data — không magic number.*

#### 3.5 — Col: Collective Anomaly Score (Beaconing Detector)
Sử dụng Coefficient of Variation (CoV) trên EID 3.
**Gate chống chia 0:** `if len(timestamps) < 4 -> Col = 0.0` (Phải có ít nhất 3 intervals mới có ý nghĩa thống kê).
$Col\_Score = \max(0.0, \min(10.0, (1.0 - CoV) \times 10.0))$

#### 3.6 — CI: Corroboration Index & Sigma Floor (v8.6)
Khuếch đại khi đa tín hiệu đồng thuận.

- **CI Calculation (unified):**  
  $$CI_{raw}=1.0+0.2\times(N_{active}-2),\quad CI=\text{clip}(CI_{raw}, CI_{min}(max\_signal), 1.5)$$
- **Continuous CI Floor:** dùng hàm liên tục theo `max_signal`, không dùng nhiều floor rời rạc.
- **Sigma Floor (không bypass):** nếu `Sigma_Score >= 7.0` thì:
  $$Final\_Score = \max(Final\_Score,\ \alpha\times Sigma\_Score),\ \alpha = 0.85$$
  Giá trị `0.85` là `sigma.floor_alpha` trong config.

---

### LAYER 4 — AGGREGATION & OUTPUT

#### 4.1 — Công thức Final Score & Backpropagation
**Bước 1: Tính Final Score thô**
$$Final\_Score = \Bigl(w_P \cdot P + w_C \cdot C + w_S \cdot S + w_{Seq} \cdot Seq\Bigr)\times CI + w_{Col}\cdot Col$$
*(Col là Additive Bonus ngoài hệ số nhân CI).*

Trong đó:
- weights mặc định lấy từ `config.toml`:  
  `P=0.25, C=0.20, S=0.30, Seq=0.25, Col=0.10`.
- `effective_weights` là bộ trọng số sau rescaling khi có scorer inactive.

**Bước 2: Guilt Backpropagation (Truyền rủi ro ngược)**
Duyệt đồ thị từ Lá lên Rễ (Bottom-Up). Rủi ro của con truyền lên cha với hệ số suy hao 0.8:
$$Node.Final\_Score = \max(Node.Final\_Score,\ Max\_Child\_Score \times 0.8)$$
Nếu điểm bị tăng do bước này, gán cờ `INHERITED_RISK`.

#### 4.2 — Output Format (.TXT - Forensic Process Tree)
Cấu trúc cây phả hệ ASCII Tree. Phân Tier rõ ràng. **Smart Collapse:** Các nhánh (Root -> Leaves) hoàn toàn SAFE (< 1.5) sẽ bị gộp vào dòng cuối để chống trôi màn hình.

```text
================================================================================
 SRAH PLATFORM - BÁO CÁO PHÂN TÍCH FORENSIC
================================================================================

================================================================================
 TỔNG QUAN PHÂN TÍCH
================================================================================
  Tổng events phân tích      : <N>
  Tổng processes             : <N>
  Sigma rules triggered      : <N> processes
  Tier 1 (CRITICAL)          : <N> (>= 7.0)
  Tier 2 (HIGH)              : <N> (>= 5.0)
  Tier 3 (MEDIUM)            : <N> (>= 1.5)
  Tier 4 (LOW/BENIGN)        : <N> (< 1.5)
  Thời gian phân tích        : <N>s

================================================================================
 CÂY TIẾN TRÌNH (PROCESS TREE)
================================================================================
ROOT: <image_name.exe> (<User>) [<TIER>] Score:<Final_Score> [<MITRE_Tags>]
    ↳ S:<S_Score>  P:<P_Score>  C:<C_Score>  Seq:<Seq_Score>  Col:<Col_Score> | <FLAG_1> | <FLAG_2>
    CMD: <CommandLine>
    NET: -> <IP_Address> (<Count>x)
    FILE: <File_Path_Dropped>
    REG: <Registry_Modified>
    ├── <child_1.exe> (<User>) [<TIER>] Score:<Final_Score>
    │   ↳ S:<S>  P:<P>  C:<C>  Seq:<Seq>  Col:<Col> | <FLAGS>
    │   CMD: <CommandLine>
    └── <child_2.exe> (<User>) [<TIER>] Score:<Final_Score>
        ↳ S:<S>  P:<P>  C:<C>  Seq:<Seq>  Col:<Col> | <FLAGS>
        └── <grandchild.exe> (<User>) [<TIER>] Score:<Final_Score>
            ↳ S:<S>  P:<P>  C:<C>  Seq:<Seq>  Col:<Col> | <FLAGS>
------------------------------------------------------------
ROOT: <another_suspicious_root.exe> ...
    ...
------------------------------------------------------------

  [Collapsed] <N> benign trees: <image_1>(x<count>), <image_2>(x<count>), ...
================================================================================
```

---

## 5. LUẬT THÉP DÀNH CHO AI CODING AGENT

> **Tuyên bố:** Mọi AI/LLM đọc tài liệu này để hỗ trợ lập trình phải tuân thủ TUYỆT ĐỐI các nguyên tắc sau. Bất kỳ gợi ý code nào vi phạm sẽ bị đánh giá là **lệch kiến trúc nghiêm trọng** và không được chấp nhận.

---

[THÉP-01] CẤM Black-box ML: KHÔNG dùng RandomForest, IsolationForest, XGBoost, ECOD.
[THÉP-02] CẤM NLP Feature Extraction: KHÔNG dùng TF-IDF, Word2Vec trên Command Line. Ánh xạ về V₁₀.
[THÉP-03] CẤM Hardcoded Whitelist/Blacklist: Mọi tính toán lấy từ Data-driven. (Ngoại trừ SHELL_WRAPPERS là kiến thức Domain của OS). KHÔNG có Trust Factor, KHÔNG ưu tiên file Microsoft Signed.
[THÉP-04] CẤM Cộng dồn Sigma: Bắt buộc dùng max() + log bonus.
[THÉP-05] CẤM Reconnect: Không kết nối con trực tiếp với ông nội khi cha bị xóa.
[THÉP-06] Dùng ProcessGuid: Không dùng PID làm primary key trong Graph.
[THÉP-07] BẢO VỆ cluster -1: KHÔNG merge bất kỳ ai vào cụm -1, và cụm -1 không được merge đi đâu.
[THÉP-08] An toàn Laplace (Không Log 0): Cộng hằng số $\alpha=1$ vào tử và mẫu.
[THÉP-09] Cấm Nested For-loop / Pandas Apply() ở Layer 3. Dùng Vectorization.
[THÉP-10] Normalize: Mọi sub-scores phải ở trong [0, 10] trước khi tính Final Score.
[THÉP-11] Weights L4: Tổng weight (S, P, C, Seq) BẮT BUỘC = 1.0. Col nằm ngoài.
[THÉP-12] Ngôn ngữ: L0 bằng Rust, L1-L4 bằng Python.
[THÉP-13] Giao tiếp L0-L1: Sử dụng PyO3 để pass Native Python Objects từ Rust sang Python. Tuyệt đối KHÔNG dùng luồng text JSON qua IPC stdout/stdin để chống nghẽn thắt cổ chai hiệu năng.
[THÉP-14] Single Source of Truth: Mọi tham số runtime phải lấy từ `config.toml`, không hardcode rải rác.
[THÉP-15] Health Report bắt buộc: mỗi lần chạy phải khai báo `clustering_mode`, `seq_mode`, `campaign_state`, `effective_weights`.

---

## 6. PHỤ LỤC TOÁN HỌC

### Tóm tắt công thức (v8.3)

Symbol,Range,Công thức
S,"[0, 10]","max(B×CM) + 0.25×log₂(1+N_rules), clip [0,10]"
P,"[0, 10]","MAD Z-robust + IPAS, scale max 10. Bonus +4.0 nếu cluster=-1"
C,"[0, 10]","One-sided Z-score: z=(risk-μ)/σ; C=min(10,z×3.33) nếu z>0 else 0. Cluster -1 Active=10.0, Passive=4.0+3.0×nif_binary"
Seq_raw,"[0, ∞)",-1/(N-2) × Σ log₂(P_laplace). N=2 → duplicate node đầu.
Seq,"[0, 10]","MAD Z-robust: Z=(0.6745×(raw-Median))/MAD. Seq=0 nếu Z≤2.5; min(10,(Z-2.5)×10/2.5) nếu Z>2.5"
Col,"[0, 10]","max(0, (1-CoV) × 10). Yêu cầu len(timestamps) >= 4"
CI,"[0.6, 1.5]","max(0.8, min(1.5, 1.0+0.2×(N_active-2))). Adaptive floor=0.6 khi N_active=0 và max_signal<4.0. Override max(1.0,CI) nếu max signal>=8.0 (v8.4.2)"
Final,"[0, 10]",((0.25P + 0.15C + 0.35S + 0.25Seq) × CI + 0.10Col) truyền ngược Bottom-Up 80% (v8.4.2 weights)

### Tham số mặc định (v8.3)

Tham số,Giá trị mặc định
MAD_GATE,2.5 (Dưới mức này P=0 và Seq=0)
SEQ_MAD_GATE,2.5 (Nhất quán với MAD_GATE — điểm ngọt thực nghiệm v8.6)
C_Z_SCALE,3.33 (z=3σ → C=10.0)
CI_adaptive_floor,"0.6 khi N_active=0 VÀ max_signal<4.0; 0.8 otherwise"
CI_active_thresholds,"P>6, C>6, S>=3.0, Seq>5, Col>6 (Giảm 20% nếu Parent C=-1 hoặc IPAS>3.0)"
w_sus,"[0.15, 0.20, 0.10, 0.10, 0.15, 0.15, 0.05, 0.03, 0.04, 0.03]"
Backprop_Decay,0.8

---

*Document này là nguồn sự thật duy nhất (Single Source of Truth) cho toàn bộ implementation. Mọi quyết định code phải tham chiếu về tài liệu này.*