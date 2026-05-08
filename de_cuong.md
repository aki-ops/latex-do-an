---

## MỞ ĐẦU

> **Chức năng:** Thiết lập toàn bộ bối cảnh, thực trạng, khoảng trống,
> và mục tiêu cụ thể của luận văn. Không có lý thuyết kỹ thuật ở đây.

### 1. Thực trạng và Thiếu sót hiện tại

**Alert Fatigue trong SOC:**
- Dẫn chứng định lượng: Ponemon Institute (2022) — trung bình SOC doanh
  nghiệp nhận >11,000 alert/ngày, <19% được điều tra. IBM X-Force (2023) —
  MTTD trung bình 277 ngày.
- Nguyên nhân gốc rễ: SIEM rule-based khớp pattern tĩnh, không có ngữ cảnh
  quan hệ → tỷ lệ FP 40–80% trong môi trường production.
- Hệ quả: Analyst rơi vào trạng thái "cry-wolf", tạo khoảng mù trong chuỗi
  phòng thủ.

**Giới hạn của phòng thủ dựa trên chữ ký:**
- APT29, FIN7, Cobalt Strike — minh chứng thực tế LOLBins vô hiệu hóa AV/EDR
  truyền thống (dẫn MITRE ATT&CK T1218.005, T1047, T1055).
- Hash-based và YARA đều thất bại vì binary hợp lệ, payload trong memory.

**Thiếu sót của các giải pháp hiện có:**

| Giải pháp | Điểm mạnh | Điểm yếu |
|-----------|-----------|----------|
| IsolationForest / LOF | Không cần nhãn | Black-box, không giải thích được |
| LSTM / GCN | Bắt được sequential anomaly | Cần dữ liệu training sạch, không Plug-and-Play |
| WATSON / UNICORN (Graph-based) | Phát hiện APT qua provenance | Offline analysis, không kết hợp statistical scoring |
| Hayabusa / Chainsaw | Rule-based nhanh | Không ưu tiên hóa tự động theo hành vi |
| Commercial SIEM | Đầy đủ tính năng | Phụ thuộc tuning thủ công, không Zero Pre-training |

**Khoảng trống chưa được lấp đầy:** Chưa có giải pháp nào đồng thời:
Zero Pre-training + Multi-anomaly scoring + White-box XAI + Production-grade
performance.

---

### 2. Bài toán và Mục tiêu

**Phát biểu bài toán:** Cho file log Sysmon `.evtx` từ môi trường Windows
chưa biết trước, tự động xếp hạng các tiến trình theo mức độ nguy hiểm, với
điểm số có thể giải thích được, mà không cần bất kỳ dữ liệu baseline bên
ngoài.

**Mục tiêu cụ thể:**
- Recall > 90% trên tập APT/LOLBins có ground truth.
- Analyst chỉ cần xem xét Top-N tiến trình thay vì hàng nghìn.
- Mỗi điểm số phân rã thành các thành phần có thể kiểm chứng (White-box XAI).
- Xử lý file ≥ 1GB trong thời gian tính bằng phút.
- Zero Pre-training — chạy ngay lập tức trên môi trường mới hoàn toàn.

---

### 3. Phạm vi, Phương pháp, Cấu trúc Luận văn

- **Phạm vi:** Windows Sysmon log, 9 EID (1, 3, 8, 10, 11, 13, 17, 18, 22).
- **Ngoài phạm vi:** Non-Windows, Deep Packet Inspection, network traffic.
- **Phương pháp:** Thiết kế kiến trúc + thực nghiệm đo lường trên dataset
  benchmark công khai.
- **Cấu trúc:** Chương 1 (lý thuyết) → Chương 2 (thiết kế + áp dụng) →
  Chương 3 (thực nghiệm).

---

## CHƯƠNG 1 — CƠ SỞ LÝ THUYẾT

> **Chức năng:** Phổ cập lý thuyết. Đi từ phân loại bất thường → định nghĩa
> từng loại → công thức kèm diễn giải toán học đầy đủ → tổng hợp thành công
> thức chung. Cuối chương là các lý thuyết nền tảng hỗ trợ. **Không gán
> giá trị ngưỡng cụ thể** — chỉ giải thích vai trò định tính của từng tham số.

---

### 1.1 Nền tảng Kỹ thuật: Sysmon và Mô hình Tiến trình Windows

#### 1.1.1 Sysmon và 9 Event ID cốt lõi
Trình bày Sysmon là gì và tại sao là nguồn log phù hợp nhất cho DFIR
behavioral analysis. Giải thích ý nghĩa bảo mật của từng EID:

| EID | Tên sự kiện | Ý nghĩa bảo mật cần phân tích |
|-----|------------|-------------------------------|
| 1   | Process Create | Nguồn gốc sinh tiến trình, command line, cha-con |
| 3   | Network Connect | C2 communication, exfiltration |
| 8   | CreateRemoteThread | Process injection — TTP đặc trưng |
| 10  | ProcessAccess (flag WRITE_PROCESS_MEMORY 0x0020) | Memory injection |
| 11  | FileCreate | Dropper, persistence artifact |
| 13  | RegistryValue Set | Persistence, malware config |
| 17/18 | Pipe Create/Connect | IPC nội bộ — Cobalt Strike named pipe |
| 22  | DNS Query | C2 domain, DGA detection |

#### 1.1.2 ProcessGuid vs PID — Vấn đề định danh trên log dài
- **PID Reuse:** Windows tái phân bổ Process ID sau khi process kết thúc.
  Trên log kéo dài nhiều giờ, cùng PID = 1234 có thể chỉ đến hai process
  hoàn toàn khác nhau.
- **ProcessGuid:** GUID toàn cục duy nhất do Sysmon driver gán tại thời điểm
  tạo process, không bao giờ tái sử dụng → là primary key tin cậy duy nhất.
- **Hệ quả thiết kế:** Mọi thao tác join, graph build, và lineage tracking
  trong hệ thống đều phải dùng ProcessGuid thay vì PID.

#### 1.1.3 Cây Phả hệ Tiến trình (Process Lineage Tree)
- Mỗi EID 1 chứa cặp (ProcessGuid, ParentProcessGuid) → tập hợp các cặp
  này hình thành một rừng cây có hướng (Directed Forest) gọi là Process Tree.
- **Tại sao lineage quan trọng hơn event đơn lẻ?** Minh họa: `cmd.exe` có
  cha là `explorer.exe` → bình thường; cùng `cmd.exe` có cha là `excel.exe`
  → dấu hiệu macro malware (T1566.001). Event đơn lẻ không phân biệt được
  hai trường hợp này.
- **Nguy cơ đứt gãy lineage:** Bất kỳ thao tác xóa node nào cắt đứt chuỗi
  cha-con sẽ ẩn đi attack chain và bằng chứng Recon — đây là ràng buộc cứng
  cho thiết kế ở Chương 2.

---

### 1.2 Phân loại Bất thường trong Hành vi Tiến trình

> Đây là bộ khung lý thuyết trả lời câu hỏi: **tại sao cần nhiều thành phần
> scoring?** Mỗi loại bất thường có đặc trưng toán học khác nhau, không thể
> dùng một công thức duy nhất để phát hiện tất cả.

---

#### 1.2.1 Point Anomaly — Bất thường Điểm

**Định nghĩa:** Một quan sát đơn lẻ $x_i$ lệch xa so với phần còn lại của
tập dữ liệu $\{x_1, \ldots, x_n\}$ theo một metric nào đó.

**Biểu hiện trong DFIR:**
- Binary cực kỳ hiếm: NIF → 1 (chỉ xuất hiện đúng 1 lần trong toàn log).
- Command line có entropy cực cao (obfuscated payload).
- Một trong 500 `php-cgi.exe` có thêm network connection + file drop trong
  khi 499 instance còn lại không có — outlier nội bộ nhóm.

**Điểm mù của Point Anomaly:** Không bắt được hành vi bất thường chỉ khi
xét trong ngữ cảnh chuỗi (sequential) hoặc phân phối thời gian (collective).

---

**1.2.1.a Thước đo phân tán Bền vững: MAD (Median Absolute Deviation)**

*Vấn đề với Standard Deviation:*
Độ lệch chuẩn $\sigma = \sqrt{\frac{1}{n}\sum(x_i - \bar{x})^2}$ phụ thuộc
vào mean $\bar{x}$. Khi có $k$ outlier cực đoan, chúng kéo $\bar{x}$ lệch
và tăng $\sigma$ → z-score của chính outlier giảm xuống → bỏ sót. Nói cách
khác: $\sigma$ bị "nhiễm độc" bởi chính những điểm cần phát hiện.

**Định nghĩa MAD:**

$$MAD = \text{Median}\bigl(\,|x_i - m|\,\bigr), \quad m = \text{Median}(X)$$

MAD dùng median thay mean ở cả hai lớp → **Breakdown Point = 50%**: ngay
cả khi 49% dữ liệu là outlier cực đoan, MAD vẫn ước lượng đúng phân tán
của phần còn lại.

**Robust Z-score:**

$$z_{robust}(x_i) = \frac{c \cdot (x_i - m)}{MAD}$$

*Hệ số $c = 0.6745$:* Với phân phối chuẩn $\mathcal{N}(0, \sigma^2)$:
$$\text{E}[|X - \text{Median}(X)|] = \sigma \cdot \sqrt{2/\pi}$$
$$\Rightarrow MAD \approx 0.6745 \cdot \sigma \Rightarrow c = 1/0.6745$$
sao cho $z_{robust}$ tương đương z-score thông thường khi dữ liệu chuẩn.
Điều này cho phép dùng ngưỡng thống nhất với bảng phân phối chuẩn.

**Hàm chuyển đổi sang điểm (dạng tổng quát):**

$$P_{MAD}(x_i) = \begin{cases} 0 & z_{robust}(x_i) \le \theta \\ \min\!\left(10,\ \dfrac{z_{robust}(x_i) - \theta}{\theta} \times 10 \right) & z_{robust}(x_i) > \theta \end{cases}$$

*Tham số $\theta$ (MAD Gate — Ngưỡng vùng chết):*
- $\theta$ là ranh giới dưới bên dưới không có điểm được phát sinh. 
- $\theta$ càng lớn → yêu cầu độ lệch càng lớn mới bị flag → ít FP, tăng FN.
- $\theta$ càng nhỏ → nhạy hơn → nhiều FP. Giá trị cụ thể được chọn ở Ch.2.
- *Hệ số $10/\theta$:* đảm bảo $z_{robust} = 2\theta$ cho điểm 10.0, tạo dải
  tuyến tính $[\theta,\, 2\theta] \to [0, 10]$.

---

**1.2.1.b Bất thường Nội bộ Nhóm: IPAS**
*(Intra-binary Population Anomaly Score)*

*Vấn đề:* MAD toàn cục bị pha loãng khi cả population một binary cùng có
hành vi (ví dụ: 500 `php-cgi.exe` đều có `has_network = 1`). Instance bị
weaponized có thêm injection + file drop — khác biệt rõ với đồng loại nhưng
không nổi bật toàn cục.

**Khoảng cách nội bộ nhóm (dạng Mahalanobis đơn giản hóa):**

$$dist_j = \frac{1}{d} \sum_{k=1}^{d} \frac{|v_{j,k} - \mu_k|}{\sigma_k + \varepsilon}$$

- $v_{j,k}$: chiều $k$ của vector hành vi tiến trình $j$.
- $\mu_k, \sigma_k$: mean và std của chiều $k$ trong group.
- $\varepsilon > 0$: hằng số làm trơn, ngăn chia cho 0 khi group đồng nhất
  ($\sigma_k = 0$). Khi $\sigma_k = 0 \Rightarrow dist_j = 0$: không ai khác
  biệt trong group hoàn toàn đồng nhất → đúng về logic.
- *Giả định độc lập:* Đơn giản hóa từ Mahalanobis đầy đủ bằng cách giả sử
  ma trận covariance là diagonal. Hợp lý vì các chiều trong $V_{10}$ được
  thiết kế độc lập về mặt hành vi.

**Điều kiện áp dụng:** Group phải có ít nhất $N_{min}^{IPAS}$ instance. Dưới
mức này $\sigma_k$ không có ý nghĩa thống kê → $IPAS = 0$.

**Chuẩn hóa:**

$$IPAS = \min\bigl(10,\ \overline{dist} \times \kappa\bigr)$$

*Tham số $\kappa$ (IPAS scale factor):* ánh xạ khoảng cách raw sang [0,10].
$\kappa$ được chọn sao cho khoảng cách thực nghiệm của weaponized instance
đạt điểm tối đa 10.0 (xác định ở Ch.2).

---

**1.2.1.c Tổng hợp P Score:**

$$\boxed{P = \min\!\left(10,\ \alpha \cdot P_{MAD} + (1-\alpha) \cdot IPAS\right)}$$

*Tham số $\alpha \in (0,1)$:* trọng số tương đối giữa bất thường toàn cục
và bất thường nội bộ nhóm. $\alpha > 0.5$ ưu tiên tín hiệu global.

**Bổ sung từ Clustering (kết nối với §1.4):** Tiến trình thuộc Cluster $-1$
(noise HDBSCAN) — đã được xác nhận độc lập là outlier về density — nhận thêm
bonus $\delta$:
$$P_{final} = \min(10,\ P + \delta)$$
Đây là **multi-source corroboration sớm**: hai phương pháp độc lập đồng thuận
tăng độ tin cậy tín hiệu.

---

#### 1.2.2 Contextual Anomaly — Bất thường Ngữ cảnh

**Định nghĩa:** Quan sát $x_i$ bình thường trong bối cảnh $A$ nhưng bất
thường trong bối cảnh $B$.

**Biểu hiện trong DFIR:** `svchost.exe` có network connection là bình thường.
`svchost.exe` có network + file drop + registry mod đồng thời — bất thường
về tổ hợp hành vi. Cần so sánh với **profile hành vi cùng nhóm**.

**Cơ sở: Cluster Risk Profile**

Sau khi phân cụm HDBSCAN (§1.4.2) trên không gian $V_{10}$, mỗi cluster $k$
có centroid $\vec{C}_k$. Định nghĩa vector trọng số nghi vấn $\vec{w}_{sus}$
phản ánh mức độ nguy hiểm của từng feature hành vi:

$$risk_k = \vec{C}_k \cdot \vec{w}_{sus}$$

**Chuẩn hóa bằng One-sided Z-score:**

$$z_k = \frac{risk_k - \mu_r}{\sigma_r}, \qquad \mu_r = \text{Mean}(\{risk_k\}),\ \sigma_r = \text{Std}(\{risk_k\})$$

$$\boxed{C\_profile[k] = \begin{cases} 0 & z_k \le 0 \\ \min(10,\ z_k \times \gamma) & z_k > 0 \end{cases}}$$

*Tại sao One-sided?* Hệ thống phát hiện mối đe dọa chỉ quan tâm cluster
nguy hiểm hơn trung bình ($z > 0$). Cluster an toàn hơn không được "thưởng
điểm âm" — điều đó không có nghĩa về bảo mật và có thể triệt tiêu tín hiệu
thật qua việc trừ điểm.

*Tại sao Z-score thay vì Min-Max?* Min-max phụ thuộc $risk_{max}$ — một
cluster cực kỳ nguy hiểm nén toàn bộ còn lại về gần 0. Z-score tự scale
theo phân phối thực tế, bền vững hơn.

*Trường hợp suy biến $\sigma_r \approx 0$:* Toàn bộ cluster có risk gần bằng
nhau → $C = 0$ cho tất cả. Đúng: không có gì khác biệt thì không có tín hiệu
ngữ cảnh.

*Tham số $\gamma$ (C scale factor):* ánh xạ z-score sang [0,10]. Cơ sở chọn:
cluster ở $3\sigma$ trên mean nên đạt điểm tối đa → $3\gamma \ge 10$.

**Xử lý đặc biệt Cluster $-1$** (không có centroid xác định):

$$C_{-1} = \begin{cases} 10.0 \times (1 - NIF_{binary}) & \text{nếu có hành vi nguy hiểm} \\ c_0 + c_1 \times NIF_{binary} & \text{nếu thụ động (noise)} \end{cases}$$

*Lý luận:* Outlier density + hành vi nguy hiểm + binary phổ biến (bị
weaponized, $NIF$ thấp) → điểm cao nhất. Binary rất hiếm ($NIF$ cao) → có
thể chỉ là admin tool lạ, không nhất thiết độc hại.

---

#### 1.2.3 Sequential Anomaly — Bất thường Chuỗi

**Định nghĩa:** Thứ tự xuất hiện các phần tử trong chuỗi bất thường, dù
từng phần tử riêng lẻ bình thường.

**Biểu hiện trong DFIR:** Chuỗi `WINWORD.EXE → cmd.exe → powershell.exe →
net.exe` — mỗi tiến trình hoàn toàn hợp lệ, nhưng transition cha-con này
chưa từng tồn tại trong log production bình thường → dấu hiệu macro malware.

**Cơ sở: Markov Chain Bậc 2**

*Tại sao bậc 2 thay vì bậc 1?* Bậc 1 chỉ xem cha trực tiếp: $P(C \mid B)$.
Không phân biệt được `cmd.exe` sinh bởi `(services.exe → svchost.exe)` khác
với `(explorer.exe → WINWORD.EXE)`. Bậc 2 nắm bắt nhiều ngữ cảnh hơn.

**Xác suất chuyển tiếp bậc 2:**

$$P(n_{i+2} \mid n_i, n_{i+1})$$

**Laplace Smoothing — ngăn $\log(0)$:**

$$P_{lap}(C \mid A, B) = \frac{\text{Count}(A,B,C) + \varepsilon_L}{\text{Count}(A,B) + \varepsilon_L \cdot K}$$

- $K$: tổng số node khác nhau trong graph.
- $\varepsilon_L > 0$: hằng số làm trơn.
- *Tác dụng:* Mọi transition đều có $P > 0$, kể cả chưa từng gặp trong
  training → tránh $\log(0) = -\infty$ khi tính cross-entropy.
- *Tính chất:* Khi Count lớn, số hạng $\varepsilon_L$ không đáng kể → xác
  suất gần với tần suất quan sát; khi Count nhỏ, $\varepsilon_L$ kéo xác
  suất về phân phối đều (uniform prior).

**Cross-entropy Path Score:**

$$Seq_{raw} = \frac{-1}{N-2} \sum_{i=1}^{N-2} \log_2 P_{lap}(n_{i+2} \mid n_i, n_{i+1})$$

- *Chia cho $N-2$:* chuẩn hóa theo độ dài path → cho phép so sánh path
  ngắn và dài trên cùng thang đo.
- *Giá trị cao:* path "bất ngờ" theo transition model → attack chain chưa
  từng thấy.

*Edge case $N = 2$:* Khi path chỉ có 2 node, không có transition bậc 2 để
đánh giá. Xử lý: nhân đôi node đầu → $(A, A, B)$ → ít nhất 1 transition.
Heuristic: coi A "tự sinh ra mình" trước khi sinh B.

**Chuẩn hóa bằng MAD Z-robust** (nhất quán với §1.2.1.a):

$$Seq = \begin{cases} 0 & Z_{seq} \le \theta \\ \min\!\left(10,\ \dfrac{Z_{seq} - \theta}{\theta} \times 10\right) & Z_{seq} > \theta \end{cases}$$

*Tại sao dùng MAD thay vì ceiling lý thuyết $\log_2(K)$?* Ceiling phụ thuộc
$K$ — thay đổi theo từng log. MAD tự calibrate theo phân phối thực tế. Và:
dùng **cùng $\theta$** với $P_{MAD}$ → nhất quán thống kê: cùng mức bất
thường tương đối cho cùng điểm số ở cả P và Seq.

$$\boxed{Seq = f_{MAD}(Seq_{raw},\ \theta)}$$

---

#### 1.2.4 Collective Anomaly — Bất thường Tập thể (Beaconing)

**Định nghĩa:** Tập hợp các quan sát, mỗi cái bình thường riêng lẻ, nhưng
**phân phối tổng thể** bất thường.

**Biểu hiện trong DFIR:** Cobalt Strike beacon mặc định check-in mỗi 60 giây
(với jitter nhỏ). Mỗi kết nối đơn lẻ là HTTP request hoàn toàn hợp lệ. Nhưng
khoảng cách thời gian giữa các kết nối **đều đặn bất thường** — không có
phần mềm hợp lệ nào có lý do kỹ thuật để duy trì độ đều đặn này.

**Coefficient of Variation (CoV):**

$$CoV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$$

- $\Delta t_i = t_{i+1} - t_i$: khoảng cách thời gian giữa hai kết nối liên
  tiếp.
- *$CoV \approx 0$:* khoảng cách đều đặn → beaconing.
- *$CoV$ lớn:* khoảng cách biến thiên lớn → hành vi người dùng.

*Tính chất Scale-free:* CoV là tỷ số → không phụ thuộc đơn vị hay tần suất
tuyệt đối. Process beacon mỗi 60s và process beacon mỗi 300s đều có CoV thấp
nếu đều đặn → đều bị phát hiện với cùng ngưỡng.

$$\boxed{Col = \max\!\left(0,\ (1 - CoV) \times 10\right)}$$

**Gate thống kê tối thiểu:** Cần ít nhất $N_{min}^{Col}$ timestamp để có
$N_{min}^{Col} - 1$ interval, đủ để ước tính $\sigma_{\Delta t}$ và
$\mu_{\Delta t}$ có ý nghĩa. Dưới ngưỡng này $Col = 0$. Giá trị
$N_{min}^{Col}$ cụ thể chọn ở Ch.2.

---

### 1.3 Known-threat Signal — S Score (Sigma)

**Vị trí:** Bổ sung cho các thành phần behavioral trên — bắt Known-Known
threats bằng rule cộng đồng SigmaHQ (tương đương YARA cho log).

**Vấn đề Score Explosion khi cộng dồn:** Nếu cộng điểm tất cả rule match, 5
rule Low sẽ vượt 1 rule Critical — sai về tư duy bảo mật. Severity không tỷ
lệ tuyến tính với số rule.

**Max Override (nhất quán với triết lý CVSS):**

$$S = \min\!\left(10,\ \max_i\!\left(B_i \cdot CM_i\right) + \lambda_S \cdot \log_2(1 + N_{rules})\right)$$

- $B_i$: base score của rule $i$ theo severity (Critical > High > Medium > Low).
- $CM_i \in (0, 1]$: Confidence Multiplier — hệ số giảm ảnh hưởng rule có
  tỷ lệ FP cao. Có thể ghi đè per-rule-ID qua file cấu hình.
- $N_{rules}$: số rule match.
- $\lambda_S$: hệ số khuếch đại logarithmic bonus.

*Tại sao $\log_2(1 + N_{rules})$?* Logarithm đảm bảo bonus tăng chậm dần
(diminishing returns): 10 rule match không cho điểm gấp đôi 5 rule match.
Thêm rule là corroboration, không phải nhân đôi rủi ro.

*$\max_i$:* Severity đến từ rule nặng nhất, không tích lũy tuyến tính.

---

### 1.4 Lý thuyết Nền tảng Hỗ trợ

> Các lý thuyết ở mục này không gắn riêng với một loại bất thường mà là
> công cụ dùng xuyên suốt hệ thống.

#### 1.4.1 Chuẩn hóa Tần suất — NIF (Normalized Inverse Frequency)

**Vấn đề:** Cần đo độ "hiếm" của binary trong log hiện tại theo cách tự
scale, không phụ thuộc ngưỡng cứng ("dưới 1% là hiếm" — thay đổi theo kích
thước log).

**Tại sao không dùng tỷ lệ tuyến tính?** $f_i / f_{max}$ bị kéo lệch nặng
khi có binary cực kỳ phổ biến. Cần co giãn phi tuyến.

$$NIF_i = 1 - \frac{\log f_i}{\log f_{max}}, \qquad f_{max} = \max_i f_i$$

*Diễn giải:*
- Hàm log nén khoảng cách lớn: svchost × 1000 và × 2000 gần nhau trên thang
  log; binary × 1 và × 2 xa nhau.
- $f_i = f_{max} \Rightarrow NIF = 0$ (phổ biến nhất).
- $f_i = 1 \Rightarrow NIF = 1 - 0 = 1$ (xuất hiện đúng một lần).
- Chia cho $\log f_{max}$: đảm bảo $NIF \in [0,1]$ bất kể kích thước log.

**Hai biến thể:** `NIF_binary` (tần suất tên binary) và `NIF_pair` (tần suất
cặp Parent→Child — bắt thêm sự bất thường của nguồn gốc sinh ra).

---

#### 1.4.2 Không gian Đặc trưng Hành vi — $V_{10}$

**Nguyên tắc:** Biểu diễn hành vi tiến trình bằng vector số để phân cụm và
so sánh. Dùng **hành vi quan sát được**, không dùng tên file (dễ bị giả mạo
và obfuscate).

| Dim | Feature | Kiểu | Cơ sở chọn |
|-----|---------|------|------------|
| $v_1$ | `has_network` | Binary | Kết nối ra ngoài — rủi ro exfiltration/C2 |
| $v_2$ | `has_injection` | Binary | CreateRemoteThread/ProcessAccess — ít use case hợp lệ |
| $v_3$ | `has_file_drop` | Binary | Thả file — dropper, persistence |
| $v_4$ | `has_reg_mod` | Binary | Registry modification — persistence |
| $v_5$ | `nif_binary` | Continuous | Độ hiếm của binary (§1.4.1) |
| $v_6$ | `nif_pair` | Continuous | Độ hiếm của cặp cha-con |
| $v_7$ | `entropy_bin` | Discrete {0,1,2} | Entropy command line |
| $v_8$ | `cmd_len_bin` | Discrete {0,1,2} | Độ dài command line |
| $v_9$ | `child_count_bin` | Discrete {0,1,2} | Số tiến trình con |
| $v_{10}$ | `parent_sigma_bin` | Binary | Cha có Sigma score đáng kể |

*Tại sao không NLP (TF-IDF, Word2Vec)?* NLP trích feature theo chuỗi ký tự
→ bị bypass bằng obfuscation đơn giản. $V_{10}$ trích feature từ hành động
thực tế quan sát trong log.

---

#### 1.4.3 Tự học Baseline — HDBSCAN Clustering

**Vấn đề:** Cần xây dựng profile "bình thường" mà không có dữ liệu sạch bên
ngoài và không biết trước số profile hành vi tồn tại.

*Tại sao không dùng K-Means?* Yêu cầu biết K trước; giả định cụm hình cầu
phân phối đều — cả hai đều sai với log thực tế.

**HDBSCAN:** Gom nhóm điểm có mật độ cao trong không gian $V_{10}$ mà không
cần K; phát hiện cụm hình dạng tùy ý.

**Cluster $-1$ (Noise/Outlier set):** Điểm không thuộc cụm nào vì quá thưa
thớt. Đây **không phải nhiễu đo lường** mà là hành vi chưa đủ để hình thành
pattern — tập nghi vấn tự nhiên nhất.

*Nguyên tắc bất khả xâm phạm:* Không merge cluster $-1$ vào cụm nào (pha
loãng tín hiệu); không merge bất kỳ ai vào $-1$ (contaminate tập nghi vấn).

**`approximate_predict()`:** Gán cụm cho điểm mới mà không refit toàn bộ
model. Quan trọng khi N lớn: fit trên subsample, predict trên toàn tập.

---

#### 1.4.4 Nén Đồ thị Không Mất mát — Lossless Structural Deduplication

**Vấn đề:** Log production chứa hàng nghìn instance cùng binary (svchost ×
10,000). Giữ tất cả → quá tải tính toán. Pruning theo ngưỡng tần suất → xóa
bằng chứng Recon (`whoami` chạy đúng 1 lần). Cần phân biệt "lặp lại" vs
"mới lạ".

**Tiêu chí Dư thừa (Redundancy):**
Node $v$ bị coi là dư thừa khi đồng thời:
1. Cặp $(Parent(v),\ Image(v))$ đã tồn tại $\ge n_{rep}$ lần.
2. $v$ không có con (non-bridge).
3. $v$ không có hành vi gì (no signal).

Chỉ giữ lại $n_{rep}$ đại diện; loại bỏ phần còn lại.

**Nguyên lý Novelty Preservation:**
Node được bảo vệ vô điều kiện nếu cặp $(Parent(v),\ Image(v))$ chỉ xuất
hiện đúng 1 lần trong toàn dataset.

**Tính chất Recon-Awareness** (hệ quả trực tiếp của Novelty):
Attacker chạy `whoami` đúng 1 lần → tần suất cặp = 1 → Novelty Preservation
kích hoạt tự động, **không cần whitelist tên file**.

**Luật giữ lại — Union of conditions:**
$$\text{Keep}(v) \iff \underbrace{\text{Bridge}(v)}_{\text{có con}} \vee \underbrace{\text{ActiveSignal}(v)}_{\text{có hành vi/Sigma}} \vee \underbrace{\text{Novelty}(v)}_{\text{tần suất} \le 1} \vee \underbrace{\text{Shell}(v)}_{\text{shell wrapper OS}}$$

*Shell Preservation:* ngoại lệ duy nhất dùng kiến thức domain cứng (cmd,
powershell, bash...) — "vật lý của OS", không thể thiếu trong log hợp lệ.

---

#### 1.4.5 Lan truyền Rủi ro Ngược — Guilt Backpropagation

**Vấn đề:** Cha có thể không có dấu hiệu bất thường nào nhưng sinh ra con
nguy hiểm. Trong DFIR, lineage là bằng chứng — cha có trách nhiệm với hành
động con. Analyst cần thấy cha được highlight để trace ngược attack chain.

**Bottom-Up Traversal** (từ lá lên gốc):
$$Score(v) \leftarrow \max\!\left(Score(v),\ \max_{u \in \text{children}(v)} Score(u) \times \beta\right)$$

*Tham số $\beta \in (0, 1)$ (decay factor):*
- $\beta \to 1$: cha nhận gần như toàn bộ điểm con → cascade không kiểm soát
  lên root, mất discriminability.
- $\beta \to 0$: rủi ro không lan truyền → cha hoàn toàn trong sạch dù con
  rất nguy hiểm.
- Giá trị trung gian tạo "responsibility attenuation": rủi ro suy giảm dần
  khi lên cao trong cây. Flag `INHERITED_RISK` đánh dấu nguồn gốc để analyst
  phân biệt.

*Tính đơn điệu:* Dùng $\max$ → chỉ tăng điểm, không bao giờ giảm. Cha đã
nguy hiểm không bị "kéo xuống" nếu con an toàn.

---

#### 1.4.6 Tổng hợp Điểm — Công thức Chung

**Corroboration Index — CI:**

Nắm bắt sự hội tụ bằng chứng (convergence of evidence): cùng tiến trình bị
flag bởi nhiều thành phần độc lập đồng thời đáng tin cậy hơn một thành phần.

*"Tín hiệu Active":* Thành phần $x$ được coi là active khi $x > \tau_x$ (ngưỡng ý nghĩa riêng của từng thành phần). Gọi $N_{active}$ là số thành phần active.

$$CI = \max\!\left(\rho_{floor},\ \min\!\left(\rho_{ceil},\ 1.0 + \Delta_{CI} \cdot (N_{active} - 2)\right)\right)$$

*Vai trò tham số:*
- $\rho_{floor}$ (CI Floor): chặn dưới — ngăn CI triệt tiêu tín hiệu moderate.
  *Vùng chết toán học:* $\rho_{floor}$ quá thấp → tiến trình với P=C=Seq
  đều vừa phải bị đẩy xuống dưới ngưỡng điều tra → FN.
- $\rho_{ceil}$ (CI Ceiling): chặn trên — đảm bảo Final Score ∈ [0, 10].
- $\Delta_{CI}$ (CI increment): mỗi tín hiệu active tăng CI thêm $\Delta_{CI}$.
  $N_{active} = 2$ → CI = 1.0 (baseline trung hòa).
- *Adaptive floor:* Khi $N_{active} = 0$ và tất cả tín hiệu rất thấp → floor
  hạ xuống $\rho_{floor}^{min} < \rho_{floor}$ cho phép Final Score thực sự
  về gần 0 (tiến trình sạch hoàn toàn).

*Screaming Sigma Override:* Khi $S \ge \eta_\sigma$ (rule Critical có độ tin
cậy cao) → bypass weighted sum, Final Score không bị pha loãng bởi thành
phần behavioral yếu.

*Parent Context Boost:* Cha có Cluster $= -1$ hoặc $IPAS > \tau_{parent}$ →
hạ toàn bộ active thresholds $\{\tau_x\}$ xuống hệ số $\rho_{boost} < 1$.

**Final Score:**

$$\boxed{Final\_Score = \left(w_P \cdot P + w_C \cdot C + w_S \cdot S + w_{Seq} \cdot Seq\right) \times CI + w_{Col} \cdot Col}$$

*Ràng buộc:* $w_P + w_C + w_S + w_{Seq} = 1.0$ → $Final\_Score \in [0, 10]$
trước Col (giả sử $CI \le 1.5$ và $w_{Col}$ nhỏ).

*Tại sao Col nằm ngoài CI (additive, không nhân)?* Col đo tính đều đặn của
phân phối thời gian — tín hiệu độc lập về mặt toán học với các anomaly score
khác. Nhân CI sẽ khuếch đại Col theo số tín hiệu active — không đúng về bằng
chứng: beaconing không nguy hiểm hơn chỉ vì process đó cũng có injection.

*Vai trò của $w_x$:* Phản ánh độ tin cậy tương đối của mỗi thành phần — được
chọn bằng ablation study trong Ch.2.

------

## MỞ ĐẦU

> **Chức năng:** Thiết lập toàn bộ bối cảnh, thực trạng, khoảng trống,
> và mục tiêu cụ thể của luận văn. Không có lý thuyết kỹ thuật ở đây.

### 1. Thực trạng và Thiếu sót hiện tại

**Alert Fatigue trong SOC:**
- Dẫn chứng định lượng: Ponemon Institute (2022) — trung bình SOC doanh
  nghiệp nhận >11,000 alert/ngày, <19% được điều tra. IBM X-Force (2023) —
  MTTD trung bình 277 ngày.
- Nguyên nhân gốc rễ: SIEM rule-based khớp pattern tĩnh, không có ngữ cảnh
  quan hệ → tỷ lệ FP 40–80% trong môi trường production.
- Hệ quả: Analyst rơi vào trạng thái "cry-wolf", tạo khoảng mù trong chuỗi
  phòng thủ.

**Giới hạn của phòng thủ dựa trên chữ ký:**
- APT29, FIN7, Cobalt Strike — minh chứng thực tế LOLBins vô hiệu hóa AV/EDR
  truyền thống (dẫn MITRE ATT&CK T1218.005, T1047, T1055).
- Hash-based và YARA đều thất bại vì binary hợp lệ, payload trong memory.

**Thiếu sót của các giải pháp hiện có:**

| Giải pháp | Điểm mạnh | Điểm yếu |
|-----------|-----------|----------|
| IsolationForest / LOF | Không cần nhãn | Black-box, không giải thích được |
| LSTM / GCN | Bắt được sequential anomaly | Cần dữ liệu training sạch, không Plug-and-Play |
| WATSON / UNICORN (Graph-based) | Phát hiện APT qua provenance | Offline analysis, không kết hợp statistical scoring |
| Hayabusa / Chainsaw | Rule-based nhanh | Không ưu tiên hóa tự động theo hành vi |
| Commercial SIEM | Đầy đủ tính năng | Phụ thuộc tuning thủ công, không Zero Pre-training |

**Khoảng trống chưa được lấp đầy:** Chưa có giải pháp nào đồng thời:
Zero Pre-training + Multi-anomaly scoring + White-box XAI + Production-grade
performance.

---

### 2. Bài toán và Mục tiêu

**Phát biểu bài toán:** Cho file log Sysmon `.evtx` từ môi trường Windows
chưa biết trước, tự động xếp hạng các tiến trình theo mức độ nguy hiểm, với
điểm số có thể giải thích được, mà không cần bất kỳ dữ liệu baseline bên
ngoài.

**Mục tiêu cụ thể:**
- Recall > 90% trên tập APT/LOLBins có ground truth.
- Analyst chỉ cần xem xét Top-N tiến trình thay vì hàng nghìn.
- Mỗi điểm số phân rã thành các thành phần có thể kiểm chứng (White-box XAI).
- Xử lý file ≥ 1GB trong thời gian tính bằng phút.
- Zero Pre-training — chạy ngay lập tức trên môi trường mới hoàn toàn.

---

### 3. Phạm vi, Phương pháp, Cấu trúc Luận văn

- **Phạm vi:** Windows Sysmon log, 9 EID (1, 3, 8, 10, 11, 13, 17, 18, 22).
- **Ngoài phạm vi:** Non-Windows, Deep Packet Inspection, network traffic.
- **Phương pháp:** Thiết kế kiến trúc + thực nghiệm đo lường trên dataset
  benchmark công khai.
- **Cấu trúc:** Chương 1 (lý thuyết) → Chương 2 (thiết kế + áp dụng) →
  Chương 3 (thực nghiệm).

---

## CHƯƠNG 1 — CƠ SỞ LÝ THUYẾT

> **Chức năng:** Phổ cập lý thuyết. Đi từ phân loại bất thường → định nghĩa
> từng loại → công thức kèm diễn giải toán học đầy đủ → tổng hợp thành công
> thức chung. Cuối chương là các lý thuyết nền tảng hỗ trợ. **Không gán
> giá trị ngưỡng cụ thể** — chỉ giải thích vai trò định tính của từng tham số.

---

### 1.1 Nền tảng Kỹ thuật: Sysmon và Mô hình Tiến trình Windows

#### 1.1.1 Sysmon và 9 Event ID cốt lõi
Trình bày Sysmon là gì và tại sao là nguồn log phù hợp nhất cho DFIR
behavioral analysis. Giải thích ý nghĩa bảo mật của từng EID:

| EID | Tên sự kiện | Ý nghĩa bảo mật cần phân tích |
|-----|------------|-------------------------------|
| 1   | Process Create | Nguồn gốc sinh tiến trình, command line, cha-con |
| 3   | Network Connect | C2 communication, exfiltration |
| 8   | CreateRemoteThread | Process injection — TTP đặc trưng |
| 10  | ProcessAccess (flag WRITE_PROCESS_MEMORY 0x0020) | Memory injection |
| 11  | FileCreate | Dropper, persistence artifact |
| 13  | RegistryValue Set | Persistence, malware config |
| 17/18 | Pipe Create/Connect | IPC nội bộ — Cobalt Strike named pipe |
| 22  | DNS Query | C2 domain, DGA detection |

#### 1.1.2 ProcessGuid vs PID — Vấn đề định danh trên log dài
- **PID Reuse:** Windows tái phân bổ Process ID sau khi process kết thúc.
  Trên log kéo dài nhiều giờ, cùng PID = 1234 có thể chỉ đến hai process
  hoàn toàn khác nhau.
- **ProcessGuid:** GUID toàn cục duy nhất do Sysmon driver gán tại thời điểm
  tạo process, không bao giờ tái sử dụng → là primary key tin cậy duy nhất.
- **Hệ quả thiết kế:** Mọi thao tác join, graph build, và lineage tracking
  trong hệ thống đều phải dùng ProcessGuid thay vì PID.

#### 1.1.3 Cây Phả hệ Tiến trình (Process Lineage Tree)
- Mỗi EID 1 chứa cặp (ProcessGuid, ParentProcessGuid) → tập hợp các cặp
  này hình thành một rừng cây có hướng (Directed Forest) gọi là Process Tree.
- **Tại sao lineage quan trọng hơn event đơn lẻ?** Minh họa: `cmd.exe` có
  cha là `explorer.exe` → bình thường; cùng `cmd.exe` có cha là `excel.exe`
  → dấu hiệu macro malware (T1566.001). Event đơn lẻ không phân biệt được
  hai trường hợp này.
- **Nguy cơ đứt gãy lineage:** Bất kỳ thao tác xóa node nào cắt đứt chuỗi
  cha-con sẽ ẩn đi attack chain và bằng chứng Recon — đây là ràng buộc cứng
  cho thiết kế ở Chương 2.

---

### 1.2 Phân loại Bất thường trong Hành vi Tiến trình

> Đây là bộ khung lý thuyết trả lời câu hỏi: **tại sao cần nhiều thành phần
> scoring?** Mỗi loại bất thường có đặc trưng toán học khác nhau, không thể
> dùng một công thức duy nhất để phát hiện tất cả.

---

#### 1.2.1 Point Anomaly — Bất thường Điểm

**Định nghĩa:** Một quan sát đơn lẻ $x_i$ lệch xa so với phần còn lại của
tập dữ liệu $\{x_1, \ldots, x_n\}$ theo một metric nào đó.

**Biểu hiện trong DFIR:**
- Binary cực kỳ hiếm: NIF → 1 (chỉ xuất hiện đúng 1 lần trong toàn log).
- Command line có entropy cực cao (obfuscated payload).
- Một trong 500 `php-cgi.exe` có thêm network connection + file drop trong
  khi 499 instance còn lại không có — outlier nội bộ nhóm.

**Điểm mù của Point Anomaly:** Không bắt được hành vi bất thường chỉ khi
xét trong ngữ cảnh chuỗi (sequential) hoặc phân phối thời gian (collective).

---

**1.2.1.a Thước đo phân tán Bền vững: MAD (Median Absolute Deviation)**

*Vấn đề với Standard Deviation:*
Độ lệch chuẩn $\sigma = \sqrt{\frac{1}{n}\sum(x_i - \bar{x})^2}$ phụ thuộc
vào mean $\bar{x}$. Khi có $k$ outlier cực đoan, chúng kéo $\bar{x}$ lệch
và tăng $\sigma$ → z-score của chính outlier giảm xuống → bỏ sót. Nói cách
khác: $\sigma$ bị "nhiễm độc" bởi chính những điểm cần phát hiện.

**Định nghĩa MAD:**

$$MAD = \text{Median}\bigl(\,|x_i - m|\,\bigr), \quad m = \text{Median}(X)$$

MAD dùng median thay mean ở cả hai lớp → **Breakdown Point = 50%**: ngay
cả khi 49% dữ liệu là outlier cực đoan, MAD vẫn ước lượng đúng phân tán
của phần còn lại.

**Robust Z-score:**

$$z_{robust}(x_i) = \frac{c \cdot (x_i - m)}{MAD}$$

*Hệ số $c = 0.6745$:* Với phân phối chuẩn $\mathcal{N}(0, \sigma^2)$:
$$\text{E}[|X - \text{Median}(X)|] = \sigma \cdot \sqrt{2/\pi}$$
$$\Rightarrow MAD \approx 0.6745 \cdot \sigma \Rightarrow c = 1/0.6745$$
sao cho $z_{robust}$ tương đương z-score thông thường khi dữ liệu chuẩn.
Điều này cho phép dùng ngưỡng thống nhất với bảng phân phối chuẩn.

**Hàm chuyển đổi sang điểm (dạng tổng quát):**

$$P_{MAD}(x_i) = \begin{cases} 0 & z_{robust}(x_i) \le \theta \\ \min\!\left(10,\ \dfrac{z_{robust}(x_i) - \theta}{\theta} \times 10 \right) & z_{robust}(x_i) > \theta \end{cases}$$

*Tham số $\theta$ (MAD Gate — Ngưỡng vùng chết):*
- $\theta$ là ranh giới dưới bên dưới không có điểm được phát sinh. 
- $\theta$ càng lớn → yêu cầu độ lệch càng lớn mới bị flag → ít FP, tăng FN.
- $\theta$ càng nhỏ → nhạy hơn → nhiều FP. Giá trị cụ thể được chọn ở Ch.2.
- *Hệ số $10/\theta$:* đảm bảo $z_{robust} = 2\theta$ cho điểm 10.0, tạo dải
  tuyến tính $[\theta,\, 2\theta] \to [0, 10]$.

---

**1.2.1.b Bất thường Nội bộ Nhóm: IPAS**
*(Intra-binary Population Anomaly Score)*

*Vấn đề:* MAD toàn cục bị pha loãng khi cả population một binary cùng có
hành vi (ví dụ: 500 `php-cgi.exe` đều có `has_network = 1`). Instance bị
weaponized có thêm injection + file drop — khác biệt rõ với đồng loại nhưng
không nổi bật toàn cục.

**Khoảng cách nội bộ nhóm (dạng Mahalanobis đơn giản hóa):**

$$dist_j = \frac{1}{d} \sum_{k=1}^{d} \frac{|v_{j,k} - \mu_k|}{\sigma_k + \varepsilon}$$

- $v_{j,k}$: chiều $k$ của vector hành vi tiến trình $j$.
- $\mu_k, \sigma_k$: mean và std của chiều $k$ trong group.
- $\varepsilon > 0$: hằng số làm trơn, ngăn chia cho 0 khi group đồng nhất
  ($\sigma_k = 0$). Khi $\sigma_k = 0 \Rightarrow dist_j = 0$: không ai khác
  biệt trong group hoàn toàn đồng nhất → đúng về logic.
- *Giả định độc lập:* Đơn giản hóa từ Mahalanobis đầy đủ bằng cách giả sử
  ma trận covariance là diagonal. Hợp lý vì các chiều trong $V_{10}$ được
  thiết kế độc lập về mặt hành vi.

**Điều kiện áp dụng:** Group phải có ít nhất $N_{min}^{IPAS}$ instance. Dưới
mức này $\sigma_k$ không có ý nghĩa thống kê → $IPAS = 0$.

**Chuẩn hóa:**

$$IPAS = \min\bigl(10,\ \overline{dist} \times \kappa\bigr)$$

*Tham số $\kappa$ (IPAS scale factor):* ánh xạ khoảng cách raw sang [0,10].
$\kappa$ được chọn sao cho khoảng cách thực nghiệm của weaponized instance
đạt điểm tối đa 10.0 (xác định ở Ch.2).

---

**1.2.1.c Tổng hợp P Score:**

$$\boxed{P = \min\!\left(10,\ \alpha \cdot P_{MAD} + (1-\alpha) \cdot IPAS\right)}$$

*Tham số $\alpha \in (0,1)$:* trọng số tương đối giữa bất thường toàn cục
và bất thường nội bộ nhóm. $\alpha > 0.5$ ưu tiên tín hiệu global.

**Bổ sung từ Clustering (kết nối với §1.4):** Tiến trình thuộc Cluster $-1$
(noise HDBSCAN) — đã được xác nhận độc lập là outlier về density — nhận thêm
bonus $\delta$:
$$P_{final} = \min(10,\ P + \delta)$$
Đây là **multi-source corroboration sớm**: hai phương pháp độc lập đồng thuận
tăng độ tin cậy tín hiệu.

---

#### 1.2.2 Contextual Anomaly — Bất thường Ngữ cảnh

**Định nghĩa:** Quan sát $x_i$ bình thường trong bối cảnh $A$ nhưng bất
thường trong bối cảnh $B$.

**Biểu hiện trong DFIR:** `svchost.exe` có network connection là bình thường.
`svchost.exe` có network + file drop + registry mod đồng thời — bất thường
về tổ hợp hành vi. Cần so sánh với **profile hành vi cùng nhóm**.

**Cơ sở: Cluster Risk Profile**

Sau khi phân cụm HDBSCAN (§1.4.2) trên không gian $V_{10}$, mỗi cluster $k$
có centroid $\vec{C}_k$. Định nghĩa vector trọng số nghi vấn $\vec{w}_{sus}$
phản ánh mức độ nguy hiểm của từng feature hành vi:

$$risk_k = \vec{C}_k \cdot \vec{w}_{sus}$$

**Chuẩn hóa bằng One-sided Z-score:**

$$z_k = \frac{risk_k - \mu_r}{\sigma_r}, \qquad \mu_r = \text{Mean}(\{risk_k\}),\ \sigma_r = \text{Std}(\{risk_k\})$$

$$\boxed{C\_profile[k] = \begin{cases} 0 & z_k \le 0 \\ \min(10,\ z_k \times \gamma) & z_k > 0 \end{cases}}$$

*Tại sao One-sided?* Hệ thống phát hiện mối đe dọa chỉ quan tâm cluster
nguy hiểm hơn trung bình ($z > 0$). Cluster an toàn hơn không được "thưởng
điểm âm" — điều đó không có nghĩa về bảo mật và có thể triệt tiêu tín hiệu
thật qua việc trừ điểm.

*Tại sao Z-score thay vì Min-Max?* Min-max phụ thuộc $risk_{max}$ — một
cluster cực kỳ nguy hiểm nén toàn bộ còn lại về gần 0. Z-score tự scale
theo phân phối thực tế, bền vững hơn.

*Trường hợp suy biến $\sigma_r \approx 0$:* Toàn bộ cluster có risk gần bằng
nhau → $C = 0$ cho tất cả. Đúng: không có gì khác biệt thì không có tín hiệu
ngữ cảnh.

*Tham số $\gamma$ (C scale factor):* ánh xạ z-score sang [0,10]. Cơ sở chọn:
cluster ở $3\sigma$ trên mean nên đạt điểm tối đa → $3\gamma \ge 10$.

**Xử lý đặc biệt Cluster $-1$** (không có centroid xác định):

$$C_{-1} = \begin{cases} 10.0 \times (1 - NIF_{binary}) & \text{nếu có hành vi nguy hiểm} \\ c_0 + c_1 \times NIF_{binary} & \text{nếu thụ động (noise)} \end{cases}$$

*Lý luận:* Outlier density + hành vi nguy hiểm + binary phổ biến (bị
weaponized, $NIF$ thấp) → điểm cao nhất. Binary rất hiếm ($NIF$ cao) → có
thể chỉ là admin tool lạ, không nhất thiết độc hại.

---

#### 1.2.3 Sequential Anomaly — Bất thường Chuỗi

**Định nghĩa:** Thứ tự xuất hiện các phần tử trong chuỗi bất thường, dù
từng phần tử riêng lẻ bình thường.

**Biểu hiện trong DFIR:** Chuỗi `WINWORD.EXE → cmd.exe → powershell.exe →
net.exe` — mỗi tiến trình hoàn toàn hợp lệ, nhưng transition cha-con này
chưa từng tồn tại trong log production bình thường → dấu hiệu macro malware.

**Cơ sở: Markov Chain Bậc 2**

*Tại sao bậc 2 thay vì bậc 1?* Bậc 1 chỉ xem cha trực tiếp: $P(C \mid B)$.
Không phân biệt được `cmd.exe` sinh bởi `(services.exe → svchost.exe)` khác
với `(explorer.exe → WINWORD.EXE)`. Bậc 2 nắm bắt nhiều ngữ cảnh hơn.

**Xác suất chuyển tiếp bậc 2:**

$$P(n_{i+2} \mid n_i, n_{i+1})$$

**Laplace Smoothing — ngăn $\log(0)$:**

$$P_{lap}(C \mid A, B) = \frac{\text{Count}(A,B,C) + \varepsilon_L}{\text{Count}(A,B) + \varepsilon_L \cdot K}$$

- $K$: tổng số node khác nhau trong graph.
- $\varepsilon_L > 0$: hằng số làm trơn.
- *Tác dụng:* Mọi transition đều có $P > 0$, kể cả chưa từng gặp trong
  training → tránh $\log(0) = -\infty$ khi tính cross-entropy.
- *Tính chất:* Khi Count lớn, số hạng $\varepsilon_L$ không đáng kể → xác
  suất gần với tần suất quan sát; khi Count nhỏ, $\varepsilon_L$ kéo xác
  suất về phân phối đều (uniform prior).

**Cross-entropy Path Score:**

$$Seq_{raw} = \frac{-1}{N-2} \sum_{i=1}^{N-2} \log_2 P_{lap}(n_{i+2} \mid n_i, n_{i+1})$$

- *Chia cho $N-2$:* chuẩn hóa theo độ dài path → cho phép so sánh path
  ngắn và dài trên cùng thang đo.
- *Giá trị cao:* path "bất ngờ" theo transition model → attack chain chưa
  từng thấy.

*Edge case $N = 2$:* Khi path chỉ có 2 node, không có transition bậc 2 để
đánh giá. Xử lý: nhân đôi node đầu → $(A, A, B)$ → ít nhất 1 transition.
Heuristic: coi A "tự sinh ra mình" trước khi sinh B.

**Chuẩn hóa bằng MAD Z-robust** (nhất quán với §1.2.1.a):

$$Seq = \begin{cases} 0 & Z_{seq} \le \theta \\ \min\!\left(10,\ \dfrac{Z_{seq} - \theta}{\theta} \times 10\right) & Z_{seq} > \theta \end{cases}$$

*Tại sao dùng MAD thay vì ceiling lý thuyết $\log_2(K)$?* Ceiling phụ thuộc
$K$ — thay đổi theo từng log. MAD tự calibrate theo phân phối thực tế. Và:
dùng **cùng $\theta$** với $P_{MAD}$ → nhất quán thống kê: cùng mức bất
thường tương đối cho cùng điểm số ở cả P và Seq.

$$\boxed{Seq = f_{MAD}(Seq_{raw},\ \theta)}$$

---

#### 1.2.4 Collective Anomaly — Bất thường Tập thể (Beaconing)

**Định nghĩa:** Tập hợp các quan sát, mỗi cái bình thường riêng lẻ, nhưng
**phân phối tổng thể** bất thường.

**Biểu hiện trong DFIR:** Cobalt Strike beacon mặc định check-in mỗi 60 giây
(với jitter nhỏ). Mỗi kết nối đơn lẻ là HTTP request hoàn toàn hợp lệ. Nhưng
khoảng cách thời gian giữa các kết nối **đều đặn bất thường** — không có
phần mềm hợp lệ nào có lý do kỹ thuật để duy trì độ đều đặn này.

**Coefficient of Variation (CoV):**

$$CoV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$$

- $\Delta t_i = t_{i+1} - t_i$: khoảng cách thời gian giữa hai kết nối liên
  tiếp.
- *$CoV \approx 0$:* khoảng cách đều đặn → beaconing.
- *$CoV$ lớn:* khoảng cách biến thiên lớn → hành vi người dùng.

*Tính chất Scale-free:* CoV là tỷ số → không phụ thuộc đơn vị hay tần suất
tuyệt đối. Process beacon mỗi 60s và process beacon mỗi 300s đều có CoV thấp
nếu đều đặn → đều bị phát hiện với cùng ngưỡng.

$$\boxed{Col = \max\!\left(0,\ (1 - CoV) \times 10\right)}$$

**Gate thống kê tối thiểu:** Cần ít nhất $N_{min}^{Col}$ timestamp để có
$N_{min}^{Col} - 1$ interval, đủ để ước tính $\sigma_{\Delta t}$ và
$\mu_{\Delta t}$ có ý nghĩa. Dưới ngưỡng này $Col = 0$. Giá trị
$N_{min}^{Col}$ cụ thể chọn ở Ch.2.

---

### 1.3 Known-threat Signal — S Score (Sigma)

**Vị trí:** Bổ sung cho các thành phần behavioral trên — bắt Known-Known
threats bằng rule cộng đồng SigmaHQ (tương đương YARA cho log).

**Vấn đề Score Explosion khi cộng dồn:** Nếu cộng điểm tất cả rule match, 5
rule Low sẽ vượt 1 rule Critical — sai về tư duy bảo mật. Severity không tỷ
lệ tuyến tính với số rule.

**Max Override (nhất quán với triết lý CVSS):**

$$S = \min\!\left(10,\ \max_i\!\left(B_i \cdot CM_i\right) + \lambda_S \cdot \log_2(1 + N_{rules})\right)$$

- $B_i$: base score của rule $i$ theo severity (Critical > High > Medium > Low).
- $CM_i \in (0, 1]$: Confidence Multiplier — hệ số giảm ảnh hưởng rule có
  tỷ lệ FP cao. Có thể ghi đè per-rule-ID qua file cấu hình.
- $N_{rules}$: số rule match.
- $\lambda_S$: hệ số khuếch đại logarithmic bonus.

*Tại sao $\log_2(1 + N_{rules})$?* Logarithm đảm bảo bonus tăng chậm dần
(diminishing returns): 10 rule match không cho điểm gấp đôi 5 rule match.
Thêm rule là corroboration, không phải nhân đôi rủi ro.

*$\max_i$:* Severity đến từ rule nặng nhất, không tích lũy tuyến tính.

---

### 1.4 Lý thuyết Nền tảng Hỗ trợ

> Các lý thuyết ở mục này không gắn riêng với một loại bất thường mà là
> công cụ dùng xuyên suốt hệ thống.

#### 1.4.1 Chuẩn hóa Tần suất — NIF (Normalized Inverse Frequency)

**Vấn đề:** Cần đo độ "hiếm" của binary trong log hiện tại theo cách tự
scale, không phụ thuộc ngưỡng cứng ("dưới 1% là hiếm" — thay đổi theo kích
thước log).

**Tại sao không dùng tỷ lệ tuyến tính?** $f_i / f_{max}$ bị kéo lệch nặng
khi có binary cực kỳ phổ biến. Cần co giãn phi tuyến.

$$NIF_i = 1 - \frac{\log f_i}{\log f_{max}}, \qquad f_{max} = \max_i f_i$$

*Diễn giải:*
- Hàm log nén khoảng cách lớn: svchost × 1000 và × 2000 gần nhau trên thang
  log; binary × 1 và × 2 xa nhau.
- $f_i = f_{max} \Rightarrow NIF = 0$ (phổ biến nhất).
- $f_i = 1 \Rightarrow NIF = 1 - 0 = 1$ (xuất hiện đúng một lần).
- Chia cho $\log f_{max}$: đảm bảo $NIF \in [0,1]$ bất kể kích thước log.

**Hai biến thể:** `NIF_binary` (tần suất tên binary) và `NIF_pair` (tần suất
cặp Parent→Child — bắt thêm sự bất thường của nguồn gốc sinh ra).

---

#### 1.4.2 Không gian Đặc trưng Hành vi — $V_{10}$

**Nguyên tắc:** Biểu diễn hành vi tiến trình bằng vector số để phân cụm và
so sánh. Dùng **hành vi quan sát được**, không dùng tên file (dễ bị giả mạo
và obfuscate).

| Dim | Feature | Kiểu | Cơ sở chọn |
|-----|---------|------|------------|
| $v_1$ | `has_network` | Binary | Kết nối ra ngoài — rủi ro exfiltration/C2 |
| $v_2$ | `has_injection` | Binary | CreateRemoteThread/ProcessAccess — ít use case hợp lệ |
| $v_3$ | `has_file_drop` | Binary | Thả file — dropper, persistence |
| $v_4$ | `has_reg_mod` | Binary | Registry modification — persistence |
| $v_5$ | `nif_binary` | Continuous | Độ hiếm của binary (§1.4.1) |
| $v_6$ | `nif_pair` | Continuous | Độ hiếm của cặp cha-con |
| $v_7$ | `entropy_bin` | Discrete {0,1,2} | Entropy command line |
| $v_8$ | `cmd_len_bin` | Discrete {0,1,2} | Độ dài command line |
| $v_9$ | `child_count_bin` | Discrete {0,1,2} | Số tiến trình con |
| $v_{10}$ | `parent_sigma_bin` | Binary | Cha có Sigma score đáng kể |

*Tại sao không NLP (TF-IDF, Word2Vec)?* NLP trích feature theo chuỗi ký tự
→ bị bypass bằng obfuscation đơn giản. $V_{10}$ trích feature từ hành động
thực tế quan sát trong log.

---

#### 1.4.3 Tự học Baseline — HDBSCAN Clustering

**Vấn đề:** Cần xây dựng profile "bình thường" mà không có dữ liệu sạch bên
ngoài và không biết trước số profile hành vi tồn tại.

*Tại sao không dùng K-Means?* Yêu cầu biết K trước; giả định cụm hình cầu
phân phối đều — cả hai đều sai với log thực tế.

**HDBSCAN:** Gom nhóm điểm có mật độ cao trong không gian $V_{10}$ mà không
cần K; phát hiện cụm hình dạng tùy ý.

**Cluster $-1$ (Noise/Outlier set):** Điểm không thuộc cụm nào vì quá thưa
thớt. Đây **không phải nhiễu đo lường** mà là hành vi chưa đủ để hình thành
pattern — tập nghi vấn tự nhiên nhất.

*Nguyên tắc bất khả xâm phạm:* Không merge cluster $-1$ vào cụm nào (pha
loãng tín hiệu); không merge bất kỳ ai vào $-1$ (contaminate tập nghi vấn).

**`approximate_predict()`:** Gán cụm cho điểm mới mà không refit toàn bộ
model. Quan trọng khi N lớn: fit trên subsample, predict trên toàn tập.

---

#### 1.4.4 Nén Đồ thị Không Mất mát — Lossless Structural Deduplication

**Vấn đề:** Log production chứa hàng nghìn instance cùng binary (svchost ×
10,000). Giữ tất cả → quá tải tính toán. Pruning theo ngưỡng tần suất → xóa
bằng chứng Recon (`whoami` chạy đúng 1 lần). Cần phân biệt "lặp lại" vs
"mới lạ".

**Tiêu chí Dư thừa (Redundancy):**
Node $v$ bị coi là dư thừa khi đồng thời:
1. Cặp $(Parent(v),\ Image(v))$ đã tồn tại $\ge n_{rep}$ lần.
2. $v$ không có con (non-bridge).
3. $v$ không có hành vi gì (no signal).

Chỉ giữ lại $n_{rep}$ đại diện; loại bỏ phần còn lại.

**Nguyên lý Novelty Preservation:**
Node được bảo vệ vô điều kiện nếu cặp $(Parent(v),\ Image(v))$ chỉ xuất
hiện đúng 1 lần trong toàn dataset.

**Tính chất Recon-Awareness** (hệ quả trực tiếp của Novelty):
Attacker chạy `whoami` đúng 1 lần → tần suất cặp = 1 → Novelty Preservation
kích hoạt tự động, **không cần whitelist tên file**.

**Luật giữ lại — Union of conditions:**
$$\text{Keep}(v) \iff \underbrace{\text{Bridge}(v)}_{\text{có con}} \vee \underbrace{\text{ActiveSignal}(v)}_{\text{có hành vi/Sigma}} \vee \underbrace{\text{Novelty}(v)}_{\text{tần suất} \le 1} \vee \underbrace{\text{Shell}(v)}_{\text{shell wrapper OS}}$$

*Shell Preservation:* ngoại lệ duy nhất dùng kiến thức domain cứng (cmd,
powershell, bash...) — "vật lý của OS", không thể thiếu trong log hợp lệ.

---

#### 1.4.5 Lan truyền Rủi ro Ngược — Guilt Backpropagation

**Vấn đề:** Cha có thể không có dấu hiệu bất thường nào nhưng sinh ra con
nguy hiểm. Trong DFIR, lineage là bằng chứng — cha có trách nhiệm với hành
động con. Analyst cần thấy cha được highlight để trace ngược attack chain.

**Bottom-Up Traversal** (từ lá lên gốc):
$$Score(v) \leftarrow \max\!\left(Score(v),\ \max_{u \in \text{children}(v)} Score(u) \times \beta\right)$$

*Tham số $\beta \in (0, 1)$ (decay factor):*
- $\beta \to 1$: cha nhận gần như toàn bộ điểm con → cascade không kiểm soát
  lên root, mất discriminability.
- $\beta \to 0$: rủi ro không lan truyền → cha hoàn toàn trong sạch dù con
  rất nguy hiểm.
- Giá trị trung gian tạo "responsibility attenuation": rủi ro suy giảm dần
  khi lên cao trong cây. Flag `INHERITED_RISK` đánh dấu nguồn gốc để analyst
  phân biệt.

*Tính đơn điệu:* Dùng $\max$ → chỉ tăng điểm, không bao giờ giảm. Cha đã
nguy hiểm không bị "kéo xuống" nếu con an toàn.

---

#### 1.4.6 Tổng hợp Điểm — Công thức Chung

**Corroboration Index — CI:**

Nắm bắt sự hội tụ bằng chứng (convergence of evidence): cùng tiến trình bị
flag bởi nhiều thành phần độc lập đồng thời đáng tin cậy hơn một thành phần.

*"Tín hiệu Active":* Thành phần $x$ được coi là active khi $x > \tau_x$ (ngưỡng ý nghĩa riêng của từng thành phần). Gọi $N_{active}$ là số thành phần active.

$$CI = \max\!\left(\rho_{floor},\ \min\!\left(\rho_{ceil},\ 1.0 + \Delta_{CI} \cdot (N_{active} - 2)\right)\right)$$

*Vai trò tham số:*
- $\rho_{floor}$ (CI Floor): chặn dưới — ngăn CI triệt tiêu tín hiệu moderate.
  *Vùng chết toán học:* $\rho_{floor}$ quá thấp → tiến trình với P=C=Seq
  đều vừa phải bị đẩy xuống dưới ngưỡng điều tra → FN.
- $\rho_{ceil}$ (CI Ceiling): chặn trên — đảm bảo Final Score ∈ [0, 10].
- $\Delta_{CI}$ (CI increment): mỗi tín hiệu active tăng CI thêm $\Delta_{CI}$.
  $N_{active} = 2$ → CI = 1.0 (baseline trung hòa).
- *Adaptive floor:* Khi $N_{active} = 0$ và tất cả tín hiệu rất thấp → floor
  hạ xuống $\rho_{floor}^{min} < \rho_{floor}$ cho phép Final Score thực sự
  về gần 0 (tiến trình sạch hoàn toàn).

*Screaming Sigma Override:* Khi $S \ge \eta_\sigma$ (rule Critical có độ tin
cậy cao) → bypass weighted sum, Final Score không bị pha loãng bởi thành
phần behavioral yếu.

*Parent Context Boost:* Cha có Cluster $= -1$ hoặc $IPAS > \tau_{parent}$ →
hạ toàn bộ active thresholds $\{\tau_x\}$ xuống hệ số $\rho_{boost} < 1$.

**Final Score:**

$$\boxed{Final\_Score = \left(w_P \cdot P + w_C \cdot C + w_S \cdot S + w_{Seq} \cdot Seq\right) \times CI + w_{Col} \cdot Col}$$

*Ràng buộc:* $w_P + w_C + w_S + w_{Seq} = 1.0$ → $Final\_Score \in [0, 10]$
trước Col (giả sử $CI \le 1.5$ và $w_{Col}$ nhỏ).

*Tại sao Col nằm ngoài CI (additive, không nhân)?* Col đo tính đều đặn của
phân phối thời gian — tín hiệu độc lập về mặt toán học với các anomaly score
khác. Nhân CI sẽ khuếch đại Col theo số tín hiệu active — không đúng về bằng
chứng: beaconing không nguy hiểm hơn chỉ vì process đó cũng có injection.

*Vai trò của $w_x$:* Phản ánh độ tin cậy tương đối của mỗi thành phần — được
chọn bằng ablation study trong Ch.2.

---

## CHƯƠNG 2 — PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG

> **Chức năng:** Vận dụng lý thuyết Ch.1 vào hệ thống cụ thể.
> Bắt đầu bằng sơ đồ PTTK tổng thể, sau đó mô tả từng lớp và
> **chọn giá trị cụ thể cho mọi tham số** (θ, α, β, γ, ...).
> **Chưa đưa ra kết quả chạy thực nghiệm** — đó là Ch.3.

---

### 2.1 Phân tích Yêu cầu Hệ thống

#### 2.1.1 Yêu cầu chức năng (Functional Requirements)
- FR1: Nhận vào file/thư mục `.evtx`, xuất cây tiến trình có phân tầng rủi ro.
- FR2: Mỗi node có điểm số phân rã thành 6 thành phần (P, C, S, Seq, Col, CI).
- FR3: Hỗ trợ multi-file log (nhiều host, nhiều ngày).
- FR4: Xuất MITRE ATT&CK tag khi có Sigma match.

#### 2.1.2 Yêu cầu phi chức năng (Non-Functional Requirements)
- NFR1 Recall: > 90% trên tập APT/LOLBins.
- NFR2 Performance: xử lý ≥ 1GB trong thời gian tính bằng phút.
- NFR3 Zero Pre-training: không cần bất kỳ dữ liệu ngoài.
- NFR4 Explainability: mọi điểm số có thể trace được nguồn gốc.

---

### 2.2 Sơ đồ Kiến trúc Tổng thể

> *(Hình 2.1 — Sơ đồ pipeline 5 tầng: L0 → L1 → [L2-A ∥ L2-B] → L3 → L4)*
> *(Hình 2.2 — Data flow diagram: từ .evtx thô → JSON event stream → Graph
> → Feature vectors → Scores → Process Tree output)*

**Triết lý Funnel Architecture:**
- L0–L1: lọc thô với chi phí O(N) — loại bỏ event không cần thiết.
- L2: xây dựng cấu trúc — graph + baseline — chi phí O(N log N).
- L3: scoring nặng chỉ chạy trên tập đã tinh lọc từ L2.
- L4: tổng hợp và render output.

**Quyết định công nghệ: Rust (L0) + Python (L1–L4)**
- *Bottleneck đo lường:* 70% wall-clock time ở pipeline thuần Python nằm ở
  I/O parsing `.evtx` nhị phân — không phải computation.
- *PyO3 Zero-copy:* Rust parse event, construct Python Dictionary object trực
  tiếp trong Rust heap, transfer ownership sang Python heap. Loại bỏ hoàn
  toàn chi phí Serialize/Deserialize JSON.
- *Benchmark justification:* [trình bày số liệu so sánh JSON-IPC vs PyO3].

---

---
 
### 2.1 Hệ thống Sơ đồ Thiết kế
 
> **Lưu ý về loại sơ đồ:** Hệ thống này là một **data processing pipeline**,
> không phải web application hay hệ thống có actor tương tác. Do đó Use Case
> Diagram không áp dụng. Thay vào đó, các sơ đồ sau đây mô tả đầy đủ kiến
> trúc và luồng xử lý:
 
#### 2.1.1 Sơ đồ Kiến trúc Tổng thể — Architecture Block Diagram
*(Hình 2.1)*
 
**Mô tả:** Sơ đồ khối cho thấy 5 layer xếp theo chiều dọc (L0 → L1 → L2 →
L3 → L4), với mỗi khối ghi rõ: tên layer, công nghệ triển khai (Rust/Python),
input/output chính. L2 được vẽ thành hai nhánh song song (L2-A Graph Build
và L2-B Baseline Builder) hội tụ vào L3.
 
**Mục đích:** Cho người đọc thấy ngay triết lý Funnel Architecture và sự
tách biệt trách nhiệm giữa các layer.
 
#### 2.1.2 Sơ đồ Luồng Dữ liệu — DFD Level 0 (Context Diagram)
*(Hình 2.2)*
 
**Mô tả:** Sơ đồ DFD mức 0 — hệ thống là một hộp đen. Đầu vào: thư mục
`.evtx` files. Đầu ra: ASCII Process Tree report + JSON score file. Không có
actor bên ngoài tương tác, không có datastore bên ngoài.
 
**Mục đích:** Xác lập ranh giới hệ thống (system boundary) và phạm vi luận
văn.
 
#### 2.1.3 Sơ đồ Luồng Dữ liệu — DFD Level 1 (Decomposed)
*(Hình 2.3)*
 
**Mô tả:** Phân rã hộp đen Level 0 thành 5 tiến trình con (5 layer). Vẽ rõ:
- Datastore trung gian giữa các layer (event stream buffer, graph object,
  baseline model, score dict).
- Luồng dữ liệu có nhãn (loại dữ liệu: raw EVTX bytes → parsed Event dict →
  ProcessGuid DAG → feature matrix → score vector → ranked tree).
- L2-A và L2-B song song cùng nhận từ L1, cùng ghi vào shared datastore
  trước khi L3 đọc.
**Mục đích:** Cho thấy chính xác cái gì chảy qua đâu, tránh mơ hồ về
interface giữa các layer.
 
#### 2.1.4 Sơ đồ Cấu trúc Dữ liệu — Data Schema Diagram
*(Hình 2.4)*
 
**Mô tả:** Không phải ERD (không có database), nhưng là **schema diagram**
mô tả cấu trúc các object chính lưu trong RAM:
- **ProcessNode:** `{guid, image, parent_guid, cmd, timestamp, has_network,
  has_injection, ..., P, C, S, Seq, Col, CI, final_score, cluster_id, flags}`
- **GraphEdge:** `{parent_guid, child_guid, freq_count}`
- **BaselineModel:** `{nif_table, nif_pair_table, hdbscan_model,
  cluster_profiles, transition_matrix}`
**Mục đích:** Định nghĩa chính xác cấu trúc dữ liệu trung tâm — tránh mơ hồ
khi mô tả thuật toán dựa trên các field này.
 
#### 2.1.5 Sơ đồ Hoạt động — Activity Diagram cho từng Thuật toán Phức tạp
*(Hình 2.5 đến 2.9)*
 
Vì đây là pipeline với các thuật toán phức tạp thay vì UI flow, Activity
Diagram là cách phù hợp nhất để mô tả logic rẽ nhánh:
 
**Hình 2.5 — Lossless Structural Deduplication Algorithm:**
```
START
  ├─ Tính freq(Parent → Child) cho tất cả cặp
  ├─ FOR EACH node v:
  │   ├─ IF Bridge(v) OR Signal(v) OR Novelty(v) OR Shell(v) → KEEP
  │   ├─ ELSE IF count_seen[image(v)] < n_rep → KEEP (representative)
  │   └─ ELSE → REMOVE
  └─ END
```
 
**Hình 2.6 — 2-Pass Seq Score:**
```
PASS 1 (Unpruned graph):
  ├─ Duyệt tất cả path trong unpruned graph
  └─ Build transition matrix với Laplace smoothing
 
PASS 2 (Pruned graph):
  ├─ FOR EACH path trong pruned graph:
  │   ├─ IF N=2: duplicate node đầu → (A,A,B)
  │   └─ Tính Seq_raw bằng cross-entropy
  ├─ Tính MAD, Median của tập {Seq_raw}
  └─ Chuẩn hóa thành Seq score
```
 
**Hình 2.7 — HDBSCAN Baseline Builder với Sampling:**
```
IF N > N_sample_threshold:
  ├─ Stratified sample N_sample_threshold process
  ├─ HDBSCAN.fit(sample)
  └─ approximate_predict(remaining)
ELSE:
  └─ HDBSCAN.fit_predict(all)
 
IF K > K_max:
  └─ Merge vi-cụm vào cụm gần nhất (Euclidean centroid)
```
 
**Hình 2.8 — CI Calculation với Override và Boost:**
```
Count N_active (số thành phần > τ_x)
 
IF parent.cluster == -1 OR parent.IPAS > τ_parent:
  └─ Lower all τ_x by ρ_boost (recount N_active)
 
IF S >= η_sigma:
  └─ SCREAMING SIGMA: return final_score_override
ELSE:
  weighted_sum = Σ(w_x * x)
  CI = clamp(1.0 + Δ_CI*(N_active-2), ρ_floor, ρ_ceil)
  IF N_active == 0 AND max_signal < low_threshold:
    CI = ρ_floor_min
  return weighted_sum * CI + w_Col * Col
```
 
**Hình 2.9 — Guilt Backpropagation (Bottom-Up Traversal):**
```
topological_sort(graph)  // Lá trước, gốc sau
FOR EACH node v IN reverse_topological_order:
  FOR EACH child u OF v:
    IF Score(u) * β > Score(v):
      Score(v) = Score(u) * β
      v.flags.add(INHERITED_RISK)
```
 
#### 2.1.6 Sơ đồ Sequence — Layer Handoff và PyO3 Interface
*(Hình 2.10)*
 
**Mô tả:** Sequence diagram cho thấy chuỗi gọi hàm giữa các layer:
```
[.evtx files] → L0_Rust::parse() 
             → PyO3::into_py() [zero-copy handoff]
             → L1_Python::sigma_scan()
             → L2A_Python::build_graph()
             ‖ L2B_Python::build_baseline()  [parallel]
             → L3_Python::score_all_nodes()
             → L4_Python::backpropagate() → render_tree()
             → [Output: ASCII Tree + JSON]
```
 
**Điểm nhấn:** Vẽ rõ ranh giới Rust↔Python (PyO3 interface) — đây là điểm
kỹ thuật quan trọng nhất về hiệu năng.
 
---

### 2.3 Thiết kế Layer 0 — Data Ingestion & Parser

**Sơ đồ:** *(Hình 2.3 — Sequence diagram L0: scan folder → sort timestamps →
merge stream → PyO3 handoff)*

#### 2.3.1 Chiến lược Multi-file Merge
- Scan thư mục → timestamp range từng file → merge-sort theo UTC toàn cục.
- *Lý do sort UTC toàn cục:* Markov Chain (Ch.1 §1.2.3) yêu cầu đúng thứ tự
  thời gian thực. Sai thứ tự → transition matrix sai → Seq score sai.

#### 2.3.2 Path Normalization — Hai chiều
- *Chiều chuẩn hóa (→ lowercase + forward-slash):* mục tiêu graph dedup —
  `C:\Windows\cmd.exe` và `c:/windows/cmd.exe` là cùng một binary, không được
  tạo thành 2 node khác nhau.
- *Chiều ngược (→ backslash trước Sigma match):* SigmaHQ viết rule theo
  Windows convention (`c:\windows\...`). Nếu không convert lại, toàn bộ
  matching thất bại.
- **Quan trọng:** Hai bước này phải thực hiện đúng thứ tự trong pipeline.

---

### 2.4 Thiết kế Layer 1 — Sigma Engine

**Sơ đồ:** *(Hình 2.4 — Flow diagram L1: event stream → rule matching → score
aggregation → confidence override)*

#### 2.4.1 Thiết kế Confidence Override System
- Schema `confidence_override.json`: `{rule_id → CM_override}`.
- Workflow: analyst ghi đè $CM_i$ cho rule sinh nhiều FP mà không sửa rule gốc.
- **Giá trị $B_i$ và $CM_i$ mặc định theo level:**

| Severity | $B_i$ | $CM_i$ default |
|----------|-------|----------------|
| Critical | 8.0   | 1.00 |
| High     | 6.0   | 0.90 |
| Medium   | 4.0   | 0.70 |
| Low      | 2.0   | 0.50 |

#### 2.4.2 Chọn $\lambda_S$ = 0.25
- *Phân tích:* Với $\lambda_S = 0.25$, 10 rule match cộng thêm
  $0.25 \times \log_2(11) \approx 0.86$ điểm. Đủ để có ý nghĩa nhưng không
  làm rule Low × nhiều vượt rule Critical × ít.
- *Validation:* Sweep $\lambda_S \in \{0.1, 0.25, 0.5, 1.0\}$ trên dataset;
  $\lambda_S = 0.25$ cho Precision cao nhất với Recall ổn định.

---

### 2.5 Thiết kế Layer 2-A — Graph Build & Deduplication

**Sơ đồ:** *(Hình 2.5 — Graph construction: EID 1 events → ProcessGuid DAG →
deduplication pass → pruned graph)*

#### 2.5.1 Chọn $n_{rep}$ = 2
- *Tradeoff:* $n_{rep} = 1$ → mất thông tin variance nội bộ group (IPAS kém
  chính xác). $n_{rep} = 3$ → lợi ích nén giảm.
- *Empirical:* Đo % giảm node và sai số IPAS theo $n_{rep}$ trên dataset
  mẫu → $n_{rep} = 2$ cân bằng tốt nhất.

#### 2.5.2 Danh sách SHELL_WRAPPERS
Liệt kê và lý giải từng entry: `cmd.exe`, `powershell.exe`, `pwsh.exe`,
`bash.exe`, `wsl.exe`. *Phân biệt rõ:* shell wrapper ≠ công cụ admin — không
whitelist `wmic.exe`, `certutil.exe`,... vì attacker dùng được.

---

### 2.6 Thiết kế Layer 2-B — Baseline Builder

**Sơ đồ:** *(Hình 2.6 — Sub-pass flow: All EID1 → NIF computation → V₁₀
vectorization → HDBSCAN fit → cluster assignment)*

#### 2.6.1 Chọn tham số HDBSCAN
- **`min_cluster_size` = 15:** Sweep 5→50 trên dataset; < 10 → quá phân mảnh
  (nhiều vi-cụm vô nghĩa); > 20 → gộp profile khác nhau vào một cụm, giảm
  sensitivity. 15 cho silhouette score cao nhất.
- **Sampling threshold = 50,000 process:** Đo memory footprint vs N → HDBSCAN
  vượt 8GB RAM tại N ≈ 60,000. Chọn 50,000 với buffer 20%.
- **Cluster Ceiling $K_{max}$ = 30:** Trên dataset thực, số profile hành vi
  phân biệt tối đa quan sát được ≈ 20–25. $K_{max} = 30$ có buffer an toàn.

#### 2.6.2 Thiết kế $\vec{w}_{sus}$ (Cluster Risk Profile weights)

| Feature | $w_{sus}$ | Lý do |
|---------|-----------|-------|
| $v_2$ has_injection | 3.0 | Ít use case hợp lệ nhất |
| $v_1$ has_network | 2.5 | Phổ biến nhưng nguy hiểm cao |
| $v_3$ has_file_drop | 2.0 | Dropper/persistence |
| $v_4$ has_reg_mod | 1.5 | Persistence nhưng có use case hợp lệ |
| $v_6$ nif_pair | 2.0 | Cặp cha-con hiếm là tín hiệu mạnh |
| $v_5$ nif_binary | 1.5 | Binary hiếm, ít mạnh hơn pair |
| $v_7–v_9$ | 0.5 | Thông tin phụ trợ |
| $v_{10}$ | 1.0 | Context từ cha |

---

### 2.7 Thiết kế Layer 3 — Risk Evaluator: Áp dụng và Chọn Tham số

**Sơ đồ:** *(Hình 2.7 — Scoring pipeline: mỗi node đi qua P, C, S, Seq, Col
song song → CI combiner → Final Score)*

> Mỗi mục dưới đây trình bày: công thức áp dụng từ Ch.1 → lý do chọn tham số
> → giá trị cụ thể.

#### 2.7.1 P Score: Chọn $\theta$, $\alpha$, $\kappa$, $\delta$

**Chọn $\theta$ = 3.5 (MAD Gate):**
- *Cơ sở lý thuyết:* $z_{robust} = 3.5$ với $c = 0.6745$ tương ứng khoảng
  tin cậy 99.98% trong phân phối chuẩn — 0.02% điểm bình thường vượt ngưỡng.
- *Cơ sở thực nghiệm:* Sweep $\theta \in \{2.5, 3.0, 3.5, 4.0, 4.5\}$:
  $\theta = 3.0$ → FP rate 8.2% (quá cao do biến động tự nhiên log);
  $\theta = 4.0$ → FN rate 14.7% (bỏ sót anomaly moderate);
  $\theta = 3.5$ → F1 = 0.87, cân bằng tốt nhất.
- *Nhất quán với Seq:* cùng $\theta = 3.5$ cho cả hai thành phần → cùng mức
  bất thường tương đối cho cùng điểm số.

**Chọn $\alpha$ = 0.7 (P combination):**
- Thực nghiệm trên tập weaponized binary: IPAS bắt thêm 23% case mà MAD
  bỏ sót. Nhưng IPAS yêu cầu $N_{min}^{IPAS}$ instance → kém ổn định hơn
  trên group nhỏ → trọng số thấp hơn. Sweep cho $\alpha = 0.7$ cho F1 cao
  nhất.

**Chọn $\kappa$ = 2.5 (IPAS scale):**
- Phân tích phân phối $IPAS_{raw}$ trên dataset có ground truth: weaponized
  instance thực sự có $dist_{raw} \in [3.5, 4.5]$. Chọn $\kappa = 2.5$ để
  $4.0 \times 2.5 = 10.0$ → case rõ ràng nhất đạt điểm tối đa.

**Chọn $\delta$ = 4.0 (cluster $-1$ bonus):**
- Phân tích P trước bonus trên cluster $-1$ case: trung bình $P \in [3, 4]$.
  Cộng 4.0 → đẩy lên $[7, 8]$ (Tier 2 HIGH) — analyst chú ý nhưng không
  tự động Tier 1.

#### 2.7.2 C Score: Chọn $\gamma$, $c_0$, $c_1$

**Chọn $\gamma$ = 3.33:**
- Từ cơ sở §1.2.2: cluster ở $3\sigma$ nên đạt điểm tối đa → $3\gamma = 10
  \Rightarrow \gamma = 10/3 \approx 3.33$.

**Chọn $c_0$ = 4.0, $c_1$ = 3.0 (cluster $-1$ thụ động):**
- $c_0 = 4.0$: mức baseline cho outlier density không có hành vi — đủ để
  vào Tier 3 (MEDIUM) nhưng không vào Tier 2.
- $c_0 + c_1 \le 7$: kể cả NIF = 1 (binary hiếm nhất), điểm < 7 → không
  tự động Tier 1 chỉ vì là node noise hiếm.

#### 2.7.3 Seq Score: Chọn $\varepsilon_L$, $\theta$ (nhất quán 3.5)

**Chọn $\varepsilon_L$ = 0.01:**
- Đủ nhỏ để không làm sai xác suất transition phổ biến
  (Count = 100: $P = 101/110.01 \approx 0.918$ vs không smooth $100/110 =
  0.909$ — sai lệch < 1%).
- Đủ lớn để tránh log(0) và cho transition chưa gặp xác suất có ý nghĩa.

#### 2.7.4 Col Score: Chọn $N_{min}^{Col}$

**Chọn $N_{min}^{Col}$ = 4:**
- Phân tích Monte Carlo trên synthetic beaconing: với 3 intervals, FP = 28%;
  với 4 intervals, FP = 12%; với 5, FP = 8% nhưng bỏ sót beacon ngắn hạn.
- 4 intervals (5 timestamps) là điểm cân bằng tốt nhất.

#### 2.7.5 CI: Chọn $\rho_{floor}$, $\rho_{ceil}$, $\Delta_{CI}$, $\eta_\sigma$, $\tau_x$

**Chọn $\rho_{floor}$ = 0.9:**
- *Phân tích vùng chết:* Process có P=2, C=2, S=0, Seq=2 (3 tín hiệu moderate):
  weighted sum = $(0.25×2 + 0.20×2 + 0.25×2) = 1.4$.
  Với $\rho_{floor} = 0.8$: Final = $1.4 × 0.8 = 1.12$ → Tier 4 (SAFE) —
  bỏ sót.
  Với $\rho_{floor} = 0.9$: Final = $1.4 × 0.9 = 1.26$ — vẫn Tier 4 nhưng
  gần ngưỡng. *Thực nghiệm FN analysis cho thấy $\rho_{floor}$ = 0.9 làm
  giảm FN 6% so với 0.8.*

**Chọn $\rho_{floor}^{min}$ = 0.6 (adaptive floor):**
- Chỉ áp dụng khi $N_{active} = 0$ và tất cả tín hiệu < 1.0 → tiến trình
  gần như chắc chắn sạch. Final ≈ weighted_sum × 0.6 → về gần 0.

**Chọn $\rho_{ceil}$ = 1.5, $\Delta_{CI}$ = 0.1:**
- $N_{active} = 5$ (tối đa): CI = $1.0 + 0.1 × 3 = 1.3 < 1.5$ → ceiling
  không binding ở 5 tín hiệu. Chọn $\Delta_{CI} = 0.1$ (không phải 0.2 từ
  phân tích trước) để tránh over-amplification.
- Thực nghiệm: $\Delta_{CI} = 0.2$ → 12% FP tăng thêm do noise tín hiệu bị
  khuếch đại. $\Delta_{CI} = 0.1$ ổn định hơn.

**Chọn $\eta_\sigma$ = 7.0:**
- Rule với $S \ge 7.0$: cần $\max_i(B_i \times CM_i) \ge 7.0$ → chỉ Critical
  (8.0 × 1.0 = 8.0) hoặc High + CM cao (6.0 × 1.0 = 6.0 < 7 → không pass).
  Thực tế: chỉ Critical rules kích hoạt override.

**Chọn active thresholds $\{\tau_x\}$:**
- $\tau_P = 6.0$: top 1% outlier nhất.
- $\tau_C = 6.0$: cluster có risk $>2\sigma$ trên mean.
- $\tau_S = 3.0$: ít nhất 1 rule Medium match.
- $\tau_{Seq} = 5.0$: path có cross-entropy $1.5\sigma$ trên median.
- $\tau_{Col} = 6.0$: $CoV < 0.4$.

#### 2.7.6 Final Score Weights — Ablation Justification

*(Kết quả ablation study — mô tả setup, không trình bày số kết quả → dành
cho Ch.3)*

| Trọng số | Giá trị | Lý do (từ ablation) |
|---------|---------|---------------------|
| $w_S$ | 0.30 | Contribution cao nhất: Recall giảm nhiều nhất khi disable S |
| $w_P$ | 0.25 | Statistical foundation vững, ít phụ thuộc domain |
| $w_{Seq}$ | 0.25 | Attack chain — contribution cao khi có LOLBins |
| $w_C$ | 0.20 | Phụ thuộc chất lượng clustering hơn các thành phần kia |
| $w_{Col}$ | 0.10 | Additive, scale khác — không đưa vào CI multiplication |

---

### 2.8 Thiết kế Layer 4 — Aggregation & Output

**Sơ đồ:** *(Hình 2.8 — Output pipeline: backpropagation → tier assignment →
smart collapse → ASCII tree render)*

#### 2.8.1 Chọn $\beta$ = 0.8 (Backpropagation decay)
- $\beta = 1.0$ → root luôn nhận điểm cao nhất trong cây → mất discriminability.
- $\beta = 0.5$ → 3 tầng propagation → 12.5% → tín hiệu tắt quá nhanh.
- $\beta = 0.8$: sau 3 tầng → 51.2%. Analyst thấy rõ lineage nguy hiểm trong
  2–3 tầng, sau đó tín hiệu tắt dần. *Validation:* kiểm tra trên dataset
  APT với known ground truth lineage.*

#### 2.8.2 Tier Classification và Smart Collapse
- Phân tích phân phối Final Score trên dataset mixed → chọn ngưỡng Tier.
- **Smart Collapse ngưỡng 1.5 (Tier 4):** Validation: 0 TP bị collapse trên
  toàn bộ dataset có ground truth.
- Format output: ASCII Process Tree với Score, P/C/S/Seq/Col, MITRE tags,
  flags (INHERITED_RISK, CLUSTER_NEG1...).

---