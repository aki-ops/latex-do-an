2.1. Dữ liệu log Windows cho phân tích hành vi

Kiến trúc tiến trình, vấn đề PID reuse → khái niệm ProcessGuid.

Các trường thông tin chính trong Sysmon Event ID 1,3,8,10,11,13,17,18,22.

Sự cần thiết của việc chuẩn hóa đường dẫn (case, slash, expand variable) để đảm bảo nhất quán.

2.2. Các loại bất thường trong log tiến trình (theo Chandola et al.)

Point anomaly: Một tiến trình có đặc trưng định lượng (độ dài command line, entropy, số con,…) khác thường so với phần lớn.

Contextual anomaly: Một tiến trình bình thường nếu đứng riêng nhưng lại xuất hiện trong ngữ cảnh không phù hợp (ví dụ winword.exe sinh cmd.exe).

Collective anomaly: Một nhóm các hành vi riêng lẻ bình thường nhưng kết hợp thành chuỗi hoặc mẫu thời gian bất thường (ví dụ chuỗi tiến trình hiếm gặp, beaconing đều đặn).

2.3. Ước lượng mức độ hiếm dựa trên tần suất – NIF

Khái niệm tần suất xuất hiện của một giá trị (tên tiến trình, cặp cha-con) trong toàn bộ log.

Tại sao logarit: Giảm ảnh hưởng của chênh lệch lớn, làm mịn phân phối.

Định nghĩa Normalized Inverse Frequency (NIF):

NIF
(
x
)
=
1
−
log
⁡
(
count
(
x
)
)
log
⁡
(
count
max
⁡
)
NIF(x)=1− 
log(count 
max
​
 )
log(count(x))
​
 
NIF ∈ [0,1], càng gần 1 càng hiếm. Đây là đại lượng tương đối nội tại trong dataset.

2.4. Đo lường điểm bất thường dựa trên phân phối – Nguyên lý MAD

Trung vị (median) và độ lệch tuyệt đối trung vị (MAD):

MAD
=
median
i
(
∣
x
i
−
median
(
X
)
∣
)
MAD=median 
i
​
 (∣x 
i
​
 −median(X)∣)
Tính bền vững (robustness): MAD ít bị ảnh hưởng bởi outlier so với độ lệch chuẩn.

Z-score bền vững:

z
robust
=
0.6745
⋅
(
x
−
median
(
X
)
)
MAD
z 
robust
​
 = 
MAD
0.6745⋅(x−median(X))
​
 
(Hệ số 0.6745 giúp z_robust tương đương với z-score chuẩn nếu dữ liệu có phân phối chuẩn.)

Ý nghĩa: Cho phép so sánh mức độ “lệch” giữa các đặc trưng khác thang đo. Một giá trị càng lớn về trị tuyệt đối càng bất thường.

2.5. Phát hiện bất thường trong nội bộ nhóm (weaponization) – IPAS

Tình huống: Trong một nhóm các tiến trình có cùng tên file (ví dụ 500 php-cgi.exe), chỉ một vài bị khai thác, hành vi của chúng khác biệt rõ so với số đông.

Nguyên lý: So sánh vector đặc trưng của từng cá thể với phân phối của chính nhóm đó.

Khoảng cách Mahalanobis đơn giản hóa (giả sử các chiều độc lập):

dist
j
=
1
d
∑
k
=
1
d
∣
v
j
,
k
−
μ
k
∣
σ
k
+
ϵ
dist 
j
​
 = 
d
1
​
  
k=1
∑
d
​
  
σ 
k
​
 +ϵ
∣v 
j,k
​
 −μ 
k
​
 ∣
​
 
trong đó μ_k, σ_k là trung bình và độ lệch chuẩn của chiều thứ k trong nhóm.

Điểm IPAS là một hàm tăng dần của dist này, phản ánh mức độ “lạc loài” trong nội bộ.

2.6. Nhóm hành vi ngữ cảnh – Clustering và HDBSCAN

Đặc trưng hóa tiến trình: Cần một vector bao gồm các thuộc tính nhị phân (có network, có injection, …) và các thuộc tính liên tục/rời rạc khác (NIF, entropy, chiều dài command line, số con, …) – ký hiệu là V₁₀.

Mục đích: Gom các tiến trình có cùng “kiểu hành vi ngữ cảnh” vào các cụm.

HDBSCAN:

Ưu điểm: Không cần xác định trước số cụm, tự động phát hiện cụm mật độ thay đổi, gán nhãn nhiễu (-1) cho các điểm không thuộc cụm nào.

Nguyên lý: Dựa trên lưới khoảng cách và tính bền vững theo mật độ.

Lưu ý: Cụm -1 (nhiễu) chứa các tiến trình có hành vi rất khác biệt, cần được xử lý riêng trong pha định lượng rủi ro.

2.7. Đánh giá mức độ nguy hiểm của một cụm – Trọng số ngữ cảnh

Mỗi cụm (hoặc nhiễu) có một vector centroid đặc trưng.

Gán một vector trọng số W_sus phản ánh mức độ liên quan đến tấn công của từng đặc trưng (tham khảo MITRE ATT&CK).

Độ nguy hiểm của cụm k: 
risk
k
=
Centroid
k
⋅
W
sus
risk 
k
​
 =Centroid 
k
​
 ⋅W 
sus
​
 .

2.8. Chuẩn hóa so sánh chỉ khi vượt trội – One‑sided Z‑score

Vấn đề: Không phải mọi sự khác biệt đều đáng báo động; chỉ những cụm có risk cao hơn mức trung bình mới là bất thường.

Giải pháp: Tính trung bình μ và độ lệch chuẩn σ của các risk_k. Sau đó:

z
k
=
risk
k
−
μ
σ
z 
k
​
 = 
σ
risk 
k
​
 −μ
​
 
Nếu z_k ≤ 0 (risk không cao hơn trung bình) → coi như bình thường. Nếu z_k > 0, dùng hàm tăng để chuyển thành điểm C (sẽ được thiết kế trong Chương 3).

2.9. Mô hình hóa chuỗi hành vi – Markov bậc 2

Biểu diễn chuỗi tiến trình: p₁ → p₂ → … → p_N.

Giả thiết Markov bậc 2: Xác suất của bước tiếp theo chỉ phụ thuộc vào hai bước trước đó:

P
(
p
i
∣
p
i
−
2
,
p
i
−
1
)
P(p 
i
​
 ∣p 
i−2
​
 ,p 
i−1
​
 )
Ước lượng xác suất từ dữ liệu: Đếm tần số xuất hiện của các bộ ba (a,b,c) và của các cặp (a,b). Sử dụng Laplace smoothing (cộng thêm α) để tránh xác suất bằng 0.

Đo độ bất thường của toàn chuỗi: Log‑likelihood âm trung bình:

score
raw
=
−
1
N
−
2
∑
i
=
3
N
log
⁡
P
(
p
i
∣
p
i
−
2
,
p
i
−
1
)
score 
raw
​
 =− 
N−2
1
​
  
i=3
∑
N
​
 logP(p 
i
​
 ∣p 
i−2
​
 ,p 
i−1
​
 )
Giá trị này càng lớn khi chuỗi càng hiếm gặp.

2.10. Phát hiện beaconing – Coefficient of Variation (CoV)

Tín hiệu: Một process kết nối mạng lặp lại với chu kỳ gần như đều đặn.

Cách đo: Với các timestamp t₁,…,tₘ (m ≥ 4), tính các khoảng thời gian d_i = t_{i+1} – t_i.

Trung bình 
d
ˉ
d
ˉ
 , độ lệch chuẩn σ_d.

Coefficient of Variation: 
CoV
=
σ
d
/
d
ˉ
CoV=σ 
d
​
 / 
d
ˉ
 .

Tính chất: CoV càng nhỏ, các khoảng cách càng đều, càng nghi ngờ beaconing. CoV không có đơn vị, cho phép so sánh các chuỗi với nhịp khác nhau.

2.11. Kết hợp các tín hiệu: nguyên lý Corroboration Index (CI)

Đồng thuận tín hiệu: Khi nhiều thành phần độc lập (P, C, S, Seq, Col) cùng chỉ ra bất thường, độ tin cậy tổng thể cao hơn mỗi thành phần riêng lẻ.

Tránh vùng chết: Cần một cơ chế đảm bảo rằng ngay cả khi các tín hiệu ở mức “trung bình” nhưng xuất hiện đồng thời, tổng điểm vẫn đủ để cảnh báo.

Định nghĩa CI: Một hàm tăng theo số lượng tín hiệu hoạt động, có giá trị tối thiểu (floor) > 0 và tối đa (cap) > 1. Giá trị cụ thể sẽ được thiết kế ở Chương 3.

2.12. Lan truyền rủi ro trong cây tiến trình – Guilt Backpropagation

Nguyên lý: Rủi ro của tiến trình con nên được “truy ngược” một phần lên tiến trình cha, vì cha chịu trách nhiệm sinh ra con.

Hệ số suy hao (decay): Một hằng số trong (0,1), thể hiện mức độ suy giảm rủi ro khi đi ngược lên.

Phép duyệt bottom‑up: Sau khi tính điểm cho tất cả các node, điểm của node cha được cập nhật bằng max(điểm hiện tại, max(điểm con × decay)).

2.13. Bảo toàn bằng chứng trong đồ thị tiến trình – Lossless Structural Deduplication

Vấn đề: Nhiều cạnh lặp lại (ví dụ svchost.exe → svchost.exe hàng trăm lần) gây nhiễu; nhưng các cạnh duy nhất (chỉ xuất hiện 1 lần) có thể chứa bằng chứng trinh sát quan trọng.

Nguyên lý tách:

Phân loại cạnh dựa trên tần suất xuất hiện của cặp (cha, con) trong toàn dataset.

Cạnh có tần suất > 1 có thể nén (giữ lại một vài đại diện).

Cạnh có tần suất = 1 được bảo toàn nguyên vẹn (structural novelty).

Đảm bảo kết nối: Các node làm cầu nối (có con) không bị xóa, và một số shell wrapper đặc biệt được bảo vệ để không làm gãy cây.

2.14. Hiệu năng xử lý log khổng lồ – Đọc nhị phân và bộ nhớ zero‑copy

Thách thức: Python với GIL và serialization JSON tạo nghẽn cổ chai khi parse file .evtx lớn.

Giải pháp: Sử dụng ngôn ngữ Rust với thư viện evtx để parse trực tiếp, sau đó dùng PyO3 để truyền các đối tượng Python mà không cần sao chép bộ nhớ (zero‑copy).