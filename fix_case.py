import os
import re

chuong_dir = r'C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong'

replacements = {
    "Độ sâu Toàn cục qua Khoảng cách Mahalanobis": "Độ sâu toàn cục qua khoảng cách Mahalanobis",
    "Mô hình Chứng minh Tồn tại: KDE\_Joint": "Mô hình chứng minh tồn tại: KDE\_Joint",
    "Sự trung thực Học thuật: Hạn chế và Failure Mode của KDE\_Joint": "Sự trung thực học thuật: Hạn chế và Failure Mode của KDE\_Joint",
    "Cấu trúc Phi tham số Cục bộ qua KDE": "Cấu trúc phi tham số cục bộ qua KDE",
    "Bác bỏ Giả định Biên (Phân tích DDO)": "Bác bỏ giả định biên (phân tích DDO)",
    "Biểu diễn tiến trình và Chuẩn hóa đặc trưng": "Biểu diễn tiến trình và chuẩn hóa đặc trưng",
    "Phá vỡ Giới hạn bằng Bằng chứng Tồn tại (KDE\_Joint)": "Phá vỡ giới hạn bằng bằng chứng tồn tại (KDE\_Joint)",
    "Thiết kế Không gian Đặc trưng Hành vi V10": "Thiết kế không gian đặc trưng hành vi V10",
    "Biểu diễn Đồ thị Tiến trình": "Biểu diễn đồ thị tiến trình",
    "Thiết lập Thực nghiệm và Tập dữ liệu": "Thiết lập thực nghiệm và tập dữ liệu",
    "Nền tảng Windows Event Logging và Nhật ký sự kiện Sysmon": "Nền tảng Windows Event Logging và nhật ký sự kiện Sysmon",
    "Hai Đóng góp Học thuật Nổi bật của Luận văn": "Hai đóng góp học thuật nổi bật của luận văn",
    "Ảnh hưởng của Concept Drift và Cập nhật hệ thống": "Ảnh hưởng của Concept Drift và cập nhật hệ thống",
    "Nghịch lý Cấu trúc: Global Bias và Local Pockets": "Nghịch lý cấu trúc: Global Bias và Local Pockets",
    "Lý thuyết Học máy không giám sát (UAD) và Ảo giác Hiệu năng": "Lý thuyết học máy không giám sát (UAD) và ảo giác hiệu năng",
    "4. Phát biểu bài toán \& Mục tiêu nghiên cứu": "4. Phát biểu bài toán \& mục tiêu nghiên cứu",
    "Kết luận và Đánh giá chung": "Kết luận và đánh giá chung",
    "Đánh giá Tác động Cấu trúc (Phân tích DensPct\_Mahal)": "Đánh giá tác động cấu trúc (phân tích DensPct\_Mahal)",
    "Mật độ Toàn cục vs Cấu trúc Phi tham số Cục bộ": "Mật độ toàn cục vs cấu trúc phi tham số cục bộ",
    "Phân tích Nguyên nhân lỗi (Failure Mode)": "Phân tích nguyên nhân lỗi (Failure Mode)",
    "Bằng chứng Trực tiếp cho Local Pockets": "Bằng chứng trực tiếp cho Local Pockets",
    "Phương pháp Chọn ngưỡng (Threshold Protocol)": "Phương pháp chọn ngưỡng (Threshold Protocol)",
    "Mô hình Phát hiện Đa Cảm biến SRAH": "Mô hình phát hiện đa cảm biến SRAH",
    "Khung đo lường Cốt lõi: Độ sâu Toàn cục (DensPct\_Mahal)": "Khung đo lường cốt lõi: Độ sâu toàn cục (DensPct\_Mahal)",
    "Phương pháp luận tạo sinh Dữ liệu Tổng hợp (KB Datasets)": "Phương pháp luận tạo sinh dữ liệu tổng hợp (KB Datasets)",
    "Hiện tượng sụp đổ sớm F1-Score do Hạn chế của AUC": "Hiện tượng sụp đổ sớm F1-Score do hạn chế của AUC",
    "Ablation Study trên Không gian V10": "Ablation Study trên không gian V10"
}

def fix_content(content):
    def rep(m):
        cmd = m.group(1)
        val = m.group(2)
        new_val = replacements.get(val, val)
        return f"{cmd}{{{new_val}}}"
    return re.sub(r'(\\(?:sub)*section\*?)\{([^}]+)\}', rep, content)

for file in os.listdir(chuong_dir):
    if file.endswith('.tex'):
        path = os.path.join(chuong_dir, file)
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_content = fix_content(content)
        
        if new_content != content:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Updated case in {file}")
