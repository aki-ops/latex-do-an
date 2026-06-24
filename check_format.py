import os
import re

latex_dir = r'C:\Users\Admin\Documents\GitHub\latex-do-an'
chuong_dir = os.path.join(latex_dir, 'Chuong')

issues = []

# Check main.tex for 0_1_subject
with open(os.path.join(latex_dir, 'main.tex'), 'r', encoding='utf-8') as f:
    main_content = f.read()
    if r'%\subfile{chapters/0_1_subject.tex}' in main_content or r'%\subfile{Chuong/0_1_subject.tex}' in main_content:
        issues.append('Cấu trúc luận văn: Phần Đề tài tốt nghiệp (0_1_subject.tex) đang bị comment lại trong main.tex.')

# Check Chuong files
for root, _, files in os.walk(chuong_dir):
    for file in files:
        if file.endswith('.tex'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check chapter titles uppercase
                for i, line in enumerate(lines):
                    if line.strip().startswith('\chapter{'):
                        m = re.search(r'\\chapter{([^}]+)}', line)
                        if m:
                            title = m.group(1)
                            if title != title.upper():
                                issues.append(f'Tiêu đề chương chưa in hoa toàn bộ: "{title}" trong {file}')
                                
                # Check figure captions (should be below)
                fig_blocks = re.findall(r'\\begin{figure}.*?\\end{figure}', content, re.DOTALL)
                for block in fig_blocks:
                    if '\caption' in block and '\includegraphics' in block:
                        caption_idx = block.find('\caption')
                        graphics_idx = block.find('\includegraphics')
                        if caption_idx < graphics_idx:
                            issues.append(f'Hình vẽ: \\caption đang bị đặt TRÊN hình vẽ trong {file}. Theo quy định phải đặt DƯỚI.')
                            
                # Check table captions (should be above)
                table_blocks = re.findall(r'\\begin{table}.*?\\end{table}', content, re.DOTALL)
                for block in table_blocks:
                    if '\caption' in block and r'\begin{tabular' in block:
                        caption_idx = block.find('\caption')
                        tabular_idx = block.find(r'\begin{tabular')
                        if caption_idx > tabular_idx:
                            issues.append(f'Bảng biểu: \\caption đang bị đặt DƯỚI bảng trong {file}. Theo quy định phải đặt TRÊN.')

with open('issues.txt', 'w', encoding='utf-8') as f:
    if not issues:
        f.write('Không tìm thấy vi phạm định dạng nào!')
    else:
        for issue in issues:
            f.write('- ' + issue + '\n')
