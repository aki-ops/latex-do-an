import os
import re

files_to_fix = [
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_1_Co_so_ly_thuyet.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_2_Thiet_ke_he_thong.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_3_Thuc_nghiem_va_danh_gia.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_5_Ket_luan.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Mo_dau.tex"
]

acronyms = ["UAD", "BBS", "PID", "DDO", "AUC", "FPR", "TPR", "Sysmon", "EventLog", "Windows", "LotL", "APT", "ECOD", "KDE", "LOF", "SRAH", "SOC", "V10", "F1-Score", "F1", "KDE_Joint", "Mahalanobis", "DensPct", "DensPct_Mahal", "Isolation", "Forest", "Controlled", "Injection", "Local", "Pockets", "Point", "Anomaly", "Contextual", "Collective"]

def capitalize_title(title):
    words = title.split()
    if not words:
        return title
    
    # Capitalize first word no matter what
    res = [words[0].capitalize()]
    
    for word in words[1:]:
        # If word is in acronyms (case-insensitive check), keep acronym case
        is_acronym = False
        for acr in acronyms:
            if word.lower() == acr.lower():
                res.append(acr)
                is_acronym = True
                break
        
        if not is_acronym:
            res.append(word.lower())
            
    return " ".join(res)

def process_file(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Fix tone: replace "chúng tôi", "tôi", "nhóm nghiên cứu"
    # To be safe, we'll replace:
    # "Chúng tôi đề xuất" -> "Nghiên cứu đề xuất"
    # "chúng tôi đề xuất" -> "nghiên cứu đề xuất"
    # "Chúng tôi" -> "Nghiên cứu"
    # "chúng tôi" -> "nghiên cứu"
    # "Tôi" -> "Nghiên cứu"
    # "tôi" -> "nghiên cứu" (Wait, "tôi" might be part of other words if not careful, use word boundaries)
    # "nhóm nghiên cứu" -> "nghiên cứu"
    
    replacements = [
        (r'\bChúng tôi\b', 'Nghiên cứu'),
        (r'\bchúng tôi\b', 'nghiên cứu'),
        (r'\bNhóm nghiên cứu\b', 'Nghiên cứu'),
        (r'\bnhóm nghiên cứu\b', 'nghiên cứu'),
    ]
    # Handle standalone "tôi" and "Tôi" safely without messing up words like "tối"
    # Since "tôi" is often used as subject, just replacing it with "nghiên cứu" works.
    replacements.append((r'\bTôi\b', 'Nghiên cứu'))
    replacements.append((r'\btôi\b', 'nghiên cứu'))

    for pattern, repl in replacements:
        content = re.sub(pattern, repl, content)

    # 2. Fix headings
    def heading_replacer(match):
        cmd = match.group(1) # e.g. section
        star = match.group(2) # e.g. *
        title = match.group(3) # e.g. TỔNG QUAN VỀ HỆ THỐNG
        
        new_title = capitalize_title(title)
        return f"\\{cmd}{star}{{{new_title}}}"

    # Match \section{...}, \subsection{...}, \subsubsection{...}, \chapter{...}
    # including starred versions
    content = re.sub(r'\\(section|subsection|subsubsection|chapter)(\*?)\{([^}]+)\}', heading_replacer, content)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Processed: {filepath}")

for f in files_to_fix:
    process_file(f)
