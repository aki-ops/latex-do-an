import os
import re

files_to_fix = [
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_1_Co_so_ly_thuyet.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_2_Thiet_ke_he_thong.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Chuong_3_Thuc_nghiem_va_danh_gia.tex",
    r"C:\Users\Admin\Documents\GitHub\latex-do-an\Chuong\Phu_luc_A.tex"
]

def fix_table_caption(content):
    # Regex to find \begin{table}... \end{table} blocks
    # We use non-greedy matching .*? with DOTALL to match across multiple lines
    def replacer(match):
        table_content = match.group(0)
        
        # Check if it has a \caption
        if '\\caption' not in table_content:
            return table_content
            
        # Check if \caption is below \begin{tabular}
        idx_tabular = table_content.find('\\begin{tabular}')
        idx_caption = table_content.find('\\caption')
        
        if idx_tabular != -1 and idx_caption > idx_tabular:
            # We need to extract the caption line(s) and move it before \begin{tabular}
            # Sometimes \caption is followed by \label on the next line.
            # So let's extract everything from \caption{...} up to the \label{...} if it exists nearby.
            
            # Using regex to find \caption{...} and optionally \label{...} that immediately follows it
            # We must be careful because caption can span multiple lines.
            
            # Find the \begin{tabular} part and \end{tabular} part
            tabular_match = re.search(r'(\\begin\{tabular\}.*?\\end\{tabular\})', table_content, re.DOTALL)
            if not tabular_match:
                return table_content
            tabular_block = tabular_match.group(1)
            
            # Remove tabular_block from table_content
            content_without_tabular = table_content.replace(tabular_block, '')
            
            # Now content_without_tabular contains \begin{table}, \centering, \caption, \label, \end{table}
            # We want the \caption and \label to be BEFORE the tabular block.
            # Let's reconstruct it manually.
            # \begin{table}[H]
            # \centering
            # \small
            # \setlength...
            # \caption{...}
            # \label{...}
            # \begin{tabular}... \end{tabular}
            # \end{table}
            
            lines = table_content.split('\n')
            
            # Extract caption lines and label lines
            caption_label_lines = []
            other_lines_top = []
            tabular_lines = []
            
            in_tabular = False
            for line in lines:
                if '\\begin{tabular}' in line:
                    in_tabular = True
                
                if in_tabular:
                    tabular_lines.append(line)
                    if '\\end{tabular}' in line:
                        in_tabular = False
                else:
                    if '\\caption' in line or '\\label' in line:
                        caption_label_lines.append(line)
                    elif '\\begin{table}' not in line and '\\end{table}' not in line:
                        other_lines_top.append(line)
            
            new_table = ['\\begin{table}[H]'] + other_lines_top + caption_label_lines + tabular_lines + ['\\end{table}']
            return '\n'.join(new_table)
            
        return table_content

    # Match each table environment
    return re.sub(r'\\begin\{table\}.*?\\end\{table\}', replacer, content, flags=re.DOTALL)

for filepath in files_to_fix:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        new_content = fix_table_caption(content)
        
        if new_content != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed captions in {filepath}")
        else:
            print(f"No changes in {filepath}")
