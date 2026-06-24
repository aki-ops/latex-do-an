import os
import re

latex_dir = r'C:\Users\Admin\Documents\GitHub\latex-do-an'
chuong_dir = os.path.join(latex_dir, 'Chuong')

def find_caption(text):
    idx = text.find(r'\caption')
    if idx == -1: return -1, -1
    
    # find the opening brace {
    open_idx = text.find('{', idx)
    if open_idx == -1: return -1, -1
    
    # brace matching
    brace_cnt = 0
    close_idx = -1
    for i in range(open_idx, len(text)):
        if text[i] == '{': brace_cnt += 1
        elif text[i] == '}':
            brace_cnt -= 1
            if brace_cnt == 0:
                close_idx = i
                break
                
    if close_idx == -1: return -1, -1
    return idx, close_idx + 1

def fix_table_captions(content):
    def replace_table(match):
        block = match.group(0)
        start_cap, end_cap = find_caption(block)
        if start_cap == -1: return block
        
        caption_str = block[start_cap:end_cap]
        tabular_idx = block.find(r'\begin{tabular')
        
        if tabular_idx != -1 and start_cap > tabular_idx:
            # caption is after tabular
            # Remove caption and any preceding newline/whitespace, but keep it simple: just remove caption_str
            # Actually, to be clean, let's remove \caption{...} and any trailing whitespaces
            # We'll just replace the exact caption_str with empty string.
            new_block = block[:start_cap] + block[end_cap:]
            # Then we insert it before \begin{tabular
            # find new tabular idx
            new_tab_idx = new_block.find(r'\begin{tabular')
            new_block = new_block[:new_tab_idx] + caption_str + '\n' + new_block[new_tab_idx:]
            # Also clean up empty lines where caption used to be
            new_block = re.sub(r'\n\s*\n', '\n', new_block)
            return new_block
            
        return block

    return re.sub(r'\\begin\{table\}.*?\\end\{table\}', replace_table, content, flags=re.DOTALL)


for root, _, files in os.walk(chuong_dir):
    for file in files:
        if file.endswith('.tex'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            new_content = fix_table_captions(content)
            
            if new_content != content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f'Fixed tables in {file}')
