import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import os


output_dir = r"C:\Users\Admin\Documents\GitHub\latex-do-an\images"
os.makedirs(output_dir, exist_ok=True)

# Function 1: Chandola Anomalies
def generate_chandola_anomalies():
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    # 1. Point Anomaly
    ax = axes[0]
    np.random.seed(42)
    x = np.random.normal(0, 1, 100)
    y = np.random.normal(0, 1, 100)
    ax.scatter(x, y, color='blue', alpha=0.5, label='Bình thường')
    ax.scatter([4], [4], color='red', s=100, label='Point Anomaly')
    ax.set_title('Bất thường Điểm (Point Anomaly)', fontsize=12)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.legend(loc='upper left')

    # 2. Contextual Anomaly (Time series)
    ax = axes[1]
    t = np.linspace(0, 10, 200)
    signal = np.sin(t) + np.random.normal(0, 0.1, 200)
    ax.plot(t, signal, color='blue', alpha=0.5, label='Bình thường')
    ax.scatter([t[50]], [signal[50]+1.5], color='red', s=50, label='Contextual Anomaly')
    ax.set_title('Bất thường Theo ngữ cảnh (Contextual Anomaly)', fontsize=12)
    ax.set_xticks([])
    ax.set_yticks([])
    
    # 3. Collective Anomaly
    ax = axes[2]
    x_col = np.random.normal(0, 1, 100)
    y_col = np.random.normal(0, 1, 100)
    x_abn = np.random.normal(5, 0.5, 20)
    y_abn = np.random.normal(5, 0.5, 20)
    ax.scatter(x_col, y_col, color='blue', alpha=0.5, label='Bình thường')
    ax.scatter(x_abn, y_abn, color='red', alpha=0.7, label='Collective Anomaly')
    ax.set_title('Bất thường Tập thể (Collective Anomaly)', fontsize=12)
    ax.set_xticks([])
    ax.set_yticks([])

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'chandola_anomalies.png'), dpi=300)
    plt.close()

# Function 2: Blending Mahalanobis
def generate_blending_mahalanobis():
    fig, ax = plt.subplots(figsize=(8, 6))
    np.random.seed(42)
    
    # Generate benign data with covariance
    mean = [0, 0]
    cov = [[2, 1.5], [1.5, 2]]
    x_benign, y_benign = np.random.multivariate_normal(mean, cov, 300).T
    
    # Generate malicious data blending in
    mean_mal = [1, 1]
    cov_mal = [[0.5, 0.3], [0.3, 0.5]]
    x_mal, y_mal = np.random.multivariate_normal(mean_mal, cov_mal, 50).T

    ax.scatter(x_benign, y_benign, color='#1f77b4', alpha=0.5, label='Tiến trình hợp lệ', s=20)
    ax.scatter(x_mal, y_mal, color='#d62728', alpha=0.8, label='Tiến trình độc hại (LotL)', s=30, marker='X')

    # Draw Mahalanobis ellipses
    from matplotlib.patches import Ellipse
    def draw_ellipse(position, covariance, ax=None, **kwargs):
        ax = ax or plt.gca()
        U, s, Vt = np.linalg.svd(covariance)
        angle = np.degrees(np.arctan2(U[1, 0], U[0, 0]))
        width, height = 2 * np.sqrt(s)
        for nsig in range(1, 4):
            ax.add_patch(Ellipse(position, nsig * width, nsig * height, angle=angle, **kwargs))

    draw_ellipse(mean, cov, ax=ax, fill=False, edgecolor='black', linestyle='--', alpha=0.5, linewidth=1.5)
    
    ax.set_title('Hiện tượng Hòa trộn và Không gian Mahalanobis', fontsize=14, pad=15)
    ax.set_xlabel('Đặc trưng hành vi 1', fontsize=12)
    ax.set_ylabel('Đặc trưng hành vi 2', fontsize=12)
    ax.legend()
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'blending_mahalanobis.png'), dpi=300)
    plt.close()

# Function 3: iForest Diagram
def generate_iforest_diagram():
    fig, ax = plt.subplots(figsize=(6, 6))
    np.random.seed(10)
    
    x = np.random.uniform(0, 10, 50)
    y = np.random.uniform(0, 10, 50)
    
    x_anom = [8]
    y_anom = [8]
    
    ax.scatter(x, y, color='blue', alpha=0.5)
    ax.scatter(x_anom, y_anom, color='red', s=100, label='Bất thường')
    
    # Splits to isolate anomaly
    ax.axhline(7, color='black', linestyle='-', linewidth=1.5)
    ax.axvline(6, ymin=0.7, color='black', linestyle='-', linewidth=1.5)
    ax.axhline(9, xmin=0.6, color='black', linestyle='-', linewidth=1.5)
    ax.axvline(9, ymin=0.7, ymax=0.9, color='black', linestyle='-', linewidth=1.5)

    # Label splits
    ax.text(0.5, 7.2, "Split 1", fontsize=10)
    ax.text(6.2, 9.5, "Split 2", fontsize=10)
    ax.text(9.2, 7.5, "Split 3", fontsize=10)

    ax.set_title('Minh họa Isolation Forest chia cắt không gian', fontsize=14)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'iforest_diagram.png'), dpi=300)
    plt.close()

# Function 4: Pipeline Diagram
def generate_pipeline_diagram():
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.axis('off')
    
    boxes = [
        ("Raw Windows\nEvent Logs\n(Sysmon)", 0.05, 0.4),
        ("Process\nExtraction", 0.25, 0.4),
        ("V10 Feature\nVectorization", 0.45, 0.4),
        ("Mahalanobis\nDistance Calc", 0.65, 0.4),
        ("BBS / DensPct\nScore Output", 0.85, 0.4)
    ]
    
    for i, (text, x, y) in enumerate(boxes):
        ax.add_patch(patches.FancyBboxPatch((x, y), 0.12, 0.2, boxstyle="round,pad=0.03", edgecolor='black', facecolor='#e1f5fe', lw=2))
        ax.text(x + 0.06, y + 0.1, text, ha='center', va='center', fontsize=10, weight='bold')
        if i < len(boxes) - 1:
            ax.annotate('', xy=(boxes[i+1][1], y+0.1), xytext=(x+0.12, y+0.1),
                        arrowprops=dict(arrowstyle="->", lw=2, color='black'))
            
    ax.set_title('Sơ đồ Pipeline Khung đo lường BBS', fontsize=14, weight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'bbs_pipeline.png'), dpi=300)
    plt.close()

# Function 5: Sysmon Diagram
def generate_sysmon_diagram():
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.axis('off')
    
    ax.add_patch(patches.FancyBboxPatch((0.1, 0.6), 0.2, 0.2, boxstyle="round,pad=0.03", edgecolor='black', facecolor='#fff9c4', lw=2))
    ax.text(0.2, 0.7, "OS Kernel /\nUser Mode", ha='center', va='center', fontsize=10, weight='bold')

    ax.add_patch(patches.FancyBboxPatch((0.4, 0.6), 0.2, 0.2, boxstyle="round,pad=0.03", edgecolor='black', facecolor='#c8e6c9', lw=2))
    ax.text(0.5, 0.7, "Sysmon\nDriver", ha='center', va='center', fontsize=10, weight='bold')

    ax.add_patch(patches.FancyBboxPatch((0.7, 0.6), 0.2, 0.2, boxstyle="round,pad=0.03", edgecolor='black', facecolor='#ffcdd2', lw=2))
    ax.text(0.8, 0.7, "EventLog\nService", ha='center', va='center', fontsize=10, weight='bold')

    ax.add_patch(patches.FancyBboxPatch((0.4, 0.2), 0.2, 0.2, boxstyle="round,pad=0.03", edgecolor='black', facecolor='#bbdefb', lw=2))
    ax.text(0.5, 0.3, "Log Analysis\nPlatform", ha='center', va='center', fontsize=10, weight='bold')

    ax.annotate('', xy=(0.4, 0.7), xytext=(0.3, 0.7), arrowprops=dict(arrowstyle="->", lw=2, color='black'))
    ax.annotate('', xy=(0.7, 0.7), xytext=(0.6, 0.7), arrowprops=dict(arrowstyle="->", lw=2, color='black'))
    ax.annotate('', xy=(0.5, 0.4), xytext=(0.5, 0.6), arrowprops=dict(arrowstyle="->", lw=2, color='black'))
    ax.annotate('', xy=(0.5, 0.4), xytext=(0.8, 0.6), arrowprops=dict(arrowstyle="->", lw=2, color='black', connectionstyle="angle,angleA=0,angleB=90,rad=10"))

    ax.set_title('Cơ chế hoạt động của Sysmon trên Windows', fontsize=14, weight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'sysmon_diagram.png'), dpi=300)
    plt.close()

if __name__ == "__main__":
    generate_chandola_anomalies()
    generate_blending_mahalanobis()
    generate_iforest_diagram()
    generate_pipeline_diagram()
    generate_sysmon_diagram()
    print("Generated 5 images in images/ directory.")
