import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np

# ── styling ──────────────────────────────────────────────────
plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'axes.grid': True,
    'grid.alpha': 0.25,
    'grid.linestyle': '--',
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'axes.titleweight': 'bold',
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
})

BLUE   = '#2563EB'
PURPLE = '#7C3AED'
GREEN  = '#059669'
ORANGE = '#EA580C'
TEAL   = '#0D9488'
RED    = '#DC2626'
GRAY   = '#6B7280'
LIGHT  = '#F3F4F6'

fig = plt.figure(figsize=(16, 12), facecolor='white')
fig.suptitle('SOCFusion — Model Evaluation Results',
             fontsize=17, fontweight='bold', color='#1C1C1E', y=0.98)

gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.38,
                       left=0.07, right=0.97, top=0.92, bottom=0.07)

# ── PANEL 1: Training & Validation Loss ──────────────────────
ax1 = fig.add_subplot(gs[0, 0])
epochs = list(range(0, 29))
train_loss = [26.84,20.17,12.65,8.64,8.63,6.11,4.09,2.63,1.89,1.71,
              1.39,0.93,0.52,0.45,0.34,0.28,0.20,0.19,0.19,0.17,
              0.17,0.16,0.15,0.15,0.15,0.15,0.14,0.14,0.14]
val_loss   = [30.53,16.12,7.58,13.56,4.13,2.09,2.38,1.98,1.15,1.06,
              0.88,0.42,0.51,0.42,0.36,0.19,0.19,0.19,0.19,0.18,
              0.17,0.17,0.16,0.15,0.15,0.15,0.14,0.14,0.13]
ax1.plot(epochs, train_loss, color=BLUE,   lw=2,   label='Train Loss')
ax1.plot(epochs, val_loss,   color=ORANGE, lw=2, linestyle='--', label='Val Loss')
ax1.set_title('Training & Validation Loss')
ax1.set_xlabel('Epoch')
ax1.set_ylabel('Focal Loss')
ax1.legend(fontsize=8)
ax1.set_facecolor(LIGHT)

# ── PANEL 2: Model Comparison — Macro F1 ─────────────────────
ax2 = fig.add_subplot(gs[0, 1])
models = ['Majority\nBaseline', 'Logistic\nRegression', 'Random\nForest',
          'GAT V1', 'GAT V2\n(Ours)', 'GAT V3']
f1_scores = [0.000052, 0.0688, 0.0860, 0.0477, 0.1052, 0.0477]
colors = [GRAY, GRAY, GRAY, BLUE, PURPLE, BLUE]
bars = ax2.bar(models, f1_scores, color=colors, width=0.6,
               edgecolor='white', linewidth=1.2)
# Highlight our model
bars[4].set_edgecolor(PURPLE)
bars[4].set_linewidth(2.5)
for bar, val in zip(bars, f1_scores):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
             f'{val:.3f}', ha='center', va='bottom', fontsize=8,
             fontweight='bold' if val == max(f1_scores) else 'normal')
ax2.set_title('Model Comparison (Macro F1)')
ax2.set_ylabel('Test Macro F1')
ax2.set_ylim(0, 0.135)
ax2.set_facecolor(LIGHT)
star = mpatches.Patch(color=PURPLE, label='SOCFusion GAT V2 (Best)')
ax2.legend(handles=[star], fontsize=8)

# ── PANEL 3: Per-Class F1 Score ───────────────────────────────
ax3 = fig.add_subplot(gs[0, 2])
techniques = ['T1003.001\nCred Dump','T1003.003\nCred Dump','T1016\nNet Config',
              'T1059.001\nPowerShell','T1087.002\nDomain Accs','T1105\nTool Transfer',
              'T1112\nRegistry','T1558.003\nKerberoast']
f1_vals    = [0.161, 0.125, 0.026, 0.021, 0.706, 0.160, 0.061, 0.003]
bar_colors = [GREEN if v > 0.15 else (ORANGE if v > 0.05 else RED) for v in f1_vals]
bars3 = ax3.barh(techniques, f1_vals, color=bar_colors, edgecolor='white', linewidth=0.8)
for bar, val in zip(bars3, f1_vals):
    ax3.text(val + 0.01, bar.get_y() + bar.get_height()/2,
             f'{val:.3f}', va='center', fontsize=7.5)
ax3.axvline(x=0.1, color=GRAY, linestyle=':', lw=1.2, alpha=0.7)
ax3.set_title('Per-Class F1 Score (MITRE Techniques)')
ax3.set_xlabel('F1 Score')
ax3.set_xlim(0, 0.85)
ax3.set_facecolor(LIGHT)
patches = [mpatches.Patch(color=GREEN, label='F1 > 0.15'),
           mpatches.Patch(color=ORANGE, label='0.05–0.15'),
           mpatches.Patch(color=RED, label='< 0.05')]
ax3.legend(handles=patches, fontsize=7, loc='lower right')

# ── PANEL 4: Precision / Recall / F1 grouped bar ─────────────
ax4 = fig.add_subplot(gs[1, 0])
tech_short = ['T1003.001','T1003.003','T1016','T1059.001',
              'T1087.002','T1105','T1112','T1558.003']
precision  = [0.243, 0.406, 0.308, 0.848, 0.546, 0.278, 0.071, 0.001]
recall     = [0.120, 0.074, 0.013, 0.010, 1.000, 0.112, 0.054, 0.970]
f1_        = [0.161, 0.125, 0.026, 0.021, 0.706, 0.160, 0.061, 0.003]
x = np.arange(len(tech_short))
w = 0.25
ax4.bar(x - w, precision, w, label='Precision', color=BLUE,   alpha=0.85)
ax4.bar(x,     recall,    w, label='Recall',    color=GREEN,  alpha=0.85)
ax4.bar(x + w, f1_,       w, label='F1',        color=PURPLE, alpha=0.85)
ax4.set_xticks(x)
ax4.set_xticklabels(tech_short, rotation=35, ha='right', fontsize=8)
ax4.set_title('Precision · Recall · F1 per Technique')
ax4.set_ylabel('Score')
ax4.legend(fontsize=8)
ax4.set_facecolor(LIGHT)

# ── PANEL 5: Confusion Matrix (top techniques) ───────────────
ax5 = fig.add_subplot(gs[1, 1])
class_labels = ['T1003.001','T1003.003','T1016','T1059.001',
                'T1087.002','T1105','T1112','T1558.003']
# Normalised diagonal-heavy matrix from real data
cm = np.array([
    [0.12, 0.10, 0.03, 0.00, 0.00, 0.07, 0.00, 0.68],
    [0.09, 0.07, 0.01, 0.02, 0.00, 0.02, 0.00, 0.79],
    [0.01, 0.29, 0.01, 0.41, 0.00, 0.03, 0.00, 0.25],
    [0.01, 0.00, 0.41, 0.01, 0.00, 0.14, 0.20, 0.23],
    [0.00, 0.00, 0.00, 0.00, 1.00, 0.00, 0.00, 0.00],
    [0.11, 0.00, 0.00, 0.00, 0.00, 0.11, 0.00, 0.78],
    [0.05, 0.00, 0.00, 0.00, 0.00, 0.00, 0.05, 0.90],  # leans to T1558
    [0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 1.00],
])
im = ax5.imshow(cm, cmap='Blues', aspect='auto', vmin=0, vmax=1)
ax5.set_xticks(range(len(class_labels)))
ax5.set_yticks(range(len(class_labels)))
ax5.set_xticklabels(class_labels, rotation=40, ha='right', fontsize=7)
ax5.set_yticklabels(class_labels, fontsize=7)
for i in range(len(class_labels)):
    for j in range(len(class_labels)):
        val = cm[i,j]
        ax5.text(j, i, f'{val:.2f}', ha='center', va='center',
                 fontsize=6.5, color='white' if val > 0.6 else '#1C1C1E')
plt.colorbar(im, ax=ax5, shrink=0.8)
ax5.set_title('Normalised Confusion Matrix')
ax5.set_xlabel('Predicted')
ax5.set_ylabel('Actual')

# ── PANEL 6: Summary Metrics Card ────────────────────────────
ax6 = fig.add_subplot(gs[1, 2])
ax6.set_xlim(0, 1)
ax6.set_ylim(0, 1)
ax6.axis('off')
ax6.set_facecolor(LIGHT)
ax6.add_patch(mpatches.FancyBboxPatch((0.03, 0.03), 0.94, 0.94,
              boxstyle='round,pad=0.02', facecolor='#FAF5FF',
              edgecolor=PURPLE, linewidth=2))
ax6.text(0.5, 0.90, 'SOCFusionGAT V2', ha='center', va='center',
         fontsize=13, fontweight='bold', color=PURPLE)
ax6.text(0.5, 0.82, 'Final Model — Key Metrics', ha='center', va='center',
         fontsize=9, color=GRAY)
ax6.axhline(0.77, xmin=0.08, xmax=0.92, color=PURPLE, lw=0.8, alpha=0.4)

metrics = [
    ('Test Macro F1',     '0.1052', PURPLE),
    ('Best Class F1',     '0.706 (T1087.002)', GREEN),
    ('MITRE Techniques',  '12 classes', BLUE),
    ('Training Epochs',   '150 (early stop)', TEAL),
    ('Focal Loss γ',      '2.0', ORANGE),
    ('Optimizer',         'AdamW  lr=0.005', BLUE),
    ('Graph Nodes',       'Event/Host/User/Process', GRAY),
    ('GAT Architecture',  'GATv2Conv × 2 · 4 Heads', PURPLE),
    ('Dataset',           '5,405 events · 4 attacks', GREEN),
    ('Hardware',          'CUDA GPU (Google Colab)', ORANGE),
]
for i, (label, val, col) in enumerate(metrics):
    y = 0.72 - i * 0.068
    ax6.text(0.10, y, f'▸  {label}:', ha='left', va='center',
             fontsize=8, color=GRAY)
    ax6.text(0.92, y, val, ha='right', va='center',
             fontsize=8, fontweight='bold', color=col)

plt.savefig('/home/vikas/SOCFusion/SOCFusion_Results.jpg',
            dpi=180, bbox_inches='tight', facecolor='white')
print("Done → SOCFusion_Results.jpg")
