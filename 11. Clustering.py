# =========================================================
# IMPORTS
# =========================================================

import os
import warnings
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

# =========================================================
# CAMINHOS
# =========================================================

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"

input_path   = os.path.join(base_path, "10. Features_PCA.csv")
graficos_dir = os.path.join(base_path, "Graficos_Modelagem")
output_path  = os.path.join(base_path, "12. Ativos_com_Clusters.csv")

os.makedirs(graficos_dir, exist_ok=True)

CORES_CLUSTER = ["#C00000", "#2F5496", "#548235", "#BF8F00", "#ED7D31",
                 "#7030A0", "#00B0F0", "#808080"]

def salvar(fig, nome):
    caminho = os.path.join(graficos_dir, nome)
    fig.savefig(caminho, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"    {nome}")

# =========================================================
# LEITURA DA BASE DE FEATURES + PCA
# =========================================================

print("Lendo base de features com PCA...")

features = pd.read_csv(input_path)
features = features.set_index("asset_id")

# Identificar colunas dos componentes principais
cols_pc = [c for c in features.columns if c.startswith("PC")]
X_pca = features[cols_pc].values

print(f"    Ativos: {len(features)}")
print(f"    Componentes PCA: {cols_pc}")
print(f"    Shape para clustering: {X_pca.shape}")


# ==========================================================
#
#   ETAPA 8 - CLUSTERING (K-MEANS)
#
#   Aplica K-Means sobre os componentes principais para
#   segmentar os ativos em grupos de risco.
#
# ==========================================================

print("\n" + "="*60)
print("ETAPA 8 - CLUSTERING (K-MEANS)")
print("="*60)

# ---------------------------------------------------------
# 8.1 Metodo Elbow + Silhouette para definir k
# ---------------------------------------------------------

print("\n8.1 - Testando k de 2 a 10 (Elbow + Silhouette)...")

range_k = range(2, 11)
inertias = []
silhouettes = []

for k in range_k:
    km = KMeans(n_clusters=k, init="k-means++", n_init=20, random_state=42)
    labels = km.fit_predict(X_pca)
    inertias.append(km.inertia_)
    sil = silhouette_score(X_pca, labels)
    silhouettes.append(sil)
    print(f"    k={k:2d}  |  inertia={km.inertia_:10.1f}  |  silhouette={sil:.4f}")

melhor_k = list(range_k)[np.argmax(silhouettes)]
melhor_sil = max(silhouettes)
print(f"\n    Melhor k pelo silhouette: {melhor_k} (score={melhor_sil:.4f})")

# ---------------------------------------------------------
# 8.2 Grafico Elbow + Silhouette
# ---------------------------------------------------------

print("\n8.2 - Gerando graficos Elbow e Silhouette...")

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].plot(list(range_k), inertias, "o-", color="#2F5496", linewidth=2, markersize=8)
axes[0].axvline(x=melhor_k, color="#C00000", linestyle="--",
                label=f"k = {melhor_k}")
axes[0].set_xlabel("Numero de clusters (k)")
axes[0].set_ylabel("Inercia (soma das distancias)")
axes[0].set_title("Metodo Elbow")
axes[0].set_xticks(list(range_k))
axes[0].legend()
axes[0].grid(True, alpha=0.3)

axes[1].plot(list(range_k), silhouettes, "o-", color="#548235", linewidth=2, markersize=8)
axes[1].axvline(x=melhor_k, color="#C00000", linestyle="--",
                label=f"k = {melhor_k} (sil={melhor_sil:.4f})")
axes[1].set_xlabel("Numero de clusters (k)")
axes[1].set_ylabel("Silhouette Score")
axes[1].set_title("Metodo Silhouette")
axes[1].set_xticks(list(range_k))
axes[1].legend()
axes[1].grid(True, alpha=0.3)

plt.tight_layout()
salvar(fig, "08_elbow_silhouette.png")

# ---------------------------------------------------------
# 8.3 Aplicar K-Means com melhor k
# ---------------------------------------------------------

print(f"\n8.3 - Aplicando K-Means com k={melhor_k}...")

kmeans_final = KMeans(n_clusters=melhor_k, init="k-means++", n_init=30, random_state=42)
features["cluster"] = kmeans_final.fit_predict(X_pca)
features["cluster"] = features["cluster"].astype("category")

print(f"\n    Distribuicao dos clusters:")
print(features["cluster"].value_counts().sort_index().to_string())

# ---------------------------------------------------------
# 8.4 Perfil dos clusters (medias das features originais)
# ---------------------------------------------------------

# Features de exposicao e organizacionais (excluindo descritivas e PCs)
cols_perfil = [
    "qtd_cves_aplicaveis", "cvss_score_medio", "cvss_score_max",
    "cvss_score_std", "qtd_critical", "qtd_high", "pct_critical_high",
    "qtd_cwes_distintos", "pct_aplicaveis",
    "classe_encoded", "criticidade_encoded", "ambiente_encoded",
]

print(f"\n8.4 - Perfil dos clusters (medias):")
perfil = features.groupby("cluster")[cols_perfil].mean().round(2)
print(perfil.to_string())

# ---------------------------------------------------------
# 8.5 Composicao dos clusters por variaveis categoricas
# ---------------------------------------------------------

print(f"\n8.5 - Composicao dos clusters:")

print("\n    Cluster x Classe:")
print(pd.crosstab(features["cluster"], features["classe"]).to_string())

print("\n    Cluster x Criticidade:")
crit_order = ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA"]
cross_crit = pd.crosstab(features["cluster"], features["criticidade"])
cross_crit = cross_crit.reindex(columns=[c for c in crit_order if c in cross_crit.columns])
print(cross_crit.to_string())

print("\n    Cluster x Ambiente:")
cross_amb = pd.crosstab(features["cluster"], features["ambiente"])
print(cross_amb.to_string())

print("\n    Cluster x SO (top por cluster):")
for c in sorted(features["cluster"].unique()):
    top_so = features[features["cluster"]==c]["so_produto"].value_counts().head(5)
    print(f"\n    Cluster {c}:")
    print(top_so.to_string())

# ---------------------------------------------------------
# 8.6 Grafico dos clusters nos 2 primeiros componentes
# ---------------------------------------------------------

print(f"\n8.6 - Gerando grafico de dispersao dos clusters...")

fig, ax = plt.subplots(figsize=(10, 7))

for c in sorted(features["cluster"].unique()):
    mask = features["cluster"] == c
    qtd = mask.sum()
    ax.scatter(X_pca[mask, 0], X_pca[mask, 1],
               c=CORES_CLUSTER[c % len(CORES_CLUSTER)],
               label=f"Cluster {c} ({qtd} ativos)",
               alpha=0.6, edgecolors="white", s=60)

centroides = kmeans_final.cluster_centers_
ax.scatter(centroides[:, 0], centroides[:, 1],
           c="black", marker="X", s=200, linewidths=2, label="Centroides")

ax.set_xlabel(f"PC1 (exposicao tecnica)")
ax.set_ylabel(f"PC2 (severidade relativa)")
ax.set_title(f"Segmentacao de risco - K-Means (k={melhor_k})")
ax.legend(loc="best")
ax.grid(True, alpha=0.3)
plt.tight_layout()
salvar(fig, "09_clusters_pca.png")

# ---------------------------------------------------------
# 8.7 Grafico de perfil comparativo dos clusters
# ---------------------------------------------------------

print("8.7 - Gerando grafico de perfil dos clusters...")

perfil_norm = perfil.copy()
for col in perfil_norm.columns:
    vmin = perfil_norm[col].min()
    vmax = perfil_norm[col].max()
    if vmax > vmin:
        perfil_norm[col] = (perfil_norm[col] - vmin) / (vmax - vmin)
    else:
        perfil_norm[col] = 0.5

fig, ax = plt.subplots(figsize=(12, 6))
perfil_norm.T.plot(kind="bar", ax=ax,
                   color=[CORES_CLUSTER[i % len(CORES_CLUSTER)]
                          for i in range(melhor_k)])
ax.set_ylabel("Valor normalizado (0 = minimo, 1 = maximo)")
ax.set_title("Perfil comparativo dos clusters")
ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
ax.legend(title="Cluster", bbox_to_anchor=(1.02, 1))
ax.grid(True, alpha=0.3)
plt.tight_layout()
salvar(fig, "10_perfil_clusters.png")


# ==========================================================
# SALVAR BASE FINAL COM CLUSTERS
# ==========================================================

print("\nSalvando base final com clusters...")

features_save = features.reset_index()
features_save.to_csv(output_path, index=False, encoding="utf-8-sig")
print(f"    {output_path}")


# ==========================================================
# RESUMO FINAL
# ==========================================================

print(f"\n{'='*60}")
print(f"RESUMO - CLUSTERING")
print(f"{'='*60}")
print(f"    Algoritmo:          K-Means")
print(f"    Clusters:           {melhor_k} (melhor silhouette)")
print(f"    Silhouette score:   {melhor_sil:.4f}")
print(f"")
print(f"    Distribuicao:")
for c in sorted(features["cluster"].unique()):
    qtd = (features["cluster"]==c).sum()
    pct = qtd/len(features)*100
    print(f"      Cluster {c}: {qtd} ativos ({pct:.1f}%)")
print(f"")
print(f"    ARTEFATOS:")
print(f"      Base:     12. Ativos_com_Clusters.csv ({len(features)} x {len(features_save.columns)})")
print(f"      Graficos: Graficos_Modelagem/08_elbow_silhouette.png")
print(f"                Graficos_Modelagem/09_clusters_pca.png")
print(f"                Graficos_Modelagem/10_perfil_clusters.png")
print(f"{'='*60}")
print(f"Concluido!")
