# =========================================================
# IMPORTS
# =========================================================

import os
import warnings
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

# =========================================================
# CAMINHOS
# =========================================================

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"

input_path   = os.path.join(base_path, "7. Cruzamento_CMDB_CVE.csv")
graficos_dir = os.path.join(base_path, "Graficos_Modelagem")
output_path  = os.path.join(base_path, "9. Features_PCA.csv")

os.makedirs(graficos_dir, exist_ok=True)

CORES = {
    "azul": "#2F5496", "vermelho": "#C00000", "verde": "#548235",
    "amarelo": "#BF8F00", "cinza": "#808080", "laranja": "#ED7D31",
}

def salvar(fig, nome):
    caminho = os.path.join(graficos_dir, nome)
    fig.savefig(caminho, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"    {nome}")

# =========================================================
# LEITURA DA BASE
# =========================================================

print("Lendo base de cruzamento...")

df = pd.read_csv(input_path, low_memory=False)

df_com_cve = df[df["cve_aplicabilidade"] != "Sem CVE associado"].copy()
df_aplic   = df[df["cve_aplicabilidade"] == "Aplicável"].copy()

print(f"    Shape: {df.shape}")
print(f"    Ativos: {df['asset_id'].nunique()}")


# ==========================================================
#
#   ETAPA 6 - ENGENHARIA DE FEATURES
#
#   Transforma a base de cruzamento (433k linhas no nivel
#   ativo x CVE) em uma matriz de features com 1 linha
#   por ativo (525 linhas), contendo variaveis numericas
#   adequadas para PCA e clustering.
#
# ==========================================================

print("\n" + "="*60)
print("ETAPA 6 - ENGENHARIA DE FEATURES")
print("="*60)

# ---------------------------------------------------------
# 6.1 Extrair base CMDB (1 linha por ativo)
# ---------------------------------------------------------

print("\n6.1 - Extraindo atributos do CMDB por ativo...")

cmdb = df.drop_duplicates(subset="asset_id")[
    ["asset_id", "hostname", "classe", "tipo_ativo",
     "so_produto", "criticidade", "ambiente", "status",
     "app_produto"]
].copy().set_index("asset_id")

# ---------------------------------------------------------
# 6.2 Agregar metricas de CVE por ativo
# ---------------------------------------------------------

print("6.2 - Agregando metricas de CVE por ativo...")

# Volume total de CVEs (todas as classificacoes)
vol_total = (
    df_com_cve.groupby("asset_id")["cve_id"]
    .nunique().rename("qtd_cves_total")
)

# Volume de CVEs aplicaveis
vol_aplic = (
    df_aplic.groupby("asset_id")["cve_id"]
    .nunique().rename("qtd_cves_aplicaveis")
)

# Estatisticas CVSS (apenas aplicaveis)
cvss_stats = (
    df_aplic.groupby("asset_id")["cve_cvss_score"]
    .agg(cvss_score_medio="mean", cvss_score_max="max", cvss_score_std="std")
)
cvss_stats = cvss_stats.round(2)

# Contagem por severidade (apenas aplicaveis)
sev_counts = (
    df_aplic.groupby("asset_id")["cve_cvss_severity"]
    .value_counts().unstack(fill_value=0)
)
rename_sev = {"CRITICAL": "qtd_critical", "HIGH": "qtd_high",
              "MEDIUM": "qtd_medium", "LOW": "qtd_low"}
sev_counts = sev_counts.rename(columns=rename_sev)
for col in rename_sev.values():
    if col not in sev_counts.columns:
        sev_counts[col] = 0
sev_counts = sev_counts[list(rename_sev.values())]

# Percentual CRITICAL + HIGH
total_sev = sev_counts.sum(axis=1).replace(0, 1)
sev_counts["pct_critical_high"] = (
    (sev_counts["qtd_critical"] + sev_counts["qtd_high"]) / total_sev * 100
).round(1)

# Diversidade de CWEs
cwe_div = (
    df_aplic.groupby("asset_id")["cve_cwe_id"]
    .nunique().rename("qtd_cwes_distintos")
)

# ---------------------------------------------------------
# 6.3 Codificar variaveis categoricas do CMDB
# ---------------------------------------------------------

print("6.3 - Codificando variaveis categoricas...")

cmdb["classe_encoded"] = (cmdb["classe"] == "Servidor").astype(int)

mapa_crit = {"CRÍTICA": 4, "ALTA": 3, "MÉDIA": 2, "BAIXA": 1}
cmdb["criticidade_encoded"] = cmdb["criticidade"].map(mapa_crit).fillna(0).astype(int)

mapa_amb = {"Produção": 3, "Homologação": 2, "Desenvolvimento": 1}
cmdb["ambiente_encoded"] = cmdb["ambiente"].map(mapa_amb).fillna(0).astype(int)

# ---------------------------------------------------------
# 6.4 Juntar tudo em uma matriz de features
# ---------------------------------------------------------

print("6.4 - Montando matriz de features...")

features = (
    cmdb
    .join(vol_total, how="left")
    .join(vol_aplic, how="left")
    .join(cvss_stats, how="left")
    .join(sev_counts, how="left")
    .join(cwe_div, how="left")
)

# Preencher nulos com 0 (ativos sem CVE aplicavel)
cols_preencher = [
    "qtd_cves_total", "qtd_cves_aplicaveis",
    "cvss_score_medio", "cvss_score_max", "cvss_score_std",
    "qtd_critical", "qtd_high", "qtd_medium", "qtd_low",
    "pct_critical_high", "qtd_cwes_distintos",
]
for col in cols_preencher:
    if col in features.columns:
        features[col] = features[col].fillna(0)

# Percentual de aplicaveis sobre total
features["pct_aplicaveis"] = (
    features["qtd_cves_aplicaveis"] / features["qtd_cves_total"].replace(0, 1) * 100
).round(1).fillna(0)

# ---------------------------------------------------------
# 6.5 Definir features numericas para o modelo
# ---------------------------------------------------------

cols_descritivas = ["hostname", "classe", "tipo_ativo", "so_produto",
                    "criticidade", "ambiente", "status", "app_produto"]

cols_modelo = [
    "qtd_cves_aplicaveis",
    "cvss_score_medio",
    "cvss_score_max",
    "cvss_score_std",
    "qtd_critical",
    "qtd_high",
    "pct_critical_high",
    "qtd_cwes_distintos",
    "pct_aplicaveis",
    "classe_encoded",
    "criticidade_encoded",
    "ambiente_encoded",
]

print(f"    Ativos: {len(features)}")
print(f"    Features para o modelo: {len(cols_modelo)}")
print(f"    Colunas: {cols_modelo}")

# ---------------------------------------------------------
# 6.6 Escalonamento (StandardScaler)
# ---------------------------------------------------------

print("6.6 - Escalonando features (StandardScaler)...")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(features[cols_modelo])

print(f"    Shape escalado: {X_scaled.shape}")


# ==========================================================
#
#   ETAPA 7 - PCA (REDUCAO DE DIMENSIONALIDADE)
#
#   Reduz as 12 features para os componentes principais
#   que mais explicam a variancia, eliminando redundancia
#   e multicolinearidade identificadas na EDA.
#
# ==========================================================

print("\n" + "="*60)
print("ETAPA 7 - PCA (REDUCAO DE DIMENSIONALIDADE)")
print("="*60)

# ---------------------------------------------------------
# 7.1 PCA com todos os componentes (exploratoria)
# ---------------------------------------------------------

print("\n7.1 - PCA exploratoria (todos os componentes)...")

pca_full = PCA(n_components=len(cols_modelo), random_state=42)
pca_full.fit(X_scaled)

autovalores = pca_full.explained_variance_
variancia_pct = pca_full.explained_variance_ratio_ * 100
variancia_acum = np.cumsum(variancia_pct)

print(f"\n    Autovalores, variancia e variancia acumulada:")
for i in range(len(cols_modelo)):
    print(f"    PC{i+1:2d}:  autovalor={autovalores[i]:6.3f}  "
          f"variancia={variancia_pct[i]:5.1f}%  "
          f"acumulada={variancia_acum[i]:5.1f}%")

# ---------------------------------------------------------
# 7.2 Criterio de Kaiser (autovalor > 1)
# ---------------------------------------------------------

n_kaiser = (autovalores > 1).sum()
print(f"\n7.2 - Criterio de Kaiser: {n_kaiser} componentes com autovalor > 1")
print(f"    Variancia acumulada com {n_kaiser} componentes: {variancia_acum[n_kaiser-1]:.1f}%")

# ---------------------------------------------------------
# 7.3 Grafico da variancia acumulada (Scree Plot)
# ---------------------------------------------------------

print("7.3 - Gerando Scree Plot...")

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].bar(range(1, len(autovalores)+1), autovalores, color=CORES["azul"],
            edgecolor="white", alpha=0.8)
axes[0].axhline(y=1, color=CORES["vermelho"], linestyle="--", linewidth=1.5,
                label="Critério de Kaiser (autovalor = 1)")
axes[0].set_xlabel("Componente Principal")
axes[0].set_ylabel("Autovalor")
axes[0].set_title("Scree Plot")
axes[0].set_xticks(range(1, len(autovalores)+1))
axes[0].legend()

axes[1].plot(range(1, len(variancia_acum)+1), variancia_acum,
             "o-", color=CORES["azul"], linewidth=2, markersize=8)
axes[1].axhline(y=80, color=CORES["laranja"], linestyle="--",
                label="80% da variância")
axes[1].axvline(x=n_kaiser, color=CORES["vermelho"], linestyle="--",
                label=f"Kaiser: {n_kaiser} componentes ({variancia_acum[n_kaiser-1]:.1f}%)")
axes[1].set_xlabel("Número de Componentes")
axes[1].set_ylabel("Variância Acumulada (%)")
axes[1].set_title("Variância explicada acumulada")
axes[1].set_xticks(range(1, len(variancia_acum)+1))
axes[1].set_ylim(0, 105)
axes[1].legend()

plt.tight_layout()
salvar(fig, "06_scree_plot_pca.png")

# ---------------------------------------------------------
# 7.4 Aplicar PCA com n_kaiser componentes
# ---------------------------------------------------------

print(f"7.4 - Aplicando PCA com {n_kaiser} componentes...")

pca_final = PCA(n_components=n_kaiser, random_state=42)
X_pca = pca_final.fit_transform(X_scaled)

print(f"    Shape apos PCA: {X_pca.shape}")
print(f"    Variancia total explicada: {pca_final.explained_variance_ratio_.sum()*100:.1f}%")

# ---------------------------------------------------------
# 7.5 Cargas fatoriais (loadings)
# ---------------------------------------------------------

print("7.5 - Cargas fatoriais (loadings)...")

loadings = pd.DataFrame(
    pca_final.components_.T,
    columns=[f"PC{i+1}" for i in range(n_kaiser)],
    index=cols_modelo,
)
print(loadings.round(3).to_string())

fig, ax = plt.subplots(figsize=(10, 6))
im = ax.imshow(loadings.values, cmap="RdBu_r", vmin=-1, vmax=1, aspect="auto")
ax.set_xticks(range(n_kaiser))
ax.set_yticks(range(len(cols_modelo)))
ax.set_xticklabels([f"PC{i+1}" for i in range(n_kaiser)], fontsize=11)
ax.set_yticklabels(cols_modelo, fontsize=10)
for i in range(len(cols_modelo)):
    for j in range(n_kaiser):
        val = loadings.iloc[i, j]
        color = "white" if abs(val) > 0.4 else "black"
        ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=9, color=color)
fig.colorbar(im, ax=ax, shrink=0.8, label="Carga fatorial")
ax.set_title("Cargas fatoriais - PCA")
plt.tight_layout()
salvar(fig, "07_loadings_pca.png")


# ==========================================================
# SALVAR BASE COM FEATURES + COMPONENTES PCA
#
# Salva a matriz de features original (interpretavel) +
# os componentes principais (para o clustering usar).
# ==========================================================

print("\nSalvando base de features com componentes PCA...")

# Adicionar componentes PCA ao dataframe de features
for i in range(n_kaiser):
    features[f"PC{i+1}"] = X_pca[:, i]

features_save = features.reset_index()
features_save.to_csv(output_path, index=False, encoding="utf-8-sig")
print(f"    {output_path}")

# ==========================================================
# RESUMO
# ==========================================================

print(f"\n{'='*60}")
print(f"RESUMO - ENGENHARIA DE FEATURES + PCA")
print(f"{'='*60}")
print(f"    FEATURES:")
print(f"      Ativos:           {len(features)}")
print(f"      Features:         {len(cols_modelo)}")
print(f"      Escalonamento:    StandardScaler")
print(f"")
print(f"    PCA:")
print(f"      Componentes:      {n_kaiser} (criterio de Kaiser)")
print(f"      PC1:              {variancia_pct[0]:.1f}% (exposicao tecnica)")
print(f"      PC2:              {variancia_pct[1]:.1f}% (severidade relativa)")
print(f"      PC3:              {variancia_pct[2]:.1f}% (contexto organizacional)")
print(f"      Variancia total:  {variancia_acum[n_kaiser-1]:.1f}%")
print(f"")
print(f"    ARTEFATOS:")
print(f"      Base:    10. Features_PCA.csv ({len(features)} x {len(features_save.columns)})")
print(f"      Graficos: Graficos_Modelagem/06_scree_plot_pca.png")
print(f"                Graficos_Modelagem/07_loadings_pca.png")
print(f"{'='*60}")
print(f"Concluido! Proximo passo: rodar o script de Clustering.")
