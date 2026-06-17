# =========================================================
# IMPORTS
# =========================================================

import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# =========================================================
# CAMINHOS
# =========================================================

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"

input_path = os.path.join(base_path, "7. Cruzamento_CMDB_CVE.csv")
graficos_dir = os.path.join(base_path, "Graficos_EDA")

os.makedirs(graficos_dir, exist_ok=True)

# =========================================================
# CONFIGURACAO GLOBAL DOS GRAFICOS
# =========================================================

plt.rcParams.update({
    "figure.figsize"     : (10, 6),
    "figure.dpi"         : 150,
    "font.family"        : "sans-serif",
    "font.size"          : 11,
    "axes.titlesize"     : 14,
    "axes.titleweight"   : "bold",
    "axes.labelsize"     : 12,
    "axes.grid"          : True,
    "grid.alpha"         : 0.3,
    "legend.fontsize"    : 10,
})

CORES = {
    "azul": "#2F5496", "vermelho": "#C00000", "verde": "#548235",
    "amarelo": "#BF8F00", "cinza": "#808080", "laranja": "#ED7D31",
    "roxo": "#7030A0", "ciano": "#00B0F0",
}

CORES_SEVERITY = {
    "CRITICAL": "#C00000", "HIGH": "#ED7D31",
    "MEDIUM": "#BF8F00", "LOW": "#548235", "NONE": "#808080",
}

CORES_APLICAB = {
    "Aplicável": "#C00000", "Inconclusivo": "#808080",
    "Não aplicável": "#548235", "Provável — padrão afetado": "#ED7D31",
    "Sem CVE associado": "#2F5496",
}

def salvar(fig, nome):
    """Salva grafico na pasta e fecha."""
    caminho = os.path.join(graficos_dir, nome)
    fig.savefig(caminho, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"    {nome}")

# =========================================================
# LEITURA DA BASE
# =========================================================

print("Lendo base de cruzamento...")

df = pd.read_csv(input_path, low_memory=False)
df["cve_date_published"] = pd.to_datetime(df["cve_date_published"], errors="coerce")

df_com_cve = df[df["cve_aplicabilidade"] != "Sem CVE associado"].copy()
df_aplic   = df[df["cve_aplicabilidade"] == "Aplicável"].copy()

print(f"    Shape: {df.shape}")
print(f"    Registros com CVE  : {len(df_com_cve):,}")
print(f"    Registros Aplicavel: {len(df_aplic):,}")

# =========================================================
# 5.1 - CORRELACAO ENTRE DIMENSOES DO CVSS
#
# Justifica a aplicacao de PCA.
# A alta colinearidade entre confidencialidade e integridade
# (r=0,98) demonstra redundancia dimensional que precisa
# ser tratada antes do clustering.
# =========================================================

print("\n5.1 - Correlacao entre dimensoes do CVSS...")

mapa_encode = {
    "cve_attack_vector"          : {"NETWORK": 4, "ADJACENT_NETWORK": 3, "ADJACENT": 3, "LOCAL": 2, "PHYSICAL": 1},
    "cve_attack_complexity"      : {"LOW": 2, "HIGH": 1},
    "cve_privileges_required"    : {"NONE": 3, "LOW": 2, "HIGH": 1},
    "cve_confidentiality_impact" : {"HIGH": 3, "LOW": 2, "NONE": 1},
    "cve_integrity_impact"       : {"HIGH": 3, "LOW": 2, "NONE": 1},
    "cve_availability_impact"    : {"HIGH": 3, "LOW": 2, "NONE": 1},
}

df_corr = df_aplic[["cve_cvss_score"] + list(mapa_encode.keys())].copy()
for col, mapa in mapa_encode.items():
    df_corr[col] = df_corr[col].map(mapa)

renomear = {
    "cve_cvss_score": "CVSS Score", "cve_attack_vector": "Attack Vector",
    "cve_attack_complexity": "Attack Complexity", "cve_privileges_required": "Privileges Req.",
    "cve_confidentiality_impact": "Confidentiality", "cve_integrity_impact": "Integrity",
    "cve_availability_impact": "Availability",
}
df_corr = df_corr.rename(columns=renomear)
corr = df_corr.corr()

fig, ax = plt.subplots(figsize=(9, 7))
im = ax.imshow(corr.values, cmap="RdYlBu_r", vmin=-1, vmax=1, aspect="auto")
ax.set_xticks(range(len(corr.columns)))
ax.set_yticks(range(len(corr.columns)))
ax.set_xticklabels(corr.columns, rotation=45, ha="right", fontsize=10)
ax.set_yticklabels(corr.columns, fontsize=10)
for i in range(len(corr)):
    for j in range(len(corr)):
        val = corr.iloc[i, j]
        color = "white" if abs(val) > 0.5 else "black"
        ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=9, color=color)
fig.colorbar(im, ax=ax, shrink=0.8, label="Correlação")
ax.set_title("Correlação entre dimensões do CVSS")
plt.tight_layout()
salvar(fig, "01_correlacao_cvss.png")

print("\n    Matriz de correlacao (valores para conferencia):")
print(corr.round(2).to_string())
print(f"\n    Valores calculados:")
print(f"    CVSS Score x Confidentiality : {corr.loc['CVSS Score','Confidentiality']:.2f}")
print(f"    CVSS Score x Integrity       : {corr.loc['CVSS Score','Integrity']:.2f}")
print(f"    CVSS Score x Availability    : {corr.loc['CVSS Score','Availability']:.2f}")
print(f"    Confidentiality x Integrity  : {corr.loc['Confidentiality','Integrity']:.2f}")
print(f"    Confidentiality x Availability: {corr.loc['Confidentiality','Availability']:.2f}")
print(f"    Attack Vector x Confidential.: {corr.loc['Attack Vector','Confidentiality']:.2f}")
print(f"    Attack Vector x Integrity    : {corr.loc['Attack Vector','Integrity']:.2f}")

# =========================================================
# 5.2 - CVEs POR ATIVO
#
# Mostra a variavel central que o clustering vai segmentar.
# A distribuicao de exposicao por ativo (de 1 a 1.068 CVEs)
# evidencia a necessidade de segmentacao.
# =========================================================

print("\n5.2 - CVEs por ativo (Aplicaveis)...")

cves_por_ativo = (
    df_aplic
    .groupby(["asset_id", "hostname", "classe", "criticidade"])["cve_id"]
    .nunique()
    .reset_index(name="qtd_cves")
    .sort_values("qtd_cves", ascending=False)
)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

axes[0].hist(cves_por_ativo["qtd_cves"], bins=30, color=CORES["azul"],
             edgecolor="white", alpha=0.85)
axes[0].set_xlabel("Qtd de CVEs aplicáveis por ativo")
axes[0].set_ylabel("Frequência (nº de ativos)")
axes[0].set_title("Distribuição de CVEs por ativo")
axes[0].axvline(cves_por_ativo["qtd_cves"].mean(), color=CORES["vermelho"],
                linestyle="--", label=f"Média: {cves_por_ativo['qtd_cves'].mean():.0f}")
axes[0].axvline(cves_por_ativo["qtd_cves"].median(), color=CORES["laranja"],
                linestyle="--", label=f"Mediana: {cves_por_ativo['qtd_cves'].median():.0f}")
axes[0].legend()

top15 = cves_por_ativo.head(15)
cores_top = [CORES["vermelho"] if c == "CRÍTICA" else
             CORES["laranja"] if c == "ALTA" else
             CORES["amarelo"] if c == "MÉDIA" else
             CORES["verde"] for c in top15["criticidade"]]
axes[1].barh(top15["hostname"][::-1], top15["qtd_cves"][::-1], color=cores_top[::-1])
axes[1].set_xlabel("Qtd CVEs aplicáveis")
axes[1].set_title("Top 15 ativos mais expostos")
plt.tight_layout()
salvar(fig, "02_cves_por_ativo.png")

print(f"    Media: {cves_por_ativo['qtd_cves'].mean():.0f} | "
      f"Mediana: {cves_por_ativo['qtd_cves'].median():.0f} | "
      f"Max: {cves_por_ativo['qtd_cves'].max()} | "
      f"Min: {cves_por_ativo['qtd_cves'].min()}")

# =========================================================
# 5.3 - DISTRIBUICAO DE APLICABILIDADE
#
# Valida toda a pipeline de cruzamento (etapas 2 a 4).
# Mostra que 47% dos registros foram confirmados como
# aplicaveis pela comparacao de versao.
# =========================================================

print("\n5.3 - Distribuicao de aplicabilidade...")

contagem = df["cve_aplicabilidade"].value_counts()
cores_1 = [CORES_APLICAB.get(x, "#808080") for x in contagem.index]

fig, ax = plt.subplots()
bars = ax.barh(contagem.index[::-1], contagem.values[::-1], color=cores_1[::-1])
ax.set_xlabel("Quantidade de registros")
ax.set_title("Distribuição de aplicabilidade (ativo × CVE)")
for bar in bars:
    w = bar.get_width()
    ax.text(w + 1000, bar.get_y() + bar.get_height()/2,
            f"{w:,.0f}", va="center", fontsize=10)
ax.set_xlim(0, contagem.max() * 1.15)
salvar(fig, "03_distribuicao_aplicabilidade.png")

# =========================================================
# 5.4 - CRITICIDADE DO ATIVO x APLICABILIDADE
#
# Conecta risco tecnico (CVE) com risco de negocio
# (criticidade do ativo). E a tese central do TCC:
# combinar as duas dimensoes para segmentacao.
# =========================================================

print("\n5.4 - Criticidade do ativo x Aplicabilidade...")

cross_crit = pd.crosstab(
    df_com_cve["criticidade"],
    df_com_cve["cve_aplicabilidade"],
)
crit_order = ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA"]
aplic_order = ["Aplicável", "Provável — padrão afetado", "Inconclusivo", "Não aplicável"]
cross_crit = cross_crit.reindex(index=crit_order, columns=aplic_order).fillna(0)

fig, ax = plt.subplots(figsize=(10, 6))
cross_crit.plot(kind="bar", ax=ax,
                color=[CORES_APLICAB[c] for c in aplic_order])
ax.set_ylabel("Quantidade de registros")
ax.set_title("Criticidade do ativo × Classificação de aplicabilidade")
ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
ax.legend(title="Aplicabilidade", bbox_to_anchor=(1.02, 1))
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
plt.tight_layout()
salvar(fig, "04_criticidade_x_aplicabilidade.png")

# =========================================================
# 5.5 - SEVERIDADE CVSS
#
# Caracteriza o perfil de risco do ambiente.
# A predominancia de HIGH (63%) sustenta a argumentacao de
# que priorizacao precisa ir alem da severidade isolada.
# =========================================================

print("\n5.5 - Severidade CVSS (Aplicaveis)...")

sev = df_aplic["cve_cvss_severity"].value_counts(dropna=False)
sev.index = sev.index.where(sev.index.notna(), "Sem classificação")
ordem_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "Sem classificação"]
sev = sev.reindex([x for x in ordem_sev if x in sev.index])
cores_3 = [CORES_SEVERITY.get(x, "#808080") for x in sev.index]

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

axes[0].bar(sev.index, sev.values, color=cores_3)
axes[0].set_ylabel("Quantidade")
axes[0].set_title("Severidade CVSS")
axes[0].tick_params(axis="x", rotation=30)
for i, v in enumerate(sev.values):
    axes[0].text(i, v + 500, f"{v:,}", ha="center", fontsize=9)

sev_pizza = sev[sev.index != "Sem classificação"]
cores_pizza = [CORES_SEVERITY.get(x, "#808080") for x in sev_pizza.index]
axes[1].pie(sev_pizza.values, labels=sev_pizza.index, colors=cores_pizza,
            autopct="%1.1f%%", startangle=90, textprops={"fontsize": 10})
axes[1].set_title("Proporção (apenas classificados)")
plt.tight_layout()
salvar(fig, "05_severidade_cvss.png")

# =========================================================
# RESUMO GERAL
# =========================================================

scores = df_aplic["cve_cvss_score"].dropna()

print(f"\n{'='*60}")
print(f"RESUMO DA ANALISE EXPLORATORIA")
print(f"{'='*60}")
print(f"    Base analisada            : {len(df):,} registros x {len(df.columns)} colunas")
print(f"    Ativos unicos             : {df['asset_id'].nunique()}")
print(f"    CVEs unicas               : {df['cve_id'].nunique():,}")
print(f"")
print(f"    Aplicaveis                : {len(df_aplic):,} ({len(df_aplic)/len(df_com_cve)*100:.1f}%)")
print(f"    Nao aplicaveis            : {(df['cve_aplicabilidade']=='Não aplicável').sum():,}")
print(f"    Inconclusivos             : {(df['cve_aplicabilidade']=='Inconclusivo').sum():,}")
print(f"")
print(f"    CVSS Score medio (aplic.) : {scores.mean():.2f}")
print(f"    CVSS Score mediana        : {scores.median():.1f}")
print(f"    CVSS Score desvio-padrao  : {scores.std():.2f}")
print(f"    % CRITICAL+HIGH (aplic.) : {((df_aplic['cve_cvss_severity'].isin(['CRITICAL','HIGH'])).sum()/len(df_aplic)*100):.1f}%")
print(f"")
print(f"    Graficos salvos em        : {graficos_dir}")
print(f"    Total de graficos         : 5 arquivos PNG")
print(f"{'='*60}")
print(f"EDA concluida!")
