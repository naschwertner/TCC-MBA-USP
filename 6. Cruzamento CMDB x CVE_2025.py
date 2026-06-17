# =========================================================
# 📚 IMPORTS
# =========================================================

import os
import re
import pandas as pd

# =========================================================
# 📂 CAMINHOS
# =========================================================

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"

cmdb_path   = os.path.join(base_path, "5. CMDB_Simulado.csv")
cve_path    = os.path.join(base_path, "4. CVE_2025_Empilhado_Normalizado.csv")
output_path = os.path.join(base_path, "7. Cruzamento_CMDB_CVE.csv")

# =========================================================
# 📥 LEITURA DAS BASES
# =========================================================

print("📥 Lendo CMDB...")
cmdb = pd.read_csv(cmdb_path)
print(f"   {len(cmdb)} ativos, {len(cmdb.columns)} colunas")

print("\n📥 Lendo base CVE...")
cve = pd.read_csv(cve_path, low_memory=False)
print(f"   {len(cve):,} linhas, {len(cve.columns)} colunas")

# =========================================================
# 🧹 DEDUPLICAR CVE POR (cve_id, vendor, product)
# =========================================================

print("\n🧹 Deduplicando base CVE por (cve_id, vendor, product)...")

cve_unique = cve.drop_duplicates(
    subset=["cve_id", "vendor", "product"],
    keep="first"
).reset_index(drop=True)

print(f"   Antes : {len(cve):,} linhas")
print(f"   Depois: {len(cve_unique):,} linhas")

# =========================================================
# 🔗 CRUZAMENTO 1 — POR SISTEMA OPERACIONAL
# Chave composta: so_vendor + so_produto ↔ vendor + product
# =========================================================

print("\n🔗 Cruzamento 1 — Por SISTEMA OPERACIONAL...")

merge_so = cmdb.merge(
    cve_unique,
    left_on  = ["so_vendor", "so_produto"],
    right_on = ["vendor", "product"],
    how      = "inner",
)
merge_so["origem_match"] = "Sistema Operacional"
print(f"   Linhas geradas: {len(merge_so):,}")

# =========================================================
# 🔗 CRUZAMENTO 2 — POR APLICAÇÃO INSTALADA
# Chave composta: app_vendor + app_produto ↔ vendor + product
# =========================================================

print("\n🔗 Cruzamento 2 — Por APLICAÇÃO INSTALADA...")

cmdb_com_app = cmdb[cmdb["app_vendor"].notna()].copy()

merge_app = cmdb_com_app.merge(
    cve_unique,
    left_on  = ["app_vendor", "app_produto"],
    right_on = ["vendor", "product"],
    how      = "inner",
)
merge_app["origem_match"] = "Aplicação Instalada"
print(f"   Linhas geradas: {len(merge_app):,}")

# =========================================================
# 🔗 EMPILHAR CRUZAMENTOS 1 E 2
# =========================================================

print("\n🔗 Empilhando resultados...")
df = pd.concat([merge_so, merge_app], ignore_index=True)
df = df.drop(columns=["vendor", "product"])

# =========================================================
# 🏷️ RENOMEAR COLUNAS DA CVE COM PREFIXO 'cve_'
# =========================================================

mapa_cve_cols = {
    "date_published"         : "cve_date_published",
    "date_updated"           : "cve_date_updated",
    "titulo"                 : "cve_titulo",
    "descricao"              : "cve_descricao",
    "version_affected"       : "cve_version_affected",
    "version_less_than"      : "cve_version_less_than",
    "version_affected_norm"  : "cve_version_affected_norm",
    "version_less_than_norm" : "cve_version_less_than_norm",
    "version_limite_tipo"    : "cve_version_limite_tipo",
    "version_comparavel"     : "cve_version_comparavel",
    "default_status"         : "cve_default_status",
    "platforms"              : "cve_platforms",
    "cpes"                   : "cve_cpes",
    "cvss_version"           : "cve_cvss_version",
    "cvss_score"             : "cve_cvss_score",
    "cvss_severity"          : "cve_cvss_severity",
    "cvss_vector_string"     : "cve_cvss_vector_string",
    "attack_vector"          : "cve_attack_vector",
    "attack_complexity"      : "cve_attack_complexity",
    "privileges_required"    : "cve_privileges_required",
    "user_interaction"       : "cve_user_interaction",
    "scope"                  : "cve_scope",
    "confidentiality_impact" : "cve_confidentiality_impact",
    "integrity_impact"       : "cve_integrity_impact",
    "availability_impact"    : "cve_availability_impact",
    "cwe_id"                 : "cve_cwe_id",
    "cwe_descricao"          : "cve_cwe_descricao",
}
df = df.rename(columns=mapa_cve_cols)

# =========================================================
# 🔗 CRUZAMENTO 3 — POR VERSÃO (normalizada)
#
# Usa as colunas normalizadas para comparar o intervalo:
#   CMDB: so_versao_norm / app_versao_norm
#   CVE:  cve_version_affected_norm / cve_version_less_than_norm
#
# Considera cve_version_limite_tipo:
#   EXCLUSIVO (lessThan)       → ativo < limite
#   INCLUSIVO (lessThanOrEqual)→ ativo <= limite
# =========================================================

print("\n🔗 Cruzamento 3 — Por VERSÃO (normalizada)...")


def parse_tupla(versao_norm):
    """Converte string normalizada '10.0.20348.0' em tupla (10, 0, 20348, 0)."""
    if not isinstance(versao_norm, str) or versao_norm.strip() == "":
        return None
    try:
        return tuple(int(n) for n in versao_norm.split("."))
    except ValueError:
        return None


def classificar_versao(row):
    """
    Cruzamento 3: compara a versão normalizada do ativo
    com o intervalo normalizado da CVE.

    Retorna:
      'Aplicável'                 — versão do ativo dentro do intervalo vulnerável
      'Não aplicável'             — versão do ativo fora do intervalo
      'Provável — padrão afetado' — default_status=AFFECTED mas comparação inconclusiva
      'Inconclusivo'              — não foi possível comparar
    """

    # ── Escolher versão normalizada do ativo ────────────────
    if row["origem_match"] == "Aplicação Instalada":
        v_ativo_str = row.get("app_versao_norm")
    else:
        v_ativo_str = row.get("so_versao_norm")

    v_ini_str     = row.get("cve_version_affected_norm")
    v_fim_str     = row.get("cve_version_less_than_norm")
    limite_tipo   = row.get("cve_version_limite_tipo")
    default_status = row.get("cve_default_status")
    comparavel_cve = row.get("cve_version_comparavel")

    # Normalizar NaN → None
    v_ativo_str    = None if pd.isna(v_ativo_str)    else str(v_ativo_str)
    v_ini_str      = None if pd.isna(v_ini_str)      else str(v_ini_str)
    v_fim_str      = None if pd.isna(v_fim_str)      else str(v_fim_str)
    limite_tipo    = None if pd.isna(limite_tipo)     else str(limite_tipo)
    default_status = None if pd.isna(default_status)  else str(default_status)

    # ── CVE marcada como não comparável no ETL ──────────────
    if comparavel_cve is False or (isinstance(comparavel_cve, float) and comparavel_cve == 0):
        if default_status == "AFFECTED":
            return "Provável — padrão afetado"
        return "Inconclusivo"

    # ── Sem versão normalizada no ativo ─────────────────────
    t_ativo = parse_tupla(v_ativo_str)
    if t_ativo is None:
        if default_status == "AFFECTED":
            return "Provável — padrão afetado"
        return "Inconclusivo"

    # ── Parsear limites da CVE ──────────────────────────────
    t_ini = parse_tupla(v_ini_str)
    t_fim = parse_tupla(v_fim_str)

    # Zero como limite inferior = sem piso (afeta desde a primeira versão)
    sem_piso = (
        t_ini is None
        or (v_ini_str is not None and v_ini_str.strip() == "0")
    )

    # ── Verificar piso ──────────────────────────────────────
    if not sem_piso and t_ini is not None:
        # Tamanhos muito diferentes → não dá para comparar
        if abs(len(t_ativo) - len(t_ini)) > 2:
            if default_status == "AFFECTED":
                return "Provável — padrão afetado"
            return "Inconclusivo"
        if t_ativo < t_ini:
            return "Não aplicável"

    # ── Verificar teto ──────────────────────────────────────
    if t_fim is None:
        # Sem teto definido
        if sem_piso:
            # Sem piso e sem teto → indeterminado
            if default_status == "AFFECTED":
                return "Provável — padrão afetado"
            elif default_status == "UNAFFECTED":
                return "Não aplicável"
            return "Inconclusivo"
        else:
            # Acima do piso, sem teto → provável
            return "Aplicável"

    # Tamanhos muito diferentes no teto → inconclusivo
    if abs(len(t_ativo) - len(t_fim)) > 2:
        if default_status == "AFFECTED":
            return "Provável — padrão afetado"
        return "Inconclusivo"

    # ── Comparar com teto considerando tipo de limite ───────
    if limite_tipo == "INCLUSIVO":
        # lessThanOrEqual: ativo <= limite → vulnerável
        if t_ativo <= t_fim:
            return "Aplicável"
        else:
            return "Não aplicável"
    else:
        # EXCLUSIVO (lessThan) ou None: ativo < limite → vulnerável
        if t_ativo < t_fim:
            return "Aplicável"
        else:
            return "Não aplicável"


print("   Classificando cada registro...")

df["cve_aplicabilidade"] = df.apply(classificar_versao, axis=1)

print(f"\n📌 Distribuição de aplicabilidade (Cruzamento 3 — Versão):")
print(df["cve_aplicabilidade"].value_counts().to_string())

# =========================================================
# 📐 REORDENAR — CMDB à esquerda, CVE à direita
# =========================================================

colunas_cmdb = list(cmdb.columns)
colunas_cve  = ["cve_id"] + [c for c in df.columns
                              if c.startswith("cve_") and c != "cve_id"]
colunas_meta = ["origem_match"]

ordem_final = colunas_cmdb + colunas_meta + colunas_cve

df = df[ordem_final]

# =========================================================
# 📊 ORDENAR — por asset_id e severidade
# =========================================================

severidade_ordem = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "NONE": 5}

df["_ord_sev"] = (
    df["cve_cvss_severity"]
    .map(severidade_ordem)
    .fillna(99)
)

df = df.sort_values(
    by=["asset_id", "_ord_sev", "cve_id"],
    ascending=[True, True, True],
).drop(columns=["_ord_sev"]).reset_index(drop=True)

# =========================================================
# 📊 IDENTIFICAR ATIVOS SEM CVE ASSOCIADO
# =========================================================

ativos_com_cve = set(df["asset_id"].unique())
cmdb_sem_cve   = cmdb[~cmdb["asset_id"].isin(ativos_com_cve)].copy()

print(f"\n📊 Ativos com CVE associado : {len(ativos_com_cve)}")
print(f"📊 Ativos sem CVE associado : {len(cmdb_sem_cve)}")

if len(cmdb_sem_cve) > 0:
    cmdb_sem_cve["origem_match"]       = "Sem CVE associado"
    cmdb_sem_cve["cve_aplicabilidade"] = "Sem CVE associado"

    for col in colunas_cve:
        if col not in cmdb_sem_cve.columns:
            cmdb_sem_cve[col] = None

    cmdb_sem_cve = cmdb_sem_cve[ordem_final]

    df = pd.concat([df, cmdb_sem_cve], ignore_index=True)

# =========================================================
# 📊 ESTATÍSTICAS FINAIS
# =========================================================

print(f"\n{'='*60}")
print(f"📊 Shape final: {df.shape}")

print(f"\n📌 Distribuição por origem_match:")
print(df["origem_match"].value_counts().to_string())

print(f"\n📌 Distribuição por cve_aplicabilidade:")
print(df["cve_aplicabilidade"].value_counts().to_string())

print(f"\n📌 Aplicável × Severidade:")
aplicaveis = df[df["cve_aplicabilidade"] == "Aplicável"]
print(aplicaveis["cve_cvss_severity"].value_counts(dropna=False).to_string())

print(f"\n📌 Não aplicável × Origem:")
nao_aplic = df[df["cve_aplicabilidade"] == "Não aplicável"]
print(nao_aplic["origem_match"].value_counts().to_string())

print(f"\n📌 Top 10 ativos com mais CVEs APLICÁVEIS:")
top = (
    aplicaveis
    .groupby(["asset_id", "hostname"])
    .size()
    .reset_index(name="qtd_cves_aplicaveis")
    .nlargest(10, "qtd_cves_aplicaveis")
)
print(top.to_string(index=False))

print(f"\n📌 Ativos sem CVE:")
if len(cmdb_sem_cve) > 0:
    print(cmdb_sem_cve[["asset_id", "hostname", "so_produto", "app_produto"]].to_string(index=False))
else:
    print("   Nenhum.")

# =========================================================
# 💾 SALVAR
# =========================================================

if os.path.exists(output_path):
    try:
        os.remove(output_path)
    except PermissionError:
        print("\n⚠️  Feche o arquivo no Excel antes de rodar novamente.")
        raise

print(f"\n💾 Salvando em:\n   {output_path}")
df.to_csv(output_path, index=False, encoding="utf-8-sig")
print(f"\n✅ Concluído — {len(df):,} linhas salvas.")