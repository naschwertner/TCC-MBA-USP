# =========================================================
# 📚 IMPORTS
# =========================================================

import os
import ast
import re
import pandas as pd

# =========================================================
# 📂 CAMINHOS
# =========================================================

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"

input_path  = os.path.join(base_path, "2. CVE_2025_Empilhado.csv")
output_path = os.path.join(base_path, "4. CVE_2025_Empilhado_Normalizado.csv")

# =========================================================
# 📥 LEITURA DA BASE
# =========================================================

print("📥 Lendo base CVE...")

df = pd.read_csv(input_path, low_memory=False)

print(f"   Total de registros lidos : {len(df)}")
print(f"   Total de colunas         : {len(df.columns)}")

# =========================================================
# 🔍 FILTRO: APENAS PUBLISHED
# =========================================================

df = df[df["cveMetadata.state"] == "PUBLISHED"].copy()
df = df.reset_index(drop=True)

print(f"\n✅ Registros PUBLISHED : {len(df)}")

# =========================================================
# 🧹 SELECIONAR APENAS COLUNAS RELEVANTES
# =========================================================

colunas_relevantes = [
    "cveMetadata.cveId",
    "cveMetadata.datePublished",
    "cveMetadata.dateUpdated",
    "containers.cna.affected",
    "containers.cna.metrics",
    "containers.cna.problemTypes",
    "containers.cna.descriptions",
    "containers.cna.title",
]

df = df[colunas_relevantes].copy()

print(f"\n📌 Colunas selecionadas   : {len(df.columns)}")

# =========================================================
# 🔧 FUNÇÕES AUXILIARES
# =========================================================

def limpar_texto(texto):
    """Remove quebras de linha e espaços extras de texto livre."""
    if not isinstance(texto, str):
        return texto
    texto = re.sub(r"[\r\n]+", " ", texto)
    texto = re.sub(r"  +", " ", texto)
    return texto.strip()


def lista_para_str(lst):
    """Converte lista Python em string separada por ' | '."""
    if not lst or not isinstance(lst, list):
        return None
    itens = [str(x).strip() for x in lst if x]
    return " | ".join(itens) if itens else None


# =========================================================
# 🔧 FUNÇÃO: NORMALIZAR VERSÃO
# =========================================================

# Regex para detectar hashes de commit git (40+ hex chars)
_RE_GIT_HASH = re.compile(r"^[0-9a-f]{30,}$")

# Regex para detectar versões RPM (contêm padrão como :2.06-104.el9_6)
_RE_RPM = re.compile(r"\d+:\d+\.\d+.*\.el\d")

# Regex para detectar módulos Red Hat (IDs longos como 8100020251120003312.489197e6)
_RE_RHEL_MODULE = re.compile(r"^\d{15,}")

# Prefixos conhecidos que devem ser removidos antes da extração
_PREFIXOS_REMOVER = [
    "Oracle Java SE:",
    "Oracle GraalVM for JDK:",
    "Oracle GraalVM Enterprise Edition:",
    "ID",           # InDesign: "ID19.5.1" → "19.5.1"
    "FP",           # Adobe AEM: "FP11.3" → "11.3"
]


def normalizar_versao(versao_str):
    """
    Normaliza uma string de versão para formato comparável.

    Retorna uma tupla (versao_normalizada, comparavel):
      - versao_normalizada: string com números separados por '.'
        Ex: '10.0.20348.0', '8.451', '750'
      - comparavel: bool indicando se a comparação numérica é confiável

    Casos tratados:
      - Semântico: '10.0.20348.0' → ('10.0.20348.0', True)
      - Java u-notation: '8u451' → ('8.0.451', True)
      - SAP: 'SAP_BASIS 750' → ('750', True)
      - Prefixado: 'Oracle Java SE:11.0.25' → ('11.0.25', True)
      - InDesign: 'ID19.5.1' → ('19.5.1', True)
      - Zero/asterisco: '0' → ('0', True), '*' → (None, False)
      - Hash git: 'a1b2c3...' → (None, False)
      - RPM: '1:2.06-104.el9_6' → (None, False)
      - RHEL module: '8100020251120003312.489197e6' → (None, False)
      - Junos: '22.4R3-S6' → ('22.4.3.6', True) — extrai apenas números
    """
    if not isinstance(versao_str, str):
        return (None, False)

    v = versao_str.strip()

    if v == "" or v == "*":
        return (None, False)

    # Zero puro → válido (início do intervalo)
    if v in ("0", "0.0", "0.0.0"):
        return ("0", True)

    # Detectar hashes git → incomparável
    if _RE_GIT_HASH.match(v):
        return (None, False)

    # Detectar versões RPM → incomparável
    if _RE_RPM.search(v):
        return (None, False)

    # Detectar módulos Red Hat → incomparável
    if _RE_RHEL_MODULE.match(v):
        return (None, False)

    # Remover prefixos conhecidos
    for prefixo in _PREFIXOS_REMOVER:
        if v.startswith(prefixo):
            v = v[len(prefixo):].strip()
            break

    # Tratar Java u-notation: '8u451' → '8.0.451'
    match_java_u = re.match(r"^(\d+)u(\d+)(.*)$", v)
    if match_java_u:
        major = match_java_u.group(1)
        update = match_java_u.group(2)
        return (f"{major}.0.{update}", True)

    # Tratar SAP: 'SAP_BASIS 750' → '750'
    match_sap = re.match(r"SAP_\w+\s+(\d+)", v)
    if match_sap:
        return (match_sap.group(1), True)

    # Extrair todos os números e juntar com ponto
    numeros = re.findall(r"\d+", v)

    if not numeros:
        return (None, False)

    normalizado = ".".join(numeros)
    return (normalizado, True)


# =========================================================
# 🔧 FUNÇÃO: EXTRAIR AFFECTED (com normalização)
# =========================================================

def extrair_affected(val):
    """
    Extrai de containers.cna.affected:
      - vendor, product
      - version_affected / version_less_than (originais)
      - version_affected_norm / version_less_than_norm (normalizadas)
      - version_limite_tipo: EXCLUSIVO (lessThan) ou INCLUSIVO (lessThanOrEqual)
      - version_comparavel: True/False
      - default_status, platforms, cpes
    """
    vazio = [{
        "vendor"                 : None,
        "product"                : None,
        "version_affected"       : None,
        "version_less_than"      : None,
        "version_affected_norm"  : None,
        "version_less_than_norm" : None,
        "version_limite_tipo"    : None,
        "version_comparavel"     : False,
        "default_status"         : None,
        "platforms"              : None,
        "cpes"                   : None,
    }]

    if pd.isnull(val):
        return vazio

    try:
        lst = ast.literal_eval(val)
    except Exception:
        return vazio

    rows = []

    for item in lst:
        vendor         = item.get("vendor")
        product        = item.get("product")
        default_status = item.get("defaultStatus")
        versions       = item.get("versions") or []

        platforms_str = lista_para_str(item.get("platforms"))
        cpes_str      = lista_para_str(item.get("cpes"))

        if not versions:
            rows.append({
                "vendor"                 : vendor,
                "product"                : product,
                "version_affected"       : None,
                "version_less_than"      : None,
                "version_affected_norm"  : None,
                "version_less_than_norm" : None,
                "version_limite_tipo"    : None,
                "version_comparavel"     : False,
                "default_status"         : default_status,
                "platforms"              : platforms_str,
                "cpes"                   : cpes_str,
            })
            continue

        for v in versions:
            status = v.get("status", default_status)
            if status not in ("affected", None) and default_status != "affected":
                continue

            # ── Separar lessThan de lessThanOrEqual ─────────
            raw_lt  = v.get("lessThan")
            raw_lte = v.get("lessThanOrEqual")
            raw_va  = v.get("version")

            if raw_lt is not None:
                less_than_original = raw_lt
                limite_tipo = "EXCLUSIVO"      # < (não inclui)
            elif raw_lte is not None:
                less_than_original = raw_lte
                limite_tipo = "INCLUSIVO"      # <= (inclui)
            else:
                less_than_original = None
                limite_tipo = None

            # ── Normalizar versões ─────────────────────────
            va_norm, va_ok  = normalizar_versao(raw_va)
            lt_norm, lt_ok  = normalizar_versao(less_than_original)

            # Consideramos comparável se pelo menos um dos lados
            # tem versão normalizada
            comparavel = va_ok or lt_ok

            rows.append({
                "vendor"                 : vendor,
                "product"                : product,
                "version_affected"       : raw_va,
                "version_less_than"      : less_than_original,
                "version_affected_norm"  : va_norm,
                "version_less_than_norm" : lt_norm,
                "version_limite_tipo"    : limite_tipo,
                "version_comparavel"     : comparavel,
                "default_status"         : default_status,
                "platforms"              : platforms_str,
                "cpes"                   : cpes_str,
            })

    return rows if rows else vazio


# =========================================================
# 🔧 FUNÇÃO: EXTRAIR CVSS
# =========================================================

def extrair_cvss(val):
    """Extrai campos CVSS — prioridade: cvssV3_1 > cvssV3_0 > cvssV4_0."""
    vazio = {
        "cvss_version"           : None,
        "cvss_score"             : None,
        "cvss_severity"          : None,
        "cvss_vector_string"     : None,
        "attack_vector"          : None,
        "attack_complexity"      : None,
        "privileges_required"    : None,
        "user_interaction"       : None,
        "scope"                  : None,
        "confidentiality_impact" : None,
        "integrity_impact"       : None,
        "availability_impact"    : None,
    }

    if pd.isnull(val):
        return vazio

    try:
        lst = ast.literal_eval(val)
    except Exception:
        return vazio

    for item in lst:
        for chave in ["cvssV3_1", "cvssV3_0", "cvssV4_0"]:
            if chave in item:
                c = item[chave]
                return {
                    "cvss_version"           : c.get("version"),
                    "cvss_score"             : c.get("baseScore"),
                    "cvss_severity"          : c.get("baseSeverity"),
                    "cvss_vector_string"     : c.get("vectorString"),
                    "attack_vector"          : c.get("attackVector"),
                    "attack_complexity"      : c.get("attackComplexity"),
                    "privileges_required"    : c.get("privilegesRequired"),
                    "user_interaction"       : c.get("userInteraction"),
                    "scope"                  : c.get("scope"),
                    "confidentiality_impact" : c.get("confidentialityImpact"),
                    "integrity_impact"       : c.get("integrityImpact"),
                    "availability_impact"    : c.get("availabilityImpact"),
                }

    return vazio


# =========================================================
# 🔧 FUNÇÃO: EXTRAIR CWE
# =========================================================

def extrair_cwe(val):
    """Extrai CWE ID e descrição."""
    if pd.isnull(val):
        return {"cwe_id": None, "cwe_descricao": None}

    try:
        lst = ast.literal_eval(val)
    except Exception:
        return {"cwe_id": None, "cwe_descricao": None}

    for item in lst:
        for desc in item.get("descriptions", []):
            if desc.get("type") == "CWE":
                return {
                    "cwe_id"       : desc.get("cweId"),
                    "cwe_descricao": desc.get("description"),
                }

    return {"cwe_id": None, "cwe_descricao": None}


# =========================================================
# 🔧 FUNÇÃO: EXTRAIR DESCRIÇÃO
# =========================================================

def extrair_descricao(val):
    """Extrai o texto da descrição em inglês."""
    if pd.isnull(val):
        return None

    try:
        lst = ast.literal_eval(val)
    except Exception:
        return None

    for item in lst:
        if item.get("lang", "").startswith("en"):
            return item.get("value")

    if lst:
        return lst[0].get("value")

    return None


# =========================================================
# 🔧 EXTRAIR DESCRIÇÃO (antes da explosão)
# =========================================================

print("\n🔧 Extraindo descrição...")

df["descricao"] = df["containers.cna.descriptions"].apply(extrair_descricao)

# =========================================================
# 💥 EXPLODIR containers.cna.affected
# =========================================================

print("💥 Explodindo coluna affected (produto × versão)...")

df["_affected_rows"] = df["containers.cna.affected"].apply(extrair_affected)

df_exploded = df.explode("_affected_rows").reset_index(drop=True)

affected_df = pd.json_normalize(df_exploded["_affected_rows"])

# =========================================================
# 🔧 EXTRAIR CVSS E CWE APÓS A EXPLOSÃO
# =========================================================

print("🔧 Extraindo campos CVSS...")

cvss_df = df_exploded["containers.cna.metrics"].apply(
    lambda x: pd.Series(extrair_cvss(x))
)

print("🔧 Extraindo CWE...")

cwe_df = df_exploded["containers.cna.problemTypes"].apply(
    lambda x: pd.Series(extrair_cwe(x))
)

# =========================================================
# 🔗 MONTAR BASE FINAL
# =========================================================

print("🔗 Montando base final...")

df_final = pd.concat([
    df_exploded[[
        "cveMetadata.cveId",
        "cveMetadata.datePublished",
        "cveMetadata.dateUpdated",
        "containers.cna.title",
        "descricao",
    ]].reset_index(drop=True),
    affected_df.reset_index(drop=True),
    cvss_df.reset_index(drop=True),
    cwe_df.reset_index(drop=True),
], axis=1)

# =========================================================
# 🏷️ RENOMEAR COLUNAS
# =========================================================

df_final = df_final.rename(columns={
    "cveMetadata.cveId"         : "cve_id",
    "cveMetadata.datePublished" : "date_published",
    "cveMetadata.dateUpdated"   : "date_updated",
    "containers.cna.title"      : "titulo",
})

# =========================================================
# 🗓️ CONVERTER DATAS
# =========================================================

df_final["date_published"] = pd.to_datetime(
    df_final["date_published"], errors="coerce", utc=True
).dt.date

df_final["date_updated"] = pd.to_datetime(
    df_final["date_updated"], errors="coerce", utc=True
).dt.date

# =========================================================
# 🔠 PADRONIZAR STRINGS EM MAIÚSCULO
# =========================================================

cols_upper = [
    "cvss_severity", "attack_vector", "attack_complexity",
    "privileges_required", "user_interaction", "scope",
    "confidentiality_impact", "integrity_impact", "availability_impact",
    "default_status", "version_limite_tipo",
]

for col in cols_upper:
    if col in df_final.columns:
        df_final[col] = df_final[col].astype(str).where(
            df_final[col].notna(), None
        )
        df_final[col] = df_final[col].str.upper().replace("NONE", None)

# =========================================================
# 🧹 LIMPAR QUEBRAS DE LINHA EM CAMPOS DE TEXTO LIVRE
# =========================================================

print("🧹 Limpando quebras de linha em campos de texto...")

cols_texto = [
    "titulo", "descricao", "cwe_descricao",
    "version_affected", "version_less_than", "platforms", "cpes",
]

for col in cols_texto:
    if col in df_final.columns:
        df_final[col] = df_final[col].apply(limpar_texto)

# =========================================================
# 📊 VALIDAR NORMALIZAÇÃO DE VERSÕES
# =========================================================

total = len(df_final)
comparaveis = df_final["version_comparavel"].sum()
nao_comp    = total - comparaveis

print(f"\n📊 Shape final            : {df_final.shape}")

print(f"\n📌 Normalização de versões:")
print(f"   Comparáveis     : {comparaveis:,} ({comparaveis/total*100:.1f}%)")
print(f"   Não comparáveis : {nao_comp:,} ({nao_comp/total*100:.1f}%)")

print(f"\n📌 Tipo de limite de versão:")
print(df_final["version_limite_tipo"].value_counts(dropna=False).to_string())

print(f"\n📌 Exemplos de normalização:")
amostra = df_final[df_final["version_comparavel"] == True][
    ["vendor", "product", "version_affected", "version_affected_norm",
     "version_less_than", "version_less_than_norm", "version_limite_tipo"]
].drop_duplicates().head(15)
print(amostra.to_string())

print(f"\n📌 Colunas geradas ({len(df_final.columns)}):")
for c in df_final.columns:
    nulos = df_final[c].isnull().sum()
    pct   = nulos / len(df_final) * 100
    print(f"   {c:<30s}  nulos: {pct:5.1f}%")

# =========================================================
# 💾 SALVAR CSV
# =========================================================

if os.path.exists(output_path):
    try:
        os.remove(output_path)
    except PermissionError:
        print("\n⚠️  Feche o arquivo no Excel antes de rodar novamente.")
        raise

df_final.to_csv(output_path, index=False, encoding="utf-8-sig")

print(f"\n💾 Base salva em:\n   {output_path}")
print(f"\n✅ Concluído — {len(df_final):,} linhas geradas.")




#===========================================================
# =========================================================
# ✅ VALIDAÇÃO DA BASE CVE NORMALIZADA
# =========================================================

import pandas as pd

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"
df = pd.read_csv(base_path + r"\4. CVE_2025_Empilhado_Normalizado.csv", low_memory=False)

# 1. Shape e colunas
print("=" * 60)
print(f"1. SHAPE: {df.shape}")
print(f"   Esperado: (~198.700 linhas, 29 colunas)")
print(f"   Colunas: {list(df.columns)}")

# 2. Colunas novas existem?
novas = ["version_affected_norm", "version_less_than_norm",
         "version_limite_tipo", "version_comparavel"]
print(f"\n2. COLUNAS NOVAS:")
for col in novas:
    existe = col in df.columns
    print(f"   {col}: {'✅ existe' if existe else '❌ FALTA'}")

# 3. Normalização funcionou?
print(f"\n3. NORMALIZAÇÃO DE VERSÕES:")
total = len(df)
comp = df["version_comparavel"].sum()
print(f"   Comparáveis    : {comp:,} ({comp/total*100:.1f}%)")
print(f"   Não comparáveis: {total-comp:,} ({(total-comp)/total*100:.1f}%)")

# 4. Tipo de limite
print(f"\n4. TIPO DE LIMITE:")
print(df["version_limite_tipo"].value_counts(dropna=False).to_string())

# 5. Exemplos de normalização por produto
print(f"\n5. EXEMPLOS DE NORMALIZAÇÃO (por produto):")
produtos_teste = ["Windows Server 2022", "FortiOS", "MySQL Server",
                  "Oracle Java SE", "Linux", "macOS", "curl"]
for prod in produtos_teste:
    sub = df[df["product"] == prod].dropna(subset=["version_affected_norm"]).head(2)
    if len(sub) == 0:
        sub = df[df["product"] == prod].head(1)
    for _, row in sub.iterrows():
        print(f"   {prod}: {row.get('version_affected')} → {row.get('version_affected_norm')}  |  "
              f"{row.get('version_less_than')} → {row.get('version_less_than_norm')}  |  "
              f"comparavel={row.get('version_comparavel')}")

# 6. Verificar que Linux (git hash) ficou como não comparável
linux = df[df["product"] == "Linux"]
linux_comp = linux["version_comparavel"].sum()
print(f"\n6. LINUX (git hashes):")
print(f"   Total: {len(linux):,} | Comparáveis: {linux_comp:,} | "
      f"Não comparáveis: {len(linux)-linux_comp:,}")

# 7. Verificar que Red Hat ficou como não comparável
rh = df[df["vendor"] == "Red Hat"]
rh_comp = rh["version_comparavel"].sum()
print(f"\n7. RED HAT (RPM):")
print(f"   Total: {len(rh):,} | Comparáveis: {rh_comp:,} | "
      f"Não comparáveis: {len(rh)-rh_comp:,}")

print(f"\n{'=' * 60}")
print("✅ Validação concluída!")