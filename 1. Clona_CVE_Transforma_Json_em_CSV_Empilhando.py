# =========================================================
# 📚 IMPORTS
# =========================================================

import os
import json
import subprocess
import pandas as pd
import numpy as np

# =========================================================
# 📂 CAMINHO BASE DO PROJETO
# =========================================================

base_path = r"C:\Users\Natha\OneDrive\Documentos\Nathalia\4. Faculdade e Cursos\MBA\TCC\Projeto"

# =========================================================
# 📂 PASTA CVE
# =========================================================

cve_folder = os.path.join(base_path, "CVE")

os.makedirs(cve_folder, exist_ok=True)

print("📁 Pasta CVE:")
print(cve_folder)

# =========================================================
# 🔗 GIT
# =========================================================

git_exe = r"C:\Program Files\Git\bin\git.exe"

# =========================================================
# 🔗 REPOSITÓRIO CVE
# =========================================================

repo_url = "https://github.com/CVEProject/cvelistV5.git"

repo_path = os.path.join(
    cve_folder,
    "cvelistV5"
)

# =========================================================
# 📥 CLONE DO REPOSITÓRIO
# =========================================================

if not os.path.exists(repo_path):

    print("\n📥 Clonando repositório CVE...")

    subprocess.run([
        git_exe,
        "clone",
        "--filter=blob:none",
        "--no-checkout",
        repo_url
    ], cwd=cve_folder)

    print("✅ Clone concluído")

    # =====================================================
    # 📥 SPARSE CHECKOUT
    # =====================================================

    subprocess.run([
        git_exe,
        "sparse-checkout",
        "init",
        "--cone"
    ], cwd=repo_path)

    subprocess.run([
        git_exe,
        "sparse-checkout",
        "set",
        "cves/2025"
    ], cwd=repo_path)

    subprocess.run([
        git_exe,
        "checkout",
        "main"
    ], cwd=repo_path)

    print("✅ Apenas CVEs de 2025 baixados")

else:

    print("\n⚠️ Repositório já existe")

# =========================================================
# 📂 CAMINHO DOS JSONS
# =========================================================

target_path = os.path.join(
    repo_path,
    "cves",
    "2025"
)

print("\n📂 Caminho dos JSONs:")
print(target_path)

print("\n📌 Caminho existe?")
print(os.path.exists(target_path))

# =========================================================
# 🔍 VALIDAR QUANTIDADE DE JSONS
# =========================================================

json_files = []

for root, dirs, files in os.walk(target_path):

    for file in files:

        if file.endswith(".json"):

            json_files.append(
                os.path.join(root, file)
            )

print("\n📦 Total de JSONs encontrados:")
print(len(json_files))

# =========================================================
# 📋 LISTA PARA ARMAZENAR JSONS
# =========================================================

data_list = []

# =========================================================
# 🔍 LEITURA DOS JSONS
# =========================================================

for file_path in json_files:

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

            data_list.append(data)

    except Exception as e:

        print(f"❌ Erro no arquivo {file_path}")
        print(e)

# =========================================================
# 📊 TRANSFORMAR EM DATAFRAME
# =========================================================

print("\n📊 Transformando JSONs em DataFrame...")

df = pd.json_normalize(data_list)

# =========================================================
# 🧹 LIMPEZA DE NaN
# =========================================================

for col in df.columns:

    df[col] = df[col].apply(
        lambda x: None
        if isinstance(x, float) and np.isnan(x)
        else x
    )

# =========================================================
# 🧹 CORRIGIR COLUNAS MISTAS
# =========================================================

for col in df.columns:

    non_null_series = df[col].dropna()

    if non_null_series.empty:
        continue

    tem_lista = non_null_series.apply(
        lambda x: isinstance(x, list)
    ).any()

    tem_nao_lista = non_null_series.apply(
        lambda x: not isinstance(x, list)
    ).any()

    if tem_lista and tem_nao_lista:

        print(f"🔧 Corrigindo coluna: {col}")

        df[col] = df[col].apply(
            lambda x:
            x if (
                x is None
                or isinstance(x, list)
            )
            else [x]
        )

# =========================================================
# 📊 VALIDAR DATAFRAME
# =========================================================

print("\n📦 Total registros DataFrame:")
print(len(df))

print("\n📌 Shape:")
print(df.shape)

print("\n📌 Primeiras linhas:")
print(df.head())

print("\n📌 Colunas:")
print(df.columns)

# =========================================================
# 💾 SALVAR CSV
# =========================================================

csv_path = os.path.join(
    base_path,
    "2. base_cve_2025.csv"
)

# remove arquivo antigo se existir
if os.path.exists(csv_path):

    try:
        os.remove(csv_path)

    except:
        print("\n⚠️ Feche o CSV no Excel antes de rodar")
        raise

df.to_csv(
    csv_path,
    index=False,
    encoding="utf-8-sig"
)

print("\n💾 CSV salvo:")
print(csv_path)

# =========================================================
# ✅ VALIDAR CSV
# =========================================================

df_csv = pd.read_csv(csv_path)

print("\n📦 Total linhas CSV:")
print(len(df_csv))

