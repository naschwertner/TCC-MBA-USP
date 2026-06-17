# TCC MBA USP/ESALQ – Segmentação de Ativos por Perfis de Risco Cibernético

## Sobre o Projeto

Este repositório contém os artefatos desenvolvidos para o Trabalho de Conclusão de Curso (TCC) do MBA em Data Science e Analytics da USP/ESALQ.

O estudo propõe uma abordagem para segmentação de ativos computacionais em perfis de risco cibernético por meio da integração de informações de vulnerabilidades públicas (CVE), características dos ativos e técnicas de Ciência de Dados.

A metodologia combina:

* Coleta e tratamento de vulnerabilidades públicas;
* Construção de uma base integrada CVE × CMDB;
* Engenharia de atributos;
* Redução de dimensionalidade por PCA;
* Clusterização utilizando K-Means;
* Identificação de perfis de risco para priorização de tratamento.

---

## Objetivo

Desenvolver um modelo capaz de identificar grupos de ativos com características semelhantes de exposição técnica e criticidade de negócio, permitindo uma priorização mais eficiente das ações de gestão de vulnerabilidades.

---

## Fluxo Metodológico

1. Coleta dos registros CVE publicados em 2025.
2. Consolidação e tratamento da base de vulnerabilidades.
3. Normalização de versões de software.
4. Construção da base simulada de ativos (CMDB).
5. Cruzamento entre ativos e vulnerabilidades.
6. Análise exploratória dos dados.
7. Engenharia de atributos.
8. Redução de dimensionalidade utilizando PCA.
9. Segmentação dos ativos por K-Means.
10. Interpretação dos perfis de risco identificados.

---

## Estrutura do Repositório

### Etapa 1 – Coleta da Base de Vulnerabilidades

* 1. Clona_CVE_Transforma_Json_em_CSV_Empilhando.py
* 2. CVE_2025_Empilhado.csv

Responsável pela clonagem do repositório oficial de CVEs, extração dos arquivos JSON e consolidação dos registros em uma única base estruturada.

---

### Etapa 2 – Normalização da Base de Vulnerabilidades

* 3. CVE_2025_Normalizacao.py
* 4. CVE_2025_Empilhado_Normalizado.csv

Realiza a expansão das combinações produto-versão afetadas e a normalização dos formatos de versão para viabilizar comparações automatizadas.

---

### Etapa 3 – Base de Ativos

* 5. CMDB_Simulado.csv

Base simulada de ativos utilizada para validação da metodologia proposta.

---

### Etapa 4 – Cruzamento CVE × CMDB

* 6. Cruzamento_CMDB_x_CVE_2025.py
* 7. Cruzamento_CMDB_CVE.csv

Identifica vulnerabilidades potencialmente aplicáveis aos ativos por meio de fabricante, produto, versão, build e CPE.

---

### Etapa 5 – Análise Exploratória

* 8. EDA_Analise_Exploratoria.py

Geração de estatísticas descritivas e visualizações para compreensão do comportamento dos dados.

---

### Etapa 6 – Engenharia de Atributos e PCA

* 9. Features_PCA.py
* 10. Features_PCA.csv

Criação dos atributos utilizados na modelagem e aplicação da Análise de Componentes Principais (PCA).

---

### Etapa 7 – Clusterização

* 11. Clustering.py
* 12. Ativos_com_Clusters.csv

Aplicação do algoritmo K-Means para segmentação dos ativos em perfis de risco.

---

## Tecnologias Utilizadas

* Python 3.13
* Pandas
* NumPy
* Scikit-Learn
* Matplotlib
* Seaborn
* Git
* GitHub

---

## Resultados Obtidos

A aplicação da metodologia permitiu:

* Integrar informações de vulnerabilidades e ativos;
* Reduzir a dimensionalidade dos dados mantendo mais de 77% da variância explicada;
* Identificar três perfis distintos de risco;
* Diferenciar ativos com alta exposição técnica, alta severidade relativa e baixa exposição técnica.

---

## Reprodutibilidade

Todos os scripts, bases intermediárias e artefatos necessários para reprodução dos resultados apresentados no TCC encontram-se disponíveis neste repositório.

---

## Autora

Nathalia Defavari

MBA em Data Science e Analytics – USP/ESALQ

2026
