<div align="center">
  <img src="assets/taintzero-logo.png" width="230" alt="Logo do TaintZero">
  <h1>TaintZero</h1>
  <p>Análise de taint interprocedural open source com confirmação dinâmica e triagem opcional por LLM.</p>
  <p>
    <a href="https://github.com/marcostolosa/taintzero/actions/workflows/ci.yml"><img src="https://github.com/marcostolosa/taintzero/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11 ou superior">
    <img src="https://img.shields.io/badge/Semgrep-1.x-00A9E0" alt="Semgrep 1.x">
    <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-555555" alt="Linux e Windows">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-D22128" alt="Licença Apache 2.0"></a>
  </p>
</div>

O motor próprio do TaintZero indexa projetos Python, conecta chamadas entre arquivos e produz traces
determinísticos de source a sink. Semgrep Community, Graphviz e LLMs são integrações opcionais: eles
complementam a análise, mas não definem o caminho de taint do motor nativo.

A CLI usa Rich para tabelas, status e progresso. Porcentagens são exibidas somente quando existe
um total mensurável. Etapas internas do Semgrep mostram atividade e tempo, sem estimativas falsas.

## Recursos

- repositórios locais e Git remotos;
- análise interprocedural Python com argumentos, retornos, métodos, herança básica e atributos;
- taint tipado, sanitizers específicos e modelos adicionais em YAML;
- exportação JSON, Evidence Graph e Graphviz/DOT;
- harness dinâmico opt-in em Docker ou Podman rootless;
- detecção de linguagens, frameworks e manifests;
- regras oficiais, comunitárias, do Semgrep Registry e locais;
- triagem estruturada por provedores comerciais ou modelos locais;
- redação de credenciais antes do envio de código;
- execução em Linux e Windows.

## Requisitos

- Python 3.11 ou superior;
- Semgrep somente para o backend opcional;
- Git para repositórios remotos.

## Instalação

Executáveis para Windows, Linux e macOS são anexados a cada
[GitHub Release](https://github.com/marcostolosa/taintzero/releases). Git continua necessário para
repositórios remotos. No macOS, o binário não é assinado.

### Windows

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Para habilitar também o backend Semgrep:

```bash
python -m pip install -e ".[dev,semgrep]"
```

## Análise de repositório

Repositório local:

```powershell
taintzero analyze-repo C:\codigo\projeto --output-dir reports\projeto
```

```bash
taintzero analyze-repo /srv/codigo/projeto --output-dir reports/projeto
```

Repositório remoto:

```bash
taintzero analyze-repo https://github.com/org/projeto.git \
  --ref main \
  --output-dir reports/projeto
```

O clone remoto é raso, não interativo e armazenado em `.taintzero/repos`. Use `--refresh` para
recriá-lo.

Por padrão, `analyze-repo` usa somente o motor interprocedural próprio. `--with-semgrep` acrescenta
o Registry automático; `--rules` ou `--rules-profile` também habilitam o backend Semgrep.

### Rulesets

O parâmetro `--rules-profile` controla a origem das regras:

| Perfil | Conteúdo |
| --- | --- |
| `auto` | seleção do Semgrep Registry baseada no repositório |
| `local` | diretório `rules/` ou caminhos passados com `--rules` |
| `semgrep-all` | todas as regras Community Edition de `semgrep/semgrep-rules` |
| `community-top10` | 10 coleções comunitárias classificadas por estrelas no GitHub |
| `full` | `semgrep-all` e `community-top10` |

Baixar e analisar com o conjunto completo:

```bash
taintzero analyze-repo /srv/codigo/projeto \
  --rules-profile full \
  --output-dir reports/projeto
```

As fontes são clonadas com profundidade 1 em `.taintzero/rulesets`. Somente YAMLs com uma lista
Semgrep `rules` são copiados para o cache de execução. O commit e a contagem de arquivos ficam em
`source.json`. Arquivos incompatíveis com a versão instalada do Semgrep são omitidos e registrados
no mesmo manifesto.

Preparar o cache sem iniciar uma análise:

```bash
taintzero rules sync --profile full
taintzero rules list
```

Use `--refresh-rules` durante a análise ou `--refresh` em `rules sync` para atualizar as fontes.
Para usar o cache sem rede:

```bash
taintzero analyze-repo /srv/codigo/projeto \
  --rules-profile full \
  --offline \
  --output-dir reports/projeto
```

As dez fontes comunitárias foram selecionadas em 7 de novembro de 2026 entre repositórios que
publicam coleções de regras, por número de estrelas no GitHub. Licenças e manutenção pertencem a
cada fonte. A lista está versionada no código e não muda durante a execução.

Para usar apenas regras locais:

```bash
taintzero analyze-repo /srv/codigo/projeto \
  --offline \
  --rules rules \
  --output-dir reports/projeto
```

Arquivos gerados:

```text
reports/projeto/
  repository-profile.json
  taintzero.json
  taintzero.dot
  semgrep.json  # somente com o backend Semgrep
  triage.json   # somente quando --llm-config é informado
```

Nesta versão, `--llm-config` em `analyze-repo` requer o backend Semgrep porque a triagem ainda lê o
schema `semgrep.json`.

## Configuração de LLM

O projeto usa LiteLLM Core. O provedor e o modelo são definidos em YAML:

```yaml
llm:
  provider: ollama
  model: qwen3-coder:30b
  api_base: http://localhost:11434
  api_key_env: null
  temperature: 0
  max_tokens: 1800

analysis:
  context_lines: 20
  max_findings: 50
  redact_secrets: true
```

Para provedores remotos, informe o nome da variável que contém a credencial:

```yaml
llm:
  provider: anthropic
  model: claude-sonnet-5
  api_key_env: ANTHROPIC_API_KEY
```

Provedores principais: OpenAI, Anthropic, Gemini, Azure OpenAI, AWS Bedrock, Mistral, OpenRouter,
Ollama, LM Studio, vLLM e endpoints compatíveis com OpenAI.

Triagem com modelo local:

```bash
taintzero analyze-repo /srv/codigo/projeto \
  --with-semgrep \
  --llm-config config.example.yml \
  --output-dir reports/projeto
```

Provedores remotos exigem autorização explícita para envio de trechos:

```bash
taintzero analyze-repo /srv/codigo/projeto \
  --with-semgrep \
  --llm-config config.anthropic.yml \
  --allow-cloud-code \
  --output-dir reports/projeto
```

## Comandos

Executar apenas o motor interprocedural Python:

```bash
taintzero taint /srv/codigo/projeto \
  --output reports/taintzero.json \
  --graph reports/taintzero.dot
```

O relatório inclui diagnósticos, localizações e o trace de cada fluxo. Os modelos embutidos incluem
command/code injection, XSS, SQLi, SSRF, path traversal, desserialização insegura, SSTI e XXE
condicional. A cobertura é por APIs modeladas; essa lista não implica cobertura integral de uma
categoria ou framework.

Fluxos de atributos entre métodos são conectados por identidade de objeto. Funções chamadas mais de
uma vez têm nós e parâmetros clonados por callsite; helpers internos também são expandidos no mesmo
contexto, até profundidade 4. Recursão no mesmo contexto converge pelo solver; profundidade
excedida, dispatch interno ambíguo e múltiplas definições aparecem em `diagnostics`, sem fallback
silencioso para summaries compartilhados. Definições de atributos em branches, loops comuns e
`try/except` são fundidas por `phi` antes de cruzar métodos, preservando alternativas tainted e
sanitizadas; recursão mútua limitada usa o mesmo contexto.

Renderizar o grafo opcionalmente com Graphviz:

```bash
dot -Tsvg reports/taintzero.dot -o reports/taintzero.svg
```

Modelos adicionais podem ser fornecidos em YAML:

```yaml
version: 1
settings:
  conservative_unknown_calls: true
models:
  - symbol: company.web.get_input
    kind: source
    taint: untrusted
  - symbol: company.shell.execute
    kind: sink
    taint: untrusted
    arguments: [0]
    vulnerability: command-injection
```

```bash
taintzero taint projeto --models company-models.yml --output reports/taintzero.json
```

### Harness dinâmico

O harness só planeja por padrão. A execução requer `--execute` e runtime Docker ou Podman rootless.

```yaml
version: 1
image: python:3.13-slim
command: [python, -m, pytest, -q]
timeout_seconds: 60
instrumentation: python
sink_policy: block
inputs:
  - id: http.query.value
    environment: TAINTZERO_CANARY_VALUE
```

```bash
taintzero harness harness.yml \
  --project-root projeto \
  --output harness-plan.json

taintzero harness harness.yml \
  --project-root projeto \
  --output harness-run.json \
  --static-report reports/taintzero.json \
  --execute
```

O container bloqueia a rede, monta o código como read-only, remove capabilities, usa usuário
não-root e aplica limites de recursos. A instrumentação Python reconhece canários em APIs de
filesystem, processos, rede, desserialização e templates. Ausência de observação significa somente
que o caminho não foi exercitado; não classifica automaticamente um finding como falso positivo.

Executar somente o scanner:

```bash
taintzero scan /srv/codigo/projeto --rules rules --output reports/semgrep.json
```

Triar um relatório existente:

```bash
taintzero triage reports/semgrep.json \
  --project-root /srv/codigo/projeto \
  --llm-config config.example.yml \
  --output reports/triage.json
```

Listar provedores:

```bash
taintzero providers
```

## Segurança

- a análise estática não executa o código-alvo nem suas dependências;
- o harness só executa com `--execute` em runtime rootless e sandbox restritivo;
- credenciais são lidas de variáveis de ambiente;
- URLs Git com credenciais ou tokens são recusadas;
- código só é enviado a provedores remotos com `--allow-cloud-code`;
- o resultado da LLM é armazenado separadamente do relatório do Semgrep.

## Limitações

- a cobertura do motor nativo depende das construções Python e APIs atualmente modeladas;
- dispatch altamente dinâmico e extensões nativas podem exigir modelos adicionais;
- heap multi-call expande helpers internos até profundidade 4; ciclos recursivos no mesmo contexto
  são resolvidos, enquanto recursão profunda e dispatch ambíguo são diagnosticados;
- detecção de frameworks depende de manifests e sinais estáticos;
- `auto` requer acesso ao Semgrep Registry e os perfis baixáveis requerem Git no primeiro uso;
- a triagem depende da qualidade da regra, do contexto e do modelo selecionado.

## Testes

```bash
python -m pytest -q
ruff check .
semgrep --test --config rules tests
python -m build --no-isolation
```

O CI executa testes unitários e de integração em Linux e Windows, baixa as 11 fontes, valida o
perfil `full` e rejeita relatórios que contenham erros internos do Semgrep. A action de release
executa um scan real com cada binário empacotado.
