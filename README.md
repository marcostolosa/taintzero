<div align="center">
  <img src="assets/taintzero-logo.png" width="230" alt="Logo do TaintZero">
  <h1>TaintZero</h1>
  <p>Taint analysis com Semgrep e triagem opcional por LLM.</p>
  <p>
    <a href="https://github.com/marcostolosa/taintzero/actions/workflows/ci.yml"><img src="https://github.com/marcostolosa/taintzero/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11 ou superior">
    <img src="https://img.shields.io/badge/Semgrep-1.x-00A9E0" alt="Semgrep 1.x">
    <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-555555" alt="Linux e Windows">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-D22128" alt="Licença Apache 2.0"></a>
  </p>
</div>

O Semgrep produz os achados primários. A LLM classifica evidências, registra pré-condições, sugere
correções e indica ajustes nas regras sem modificar o relatório original.

## Recursos

- repositórios locais e Git remotos;
- detecção de linguagens, frameworks e manifests;
- regras do Semgrep Registry e regras locais;
- triagem estruturada por provedores comerciais ou modelos locais;
- redação de credenciais antes do envio de código;
- execução em Linux e Windows.

## Requisitos

- Python 3.11 ou superior;
- Semgrep;
- Git para repositórios remotos.

## Instalação

### Windows

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]" semgrep
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]" semgrep
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

Por padrão, o comando usa `--config auto` e inclui `rules/` quando o diretório existe. Para impedir
consultas ao Semgrep Registry, use regras locais:

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
  semgrep.json
  triage.json
```

`triage.json` só é criado quando `--llm-config` é informado.

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
  --llm-config config.example.yml \
  --output-dir reports/projeto
```

Provedores remotos exigem autorização explícita para envio de trechos:

```bash
taintzero analyze-repo /srv/codigo/projeto \
  --llm-config config.anthropic.yml \
  --allow-cloud-code \
  --output-dir reports/projeto
```

## Comandos

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

- o código analisado e suas dependências não são executados;
- credenciais são lidas de variáveis de ambiente;
- URLs Git com credenciais ou tokens são recusadas;
- código só é enviado a provedores remotos com `--allow-cloud-code`;
- o resultado da LLM é armazenado separadamente do relatório do Semgrep.

## Limitações

- Semgrep Community Edition não oferece análise completa entre arquivos;
- detecção de frameworks depende de manifests e sinais estáticos;
- `--config auto` requer acesso ao Semgrep Registry;
- a triagem depende da qualidade da regra, do contexto e do modelo selecionado.

## Testes

```bash
python -m pytest -q
ruff check src tests scripts
semgrep --test --config rules tests
```

O CI executa a suíte em Linux e Windows com Python 3.11 e 3.13.

Detalhes do pipeline estão em [docs/architecture.md](docs/architecture.md).
