# Arquitetura e roadmap de pesquisa

O livro citado é *From Day Zero to Zero Day*, de Eugene Lim. O projeto aproveita principalmente
o arco de code review do livro: taint analysis, mapeamento entre código e superfície de ataque,
variant analysis e descoberta de sources/sinks. A ferramenta não promete “produzir zero-days”;
ela torna o processo de formular, testar e registrar hipóteses mais sistemático.

## Pipeline

```text
repositório autorizado
        |
        v
regras Semgrep (source -> propagator -> sanitizer -> sink)
        |
        v
JSON original + dataflow disponível
        |
        +----> corpus de avaliação e métricas determinísticas
        |
        v
coletor de contexto mínimo + redator de segredos
        |
        v
adaptador provider/model escolhido pelo usuário
        |
        v
triagem estruturada: evidência, confiança, pré-condições e correção
        |
        v
feedback humano -> novo teste -> refinamento da regra
```

Semgrep decide se um fluxo casa com a regra. A LLM recebe o achado e ajuda a responder perguntas
que dependem de semântica de aplicação: a rota é alcançável, existe uma validação fora do trecho,
qual pré-condição falta e que sanitizer ou propagator deveria ser modelado? A resposta da LLM é
armazenada separadamente e nunca altera silenciosamente o resultado do scanner.

O MVP funciona com Semgrep Community Edition e, portanto, começa com análise por arquivo. Fluxos
entre arquivos exigem o engine comercial; essa diferença deve ser registrada nas métricas para não
atribuir um falso negativo ao modelo de IA.

## Uso da IA

### Agora, no MVP

- classificar `true_positive`, `false_positive` ou `needs_review`;
- explicar evidências e lacunas sem inventar contexto;
- listar pré-condições de ataque e impacto provável;
- sugerir melhorias de regra para revisão humana;
- funcionar com um modelo local ou remoto escolhido pelo usuário.

### Próximas fases

1. **Descoberta de source/sink:** indexar chamadas e pedir à LLM apenas a classificação de APIs
   desconhecidas; transformar sugestões aprovadas em testes antes de alterar regras.
2. **Variant analysis:** receber uma vulnerabilidade conhecida ou patch e gerar hipóteses de
   variantes estruturais; Semgrep continua responsável por procurá-las no corpus.
3. **Contexto de superfície de ataque:** conectar rotas, parsers, formatos e limites de confiança
   ao achado para priorizar fluxos realmente alcançáveis.
4. **Avaliação:** comparar modelos e prompts em um corpus rotulado, medindo precisão, recall,
   calibração da confiança, custo e latência.
5. **Feedback controlado:** aceitar/rejeitar sugestões e gerar um patch de regra revisável; jamais
   promover automaticamente uma regra de IA para produção.

## Métricas separadas

Não misture a qualidade do scanner com a do modelo:

- Semgrep: verdadeiros/falsos positivos, falsos negativos, precisão e recall por regra.
- LLM: acerto da triagem, taxa de `needs_review`, calibração, JSON inválido, custo e latência.
- Pipeline: redução de tempo de revisão e quantidade de melhorias de regra aceitas por humanos.

## Limites de segurança e privacidade

- somente repositórios próprios ou com autorização explícita;
- nenhum código remoto sem `--allow-cloud-code`;
- segredos comuns são redigidos antes do prompt;
- contexto limitado às linhas próximas do achado;
- nenhum exploit operacional é solicitado ao modelo;
- credenciais ficam em variáveis de ambiente, nunca no YAML.

