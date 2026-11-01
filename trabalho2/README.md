# Trabalho 2: Modelagem de Ameaças com DFD e STRIDE

Segurança de Sistemas Computacionais 2026/2, UNIVALI.
Alvo: OWASP Juice Shop 20.3.0 (imagem `bkimminich/juice-shop`), executado em contêiner Docker no GitHub Codespaces.

## Conteúdo

| Arquivo | O que é |
|---|---|
| `modelo_ameacas.py` | Arquivo-fonte do modelo (modelo como código): elementos, fronteiras de confiança e fluxos de dados |
| `saida/dfd_nivel1.png` | DFD nível 1 completo |
| `saida/recorte_fx1.png` ... `recorte_fx5.png` | Recorte do DFD de cada fluxo analisado |
| `saida/inventario.md` | Inventário de elementos, fronteiras, fluxos de dados e passos de cada fluxo |
| `saida/modelo.json` | Exportação do modelo em JSON |
| `analise.py` | Fichas, matrizes STRIDE por elemento, registro de ameaças, DREAD, mitigações e Top 10 |
| `saida/analise_fluxos.md` | Análise completa de cada fluxo, gerada por `analise.py` |
| `saida/registro_ameacas.json` | Registro de ameaças em JSON |

## Como gerar novamente

Requisito: Python 3 e Graphviz.

```bash
sudo apt-get update && sudo apt-get install -y graphviz   # só na primeira vez
python3 modelo_ameacas.py validar   # confere as regras de DFD da Seção 5.1 do roteiro
python3 modelo_ameacas.py gerar     # gera DFDs, inventário e JSON em ./saida
python3 analise.py                  # valida e gera a análise STRIDE em ./saida
```

O `analise.py` também valida as regras da Seção 6 do roteiro: no mínimo 6 ameaças por fluxo;
as seis categorias STRIDE cobertas ou justificadas; cada ameaça com categoria aplicável ao tipo
do seu elemento (STRIDE por elemento); toda célula aplicável da matriz com ameaça ou N/A justificado;
cenário no formato padrão; DREAD com 5 notas justificadas; mitigação com referência.

O comando `validar` verifica automaticamente: entidades externas só se comunicam com processos;
armazenamentos só se conectam a processos; todo processo tem entrada e saída; IDs não se repetem;
e todo fluxo analisado cruza ao menos uma fronteira de confiança.
As fronteiras atravessadas por cada fluxo de dados são calculadas a partir das zonas dos elementos.
