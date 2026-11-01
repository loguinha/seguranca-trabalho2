#!/usr/bin/env python3
"""
Analise STRIDE dos fluxos (Secao 6 do roteiro): fichas, matrizes STRIDE por elemento,
registro de ameacas, DREAD, mitigacoes e Top 10.
Usa o modelo de modelo_ameacas.py e valida as regras do roteiro.

Uso: python3 analise.py   (gera saida/analise_fluxos.md e saida/registro_ameacas.json)
"""
import json
import os
import sys
from modelo_ameacas import ELEMENTOS, FLUXOS, FLUXOS_DADOS

STRIDE = ["S", "T", "R", "I", "D", "E"]
NOME_STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
               "I": "Information Disclosure", "D": "Denial of Service",
               "E": "Elevation of Privilege"}
PROPRIEDADE = {"S": "Autenticidade", "T": "Integridade", "R": "Não repúdio",
               "I": "Confidencialidade", "D": "Disponibilidade", "E": "Autorização"}
# STRIDE por elemento (Secao 6.2 do roteiro). F = fluxo de dados.
APLICAVEL = {"E": "SR", "P": "STRIDE", "D": "TID", "F": "TID"}

# Status permitidos (Secao 6.6) mais a observacao passiva feita neste trabalho.
STATUS = ("Confirmada no T1", "Observada no T2", "Plausível", "Tratada por controle existente")


def nivel(media):
    if media >= 7.0:
        return "Alto"
    if media >= 4.0:
        return "Médio"
    return "Baixo"


# ---------------------------------------------------------------------------
# Fichas dos fluxos (Secao 7.1)
# ---------------------------------------------------------------------------
FICHAS = {
 "FX1": {
  "responsavel": "Logan Santana Fernandes",
  "descricao": "O cliente informa e-mail e senha na SPA (P1), que envia POST /rest/user/login à API (P2). "
               "P2 consulta a tabela Users em D1 e, se a combinação existir, emite um JWT assinado em RS256 "
               "e devolve também o identificador da cesta (bid) e o e-mail. P1 guarda token e bid no navegador (D5) "
               "e passa a enviar o token no cabeçalho Authorization em cada chamada, como em GET /rest/user/whoami.",
  "ator": "E1 Cliente (ainda anônimo), ao clicar em Log in.",
  "precondicoes": "Conta cadastrada; aplicação acessível pelo encaminhamento de portas do Codespaces.",
  "resultado": "Sessão ativa no navegador: o menu da conta exibe o e-mail e as chamadas com o token são aceitas.",
  "requisicoes": ["POST /rest/user/login (200 OK)", "GET /rest/user/whoami (200 OK)"],
  "dados": [
   ("E-mail", "Dado pessoal (LGPD, art. 5º, I)", "Trânsito (F01, F02, F05); repouso (D1)", "Confidencialidade"),
   ("Senha", "Credencial ou segredo", "Trânsito (F01, F02); repouso (D1, como hash MD5)", "Confidencialidade"),
   ("Token JWT", "Credencial ou segredo", "Trânsito (F05, F08); repouso (D5)", "Confidencialidade e integridade"),
   ("bid", "Interno", "Trânsito (F05); repouso (D5)", "Integridade"),
  ],
  "controles": [
   "HTTPS entre o navegador e o túnel do Codespaces (observado: URL https e HSTS enviado pelo túnel).",
   "Token assinado com RS256 (observado: cabeçalho do JWT decodificado).",
   "Senha armazenada como hash, porém MD5 sem sal (código-fonte do projeto).",
   "Limite de 1.500 requisições por minuto por porta, aplicado pelo túnel e não pela aplicação (observado: cabeçalhos Ratelimit-*).",
  ],
 },
 "FX2": {
  "responsavel": "Logan Santana Fernandes",
  "descricao": "Com a sessão ativa, P1 lê o bid em D5 e chama GET /rest/basket/{bid} com o token. "
               "P2 busca a cesta e seus produtos em D1 e devolve o JSON exibido ao cliente. "
               "O identificador da cesta é numérico e sequencial.",
  "ator": "E1 Cliente autenticado, ao abrir Your Basket ou ao carregar a loja já logado.",
  "precondicoes": "Sessão válida (token JWT) e bid gravado no navegador.",
  "resultado": "A cesta do usuário é exibida com produtos e quantidades.",
  "requisicoes": ["GET /rest/basket/1 (304 Not Modified, respondida do cache após a primeira carga)"],
  "dados": [
   ("Itens e quantidades da cesta", "Dado pessoal (revela hábito de consumo)", "Trânsito (F13); repouso (D1)", "Confidencialidade"),
   ("bid", "Interno", "Trânsito (F07, F10)", "Integridade"),
   ("Token JWT", "Credencial ou segredo", "Trânsito (F10)", "Confidencialidade"),
  ],
  "controles": [
   "A rota exige token JWT no cabeçalho Authorization (observado no Trabalho 1).",
   "Nenhuma verificação de propriedade da cesta (achado V2 do Trabalho 1).",
  ],
 },
 "FX4": {
  "responsavel": "Logan Santana Fernandes",
  "descricao": "Ao abrir a aplicação, P1 requisita GET /rest/admin/application-configuration para montar a interface. "
               "P2 lê os parâmetros de D3 e devolve a configuração completa, cerca de 36 kB de JSON, sem exigir token, "
               "embora a rota esteja no espaço /rest/admin.",
  "ator": "E1 Cliente anônimo, no carregamento da página.",
  "precondicoes": "Nenhuma.",
  "resultado": "Interface configurada; a configuração completa fica disponível a qualquer consumidor.",
  "requisicoes": ["GET /rest/admin/application-configuration (304 no navegador; 200 OK via curl anônimo, 36.154 bytes)"],
  "dados": [
   ("Parâmetros da aplicação", "Interno", "Repouso (D3); trânsito (F19)", "Confidencialidade"),
  ],
  "controles": [
   "Cabeçalhos X-Content-Type-Options: nosniff e X-Frame-Options: SAMEORIGIN enviados pela aplicação (observado via curl).",
   "Nenhuma autenticação ou autorização na rota (observado: 200 OK sem token).",
   "Access-Control-Allow-Origin: * na resposta (observado via curl).",
  ],
 },
 "FX5": {
  "responsavel": "Logan Santana Fernandes",
  "descricao": "O cliente autenticado adiciona um produto (POST /api/BasketItems), cadastra endereço (POST /api/Addresss) "
               "e cartão (POST /api/Cards), escolhe a entrega (GET /api/Deliverys) e finaliza com "
               "POST /rest/basket/{bid}/checkout, enviando os IDs de endereço, pagamento e entrega. "
               "P2 registra o pedido em D2, grava o PDF de confirmação na pasta pública ftp/ (D4) e devolve o id do pedido, "
               "exibido via GET /rest/track-order/{id}.",
  "ator": "E1 Cliente autenticado, ao clicar em Checkout.",
  "precondicoes": "Sessão válida e cesta com ao menos um item.",
  "resultado": "Pedido registrado, PDF gerado e tela de confirmação exibida.",
  "requisicoes": ["POST /api/BasketItems/ (200 OK)", "POST /api/Addresss/ (201 Created)", "GET /api/Deliverys (304)",
                  "POST /api/Cards/ (201 Created)", "POST /rest/basket/6/checkout (200 OK)",
                  "GET /rest/track-order/{id} (200 OK)", "GET /ftp e GET /ftp/order_{id}.pdf (listagem e PDF acessíveis)"],
  "dados": [
   ("Nome, telefone e endereço", "Dado pessoal (LGPD, art. 5º, I)", "Trânsito (F23); repouso (D1)", "Confidencialidade"),
   ("Número, nome e validade do cartão", "Dado pessoal e financeiro", "Trânsito (F26); repouso (D1)", "Confidencialidade"),
   ("E-mail, itens e total do pedido", "Dado pessoal", "Repouso (D2 e PDF em D4); resposta (F34)", "Confidencialidade"),
   ("addressId, paymentId, deliveryMethodId, bid", "Interno", "Trânsito (F28)", "Integridade"),
  ],
  "controles": [
   "As rotas exigem token JWT (observado: requisições autenticadas).",
   "HTTPS entre o navegador e o túnel.",
   "Nenhuma validação do cartão observada: a API aceitou número 1234567890123456 e validade 2096.",
   "Nenhum controle de acesso à pasta ftp/: listagem e PDF abertos no navegador.",
  ],
 },
}

# ---------------------------------------------------------------------------
# Registro de ameacas (Secoes 6.4 a 6.6 e 7.4)
# dread = (D, R, E, A, D) ; just = justificativa de cada nota
# ---------------------------------------------------------------------------
A = []
def ameaca(**k):
    A.append(k)

# ============================== FX1 ==============================
ameaca(id="T-FX1-01", fx="FX1", elementos=["E1", "F02"], stride="S",
  cenario="Um atacante anônimo com uma lista de senhas vazadas pode se passar por qualquer cliente, inclusive o administrador, "
          "enviando tentativas em massa no fluxo F02, explorando a ausência de limite de tentativas, bloqueio e MFA na aplicação, "
          "resultando no sequestro de contas e na exposição dos dados pessoais dos titulares.",
  cwe="CWE-307 / A07", status="Confirmada no T1 (V5)",
  controle="Apenas o limite de 1.500 requisições por minuto do túnel, que não existe fora do laboratório.",
  dread=(8, 9, 7, 8, 8),
  just=("permite tomar qualquer conta, inclusive a de administrador", "o ataque se repete sem restrição",
        "exige só uma lista de senhas e uma ferramenta comum de automação", "atinge todos os usuários cadastrados",
        "a ausência de bloqueio é percebida após poucas tentativas"),
  mitigacao="Em P2, limitar tentativas por conta e por IP com atraso progressivo, notificar o titular após falhas, "
            "e oferecer MFA (obrigatório para o administrador). Ref.: ASVS 5.0 6.3.1 e 6.3.3; "
            "Authentication e Credential Stuffing Prevention Cheat Sheets; LGPD, art. 46.",
  tipo="Preventivo e detectivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX1-02", fx="FX1", elementos=["P2", "F02"], stride="E",
  cenario="Um atacante anônimo pode obter a sessão do administrador enviando ' OR 1=1-- no campo e-mail do fluxo F02, "
          "explorando a concatenação da entrada na consulta SQL que P2 envia a D1 (F03), "
          "resultando em acesso administrativo sem credenciais e em acesso aos dados de todos os titulares.",
  cwe="CWE-89 / A03", status="Confirmada no T1 (V1) e observada no T2",
  controle="Nenhum; a consulta é montada por concatenação.",
  dread=(10, 10, 9, 10, 8),
  just=("concede privilégio total de administrador", "o mesmo payload funciona sempre",
        "um único payload conhecido, sem ferramenta", "compromete todos os usuários e dados",
        "é um teste clássico e foi reproduzido nas duas versões (20.2.0 e 20.3.0)"),
  mitigacao="Substituir a concatenação por consulta parametrizada (ou pelo próprio ORM Sequelize com parâmetros) em P2 "
            "e validar o formato do e-mail no servidor. Ref.: ASVS 5.0 1.2.4 e 2.2.1; "
            "SQL Injection Prevention e Query Parameterization Cheat Sheets.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX1-03", fx="FX1", elementos=["F08", "P2"], stride="T",
  cenario="Um usuário autenticado pode alterar o conteúdo do seu JWT (por exemplo, o e-mail ou o papel) e reassiná-lo com HS256 "
          "usando a chave pública RSA como segredo, enviando-o no fluxo F08, explorando as versões antigas de jsonwebtoken (0.4.0) "
          "e express-jwt (0.1.3) usadas por P2, que não restringem o algoritmo aceito (confusão de algoritmo, CVE-2015-9235), "
          "resultando em um token forjado aceito como de outro usuário.",
  cwe="CWE-347 / A02", status="Plausível",
  controle="Assinatura RS256 na emissão; a verificação não fixa o algoritmo.",
  dread=(9, 8, 5, 10, 6),
  just=("permite agir como qualquer usuário", "uma vez montado, o token forjado é reutilizável",
        "exige conhecer o ataque e obter a chave pública", "afeta qualquer conta",
        "a chave pública e as versões das bibliotecas são localizáveis"),
  mitigacao="Atualizar jsonwebtoken e express-jwt, fixar a lista de algoritmos aceitos em ['RS256'] na verificação "
            "e rejeitar 'none'. Ref.: ASVS 5.0 9.1.1 e 9.1.2; JSON Web Token Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX1-04", fx="FX1", elementos=["D5"], stride="I",
  cenario="Um script malicioso injetado na página (por exemplo, por XSS) pode ler o token guardado em D5, "
          "explorando o armazenamento em localStorage e em cookie sem HttpOnly e sem Secure gravado pelo próprio JavaScript de P1, "
          "resultando no sequestro da sessão e no acesso aos dados pessoais da vítima.",
  cwe="CWE-1004 / A05", status="Confirmada no T1 (V3)",
  controle="Nenhum; o token fica acessível a qualquer script da origem.",
  dread=(8, 7, 5, 7, 7),
  just=("dá acesso completo à conta da vítima", "repete-se a cada visita da vítima à página afetada",
        "depende de existir um vetor de execução de script", "atinge quem acessar a página afetada",
        "o token aparece na aba Application do DevTools"),
  mitigacao="Mover a sessão para cookie emitido pelo servidor com HttpOnly, Secure e SameSite, "
            "deixando de expor o token ao JavaScript; aplicar Content-Security-Policy. "
            "Ref.: ASVS 5.0 3.3.1, 3.3.2 e 3.3.4; Session Management e HTML5 Security Cheat Sheets.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX1-05", fx="FX1", elementos=["D1", "P2"], stride="I",
  cenario="Um atacante que obtenha os registros de Users (por exemplo, via T-FX1-02) ou um token de outro usuário "
          "pode recuperar senhas em texto claro, explorando o armazenamento em MD5 sem sal em D1 "
          "e a cópia do registro do usuário no payload do JWT emitido por P2, "
          "resultando no comprometimento das contas e de outras contas em que os titulares reutilizam a senha.",
  cwe="CWE-916 / A02", status="Plausível",
  controle="Hash MD5, sem sal e sem fator de custo.",
  dread=(8, 6, 6, 9, 5),
  just=("expõe a senha real dos titulares", "depende de obter antes os hashes",
        "quebrar MD5 sem sal é rápido com tabelas prontas", "atinge toda a base de usuários",
        "exige analisar o token ou o banco"),
  mitigacao="Armazenar senhas com função lenta e com sal (Argon2id, scrypt ou bcrypt), migrando no próximo login, "
            "e retirar dados do usuário além do identificador do payload do token. "
            "Ref.: ASVS 5.0 11.4.2; Password Storage Cheat Sheet; LGPD, art. 46.",
  tipo="Preventivo", camada="Dados", decisao="Mitigar")

ameaca(id="T-FX1-06", fx="FX1", elementos=["E1", "P2"], stride="R",
  cenario="Um cliente, ou quem tenha usado a conta dele, pode negar ter feito um login ou uma ação autenticada em P2, "
          "explorando a ausência de registro das tentativas de login (resultado, data, hora e origem) "
          "e o logout que apenas apaga o token no navegador sem invalidá-lo no servidor, "
          "resultando na impossibilidade de apurar incidentes e de atribuir ações ao titular.",
  cwe="CWE-778 / A09", status="Confirmada no T1 (V6)",
  controle="Log de aplicação em stdout voltado aos desafios; sem trilha de auditoria de segurança.",
  dread=(5, 9, 7, 8, 4),
  just=("prejudica a apuração e a responsabilização (LGPD, art. 6º, X)", "toda ação fica sem registro adequado",
        "basta usar a aplicação normalmente", "vale para todos os usuários",
        "só é percebida por quem investiga um incidente"),
  mitigacao="Registrar em P2 todo login (sucesso e falha) com usuário, data e hora, IP e resultado, "
            "e invalidar o token no servidor no logout (lista de revogação ou chave por usuário). "
            "Ref.: ASVS 5.0 16.3.1 e 7.4.1; Logging e Logging Vocabulary Cheat Sheets.",
  tipo="Detectivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX1-07", fx="FX1", elementos=["F02", "P2"], stride="D",
  cenario="Um atacante anônimo pode enviar milhares de requisições ao fluxo F02, cada uma gerando uma consulta em D1, "
          "explorando a ausência de limite de taxa na aplicação, que roda em um único processo Node.js, "
          "resultando em lentidão ou indisponibilidade do login para todos os clientes.",
  cwe="CWE-770 / A04", status="Plausível",
  controle="Limite do túnel por porta (1.500/min), que também bloquearia clientes legítimos e não existe fora do laboratório.",
  dread=(5, 8, 8, 9, 6),
  just=("indisponibilidade temporária, sem perda de dados", "basta repetir a carga",
        "ferramentas de carga comuns bastam", "afeta todos os clientes",
        "a falta de limite aparece nos primeiros testes"),
  mitigacao="Aplicar limite de taxa por IP e por conta em /rest/user/login dentro da aplicação "
            "(a dependência express-rate-limit já existe no projeto) e monitorar o volume de falhas. "
            "Ref.: ASVS 5.0 2.4.1; Denial of Service Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

# ============================== FX2 ==============================
ameaca(id="T-FX2-01", fx="FX2", elementos=["P2", "F13"], stride="I",
  cenario="Um cliente autenticado pode ver a cesta de qualquer outro cliente trocando o número na requisição "
          "GET /rest/basket/{bid} (F10), explorando a falta de verificação de propriedade em P2, "
          "resultando na exposição dos hábitos de consumo de terceiros.",
  cwe="CWE-639 / A01", status="Confirmada no T1 (V2)",
  controle="Exigência de token; nenhuma verificação de propriedade.",
  dread=(6, 10, 9, 9, 9),
  just=("expõe dado pessoal de consumo, sem alterá-lo", "basta repetir com outro número",
        "trocar um número na URL", "todas as cestas são enumeráveis",
        "o id sequencial aparece na aba Network"),
  mitigacao="Em P2, obter o dono da cesta a partir do token e recusar (403) qualquer bid que não pertença ao usuário da sessão. "
            "Ref.: ASVS 5.0 8.2.2 e 8.3.1; Authorization e IDOR Prevention Cheat Sheets; LGPD, art. 46.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX2-02", fx="FX2", elementos=["P2"], stride="E",
  cenario="Um cliente autenticado pode agir sobre a cesta de outro cliente, adicionando ou removendo itens com o BasketId alheio, "
          "explorando o fato de P2 verificar apenas se há sessão, e não se o recurso pertence a quem a apresenta, "
          "resultando em escalonamento horizontal de privilégio e na alteração de dados de terceiros.",
  cwe="CWE-285 / A01", status="Plausível",
  controle="Exigência de token apenas.",
  dread=(7, 9, 8, 9, 7),
  just=("altera dados e compras de outros clientes", "repetível com qualquer id",
        "basta editar o corpo JSON", "todas as cestas são alvos",
        "o campo BasketId é visível no payload de F21"),
  mitigacao="Derivar o BasketId do token no servidor e ignorar o valor enviado pelo cliente; testar autorização por objeto em todas as rotas /api. "
            "Ref.: ASVS 5.0 8.2.2 e 8.3.1; Authorization Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX2-03", fx="FX2", elementos=["D5", "F07"], stride="T",
  cenario="Um cliente pode alterar o bid guardado no sessionStorage (D5), que P1 lê no fluxo F07 e repassa a P2, "
          "explorando a confiança da aplicação em um identificador controlado pelo cliente, "
          "resultando no acesso às cestas de terceiros pela própria interface, sem ferramenta.",
  cwe="CWE-602 / A04", status="Plausível",
  controle="Nenhum.",
  dread=(4, 10, 9, 8, 7),
  just=("o dano real se concretiza por T-FX2-01 e T-FX2-02", "sempre funciona",
        "editar o armazenamento no DevTools", "todas as cestas",
        "o bid está visível na aba Application"),
  mitigacao="Não usar identificadores vindos do cliente para decidir acesso: o servidor obtém a cesta pela sessão. "
            "Ref.: ASVS 5.0 8.3.1 e 2.2.1.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX2-04", fx="FX2", elementos=["E1"], stride="S",
  cenario="Um atacante que tenha obtido o token de um cliente (por exemplo, via T-FX1-04) pode se passar por ele "
          "e consultar a cesta e os dados da conta, explorando a validade do token mesmo após o logout, "
          "resultando no acesso aos dados pessoais da vítima.",
  cwe="CWE-294 / A07", status="Plausível",
  controle="Expiração do token; sem revogação no servidor.",
  dread=(7, 6, 5, 6, 5),
  just=("acesso pleno à conta da vítima", "depende de obter o token antes",
        "exige um vetor de roubo do token", "atinge as vítimas cujo token vazou",
        "requer combinar com outra falha"),
  mitigacao="Invalidar o token no servidor no logout, reduzir a validade e vincular a sessão a cookie HttpOnly. "
            "Ref.: ASVS 5.0 7.4.1 e 3.3.4; Session Management Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX2-05", fx="FX2", elementos=["P2"], stride="R",
  cenario="Um cliente pode negar ter acessado a cesta de outro cliente em P2, "
          "explorando a ausência de registro dos acessos a objetos de terceiros e dos acessos negados, "
          "resultando na impossibilidade de detectar e comprovar a enumeração de cestas.",
  cwe="CWE-778 / A09", status="Confirmada no T1 (V6)",
  controle="Nenhum log de acesso por objeto.",
  dread=(4, 9, 8, 8, 4),
  just=("prejudica a apuração, sem dano direto", "nenhum acesso é registrado",
        "uso normal da aplicação", "todos os usuários",
        "só aparece em investigação"),
  mitigacao="Registrar acessos a cestas com usuário, objeto, data e hora e resultado, e gerar alerta para sequências de ids. "
            "Ref.: ASVS 5.0 16.3.2; Logging Cheat Sheet.",
  tipo="Detectivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX2-06", fx="FX2", elementos=["P2", "F10"], stride="D",
  cenario="Um cliente autenticado pode enumerar automaticamente /rest/basket/1 a N, cada chamada gerando consulta com junção de produtos em D1, "
          "explorando a ausência de limite de taxa e os ids sequenciais, "
          "resultando em sobrecarga de P2 e D1 e lentidão para todos os clientes.",
  cwe="CWE-799 / A04", status="Plausível",
  controle="Limite do túnel (1.500/min por porta).",
  dread=(4, 9, 8, 7, 6),
  just=("degradação temporária", "repetível", "script simples", "afeta todos durante o ataque",
        "a sequência de ids é óbvia"),
  mitigacao="Limitar a taxa por usuário nas rotas de cesta e usar identificadores não sequenciais. "
            "Ref.: ASVS 5.0 2.4.1; Denial of Service Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

# ============================== FX4 ==============================
ameaca(id="T-FX4-01", fx="FX4", elementos=["P2", "F19"], stride="I",
  cenario="Um usuário anônimo pode obter a configuração completa da aplicação chamando GET /rest/admin/application-configuration (F16), "
          "explorando a ausência de autenticação na rota, "
          "resultando na exposição de parâmetros internos (pelo código-fonte do projeto, inclusive os do login com Google) "
          "que facilitam ataques direcionados.",
  cwe="CWE-200 / A01", status="Observada no T2",
  controle="Nenhum; resposta 200 OK sem token.",
  dread=(5, 10, 10, 6, 8),
  just=("expõe dados internos, sem dado pessoal direto", "sempre responde",
        "uma requisição sem ferramenta", "afeta indiretamente todos os usuários",
        "a SPA faz a chamada em toda carga de página"),
  mitigacao="Servir ao cliente apenas os campos necessários à interface em uma rota pública separada "
            "e mover a configuração completa para rota autenticada e restrita ao administrador. "
            "Ref.: ASVS 5.0 13.4.5 e 8.2.3.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX4-02", fx="FX4", elementos=["P2"], stride="E",
  cenario="Um usuário anônimo pode executar funções do espaço /rest/admin, que deveriam ser exclusivas do administrador, "
          "explorando a ausência de verificação de papel por função em P2, "
          "resultando no uso de funções administrativas sem autenticação.",
  cwe="CWE-862 / A01", status="Observada no T2",
  controle="Nenhum; o prefixo /admin não implica verificação.",
  dread=(5, 10, 10, 6, 7),
  just=("as funções expostas hoje são de leitura", "sempre funciona",
        "acesso direto à URL", "afeta indiretamente todos",
        "rotas /rest/admin aparecem na aba Network"),
  mitigacao="Aplicar verificação de autenticação e de papel admin em todas as rotas /rest/admin por padrão (negar por omissão). "
            "Ref.: ASVS 5.0 8.2.1 e 8.3.1; Authorization Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX4-03", fx="FX4", elementos=["D3"], stride="T",
  cenario="Um atacante que consiga gravar arquivos no contêiner, por exemplo por travessia de caminho no envio de arquivos compactados "
          "em outra funcionalidade da loja, pode alterar os arquivos YAML de D3, "
          "explorando a gravação com o mesmo usuário que executa a aplicação, "
          "resultando em configuração adulterada servida a todos os clientes após o reinício.",
  cwe="CWE-22 / A01", status="Plausível",
  controle="A configuração só é relida na inicialização.",
  dread=(7, 4, 3, 9, 3),
  just=("altera o comportamento para todos", "depende de outra falha de gravação",
        "exige encadear vulnerabilidades", "afeta todos os clientes",
        "exige conhecer a estrutura interna do contêiner"),
  mitigacao="Montar config/ como somente leitura no contêiner e normalizar caminhos na extração de arquivos. "
            "Ref.: ASVS 5.0 V5 (tratamento de arquivos); File Upload Cheat Sheet.",
  tipo="Preventivo", camada="Rede e infraestrutura", decisao="Mitigar")

ameaca(id="T-FX4-04", fx="FX4", elementos=["P2"], stride="R",
  cenario="Um agente anônimo pode coletar a configuração repetidamente sem deixar rastro em P2, "
          "explorando a ausência de registro dos acessos às rotas /rest/admin, "
          "resultando na impossibilidade de detectar a fase de reconhecimento de um ataque.",
  cwe="CWE-778 / A09", status="Confirmada no T1 (V6)",
  controle="Nenhum.",
  dread=(3, 10, 10, 5, 4),
  just=("não causa dano direto", "sempre", "acesso direto", "indireto", "só em investigação"),
  mitigacao="Registrar todo acesso às rotas /rest/admin com origem, data e hora e resultado. "
            "Ref.: ASVS 5.0 16.3.3; Logging Cheat Sheet.",
  tipo="Detectivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX4-05", fx="FX4", elementos=["F19", "P2"], stride="D",
  cenario="Um atacante anônimo pode solicitar repetidamente a configuração de cerca de 36 kB, "
          "explorando a ausência de limite de taxa e de autenticação, "
          "resultando em consumo de banda e processamento de P2 que degrada o serviço.",
  cwe="CWE-770 / A04", status="Plausível",
  controle="ETag e resposta 304 reduzem a carga para clientes legítimos; limite do túnel.",
  dread=(3, 10, 9, 6, 5),
  just=("degradação leve e temporária", "repetível", "trivial", "todos durante o ataque", "moderada"),
  mitigacao="No laboratório, aceitar o risco; em produção, servir a configuração pública por cache ou CDN e limitar a taxa. "
            "Ref.: ASVS 5.0 2.4.1.",
  tipo="Preventivo", camada="Rede e infraestrutura", decisao="Aceitar")

ameaca(id="T-FX4-06", fx="FX4", elementos=["F19"], stride="I",
  cenario="Um site malicioso visitado por alguém da rede interna pode ler a configuração pelo navegador dessa pessoa, "
          "explorando o cabeçalho Access-Control-Allow-Origin: * enviado por P2, "
          "resultando no vazamento de dados internos mesmo que a aplicação não esteja exposta à Internet.",
  cwe="CWE-942 / A05", status="Observada no T2",
  controle="Nenhum; CORS aberto a qualquer origem.",
  dread=(5, 9, 6, 6, 6),
  just=("expõe dados internos", "repetível a cada visita", "exige atrair a vítima a um site",
        "usuários da rede interna", "o cabeçalho é visível em qualquer resposta"),
  mitigacao="Restringir Access-Control-Allow-Origin a uma lista de origens confiáveis. "
            "Ref.: ASVS 5.0 V3.5 (separação de origem do navegador); HTML5 Security Cheat Sheet (CORS).",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

# ============================== FX5 ==============================
ameaca(id="T-FX5-01", fx="FX5", elementos=["F28", "P2"], stride="T",
  cenario="Um cliente autenticado pode trocar addressId e paymentId no corpo de POST /rest/basket/{bid}/checkout (F28) "
          "pelos ids de endereço e cartão de outro cliente, que são numéricos e sequenciais, "
          "explorando a falta de verificação de propriedade em P2, "
          "resultando em compra cobrada no cartão de terceiros (fraude).",
  cwe="CWE-639 / A01", status="Plausível",
  controle="Exigência de token; ids aceitos como enviados.",
  dread=(8, 9, 8, 8, 7),
  just=("fraude financeira contra terceiros", "repetível", "editar o corpo JSON",
        "todos os clientes com cartão salvo", "os ids aparecem no payload do checkout"),
  mitigacao="Em P2, aceitar apenas endereço e cartão pertencentes ao usuário da sessão. "
            "Ref.: ASVS 5.0 8.2.2 e 2.2.1; Authorization Cheat Sheet; LGPD, art. 46.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX5-02", fx="FX5", elementos=["F21", "P2"], stride="T",
  cenario="Um cliente autenticado pode enviar quantidade negativa em POST /api/BasketItems (F21) ou um cupom forjado em couponData no checkout, "
          "explorando a ausência de validação de regras de negócio em P2, "
          "resultando em total negativo ou desconto indevido e prejuízo financeiro à loja.",
  cwe="CWE-840 / A04", status="Plausível",
  controle="Nenhum observado; a API aceitou cartão inválido, o que indica validação fraca.",
  dread=(8, 9, 7, 10, 6),
  just=("prejuízo financeiro direto", "repetível", "editar o JSON",
        "afeta o negócio como um todo", "exige testar valores fora do esperado"),
  mitigacao="Validar no servidor quantidade (inteiro positivo, limite máximo), preço vindo do catálogo e cupom assinado e verificado. "
            "Ref.: ASVS 5.0 2.2.1; Input Validation Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX5-03", fx="FX5", elementos=["D4"], stride="I",
  cenario="Um usuário anônimo pode listar a pasta /ftp e baixar os PDFs de confirmação de pedidos de todos os clientes, "
          "explorando a listagem de diretório habilitada e a gravação dos PDFs em pasta pública (D4) por P2, "
          "resultando no vazamento de e-mail, itens e valores das compras dos titulares.",
  cwe="CWE-548 / A01", status="Observada no T2",
  controle="Nenhum; listagem e PDF abertos sem autenticação.",
  dread=(7, 10, 10, 9, 9),
  just=("expõe dado pessoal de todos os compradores", "sempre funciona",
        "abrir uma URL no navegador", "todos os clientes que compraram",
        "a listagem é exibida diretamente"),
  mitigacao="Eliminar a gravação dos PDFs em pasta pública: gerar o PDF sob demanda em rota autenticada que verifica o dono do pedido, "
            "e desativar a listagem de diretórios. Ref.: ASVS 5.0 13.4.3, 13.4.7 e 8.2.2; LGPD, arts. 46 e 48.",
  tipo="Preventivo e corretivo", camada="Aplicação", decisao="Eliminar")

ameaca(id="T-FX5-04", fx="FX5", elementos=["D1", "F26"], stride="I",
  cenario="Um atacante que consiga ler D1 (por exemplo, via T-FX1-02) pode obter os números completos dos cartões, "
          "explorando o armazenamento do cardNum sem cifragem e sem tokenização, "
          "resultando em fraude com cartões e vazamento de dados financeiros dos titulares.",
  cwe="CWE-312 / A04", status="Plausível",
  controle="Nenhum observado; o número trafega completo no payload.",
  dread=(9, 6, 5, 9, 4),
  just=("dado financeiro de alto impacto", "depende de obter antes acesso a D1",
        "exige encadear com outra falha", "todos os clientes com cartão salvo",
        "exige acesso ao banco"),
  mitigacao="Transferir o armazenamento do cartão a um gateway de pagamento certificado (tokenização), "
            "guardando localmente só o token e os quatro últimos dígitos. Ref.: ASVS 5.0 8.2.3; "
            "Cryptographic Storage Cheat Sheet; LGPD, art. 46.",
  tipo="Preventivo", camada="Dados", decisao="Transferir")

ameaca(id="T-FX5-05", fx="FX5", elementos=["E1"], stride="S",
  cenario="Um atacante com o token roubado de um cliente pode se passar por ele e finalizar compras com o cartão salvo da vítima, "
          "explorando a ausência de reautenticação ou de confirmação adicional no pagamento, "
          "resultando em compras fraudulentas atribuídas à vítima.",
  cwe="CWE-306 / A07", status="Plausível",
  controle="Exigência de token apenas.",
  dread=(8, 6, 5, 6, 5),
  just=("prejuízo financeiro à vítima", "depende de roubar o token",
        "exige um vetor de roubo", "vítimas cujo token vazou", "requer combinação de falhas"),
  mitigacao="Exigir reautenticação ou segundo fator ao confirmar pagamento com cartão salvo. "
            "Ref.: ASVS 5.0 6.3.3; Transaction Authorization Cheat Sheet.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX5-06", fx="FX5", elementos=["E1", "P2"], stride="R",
  cenario="Um cliente pode contestar uma compra alegando não tê-la feito, "
          "explorando a ausência de registro, em P2, de quem finalizou o pedido, de qual origem e com qual cartão, "
          "resultando na impossibilidade de comprovar a transação.",
  cwe="CWE-778 / A09", status="Confirmada no T1 (V6)",
  controle="O pedido é gravado em D2, sem trilha de auditoria.",
  dread=(6, 8, 7, 7, 4),
  just=("prejuízo em contestações", "vale para toda compra", "basta negar",
        "todos os compradores", "só aparece em disputa"),
  mitigacao="Registrar cada checkout com usuário, IP, data e hora, ids do pedido e do pagamento, em log protegido contra alteração. "
            "Ref.: ASVS 5.0 16.3.3; Logging Cheat Sheet.",
  tipo="Detectivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX5-07", fx="FX5", elementos=["P2", "D4"], stride="D",
  cenario="Um cliente autenticado pode automatizar checkouts em sequência, cada um gravando um PDF em D4 e um pedido em D2 (em memória), "
          "explorando a ausência de limite de taxa e de cota, "
          "resultando no esgotamento de disco e memória do contêiner e na queda da loja.",
  cwe="CWE-400 / A04", status="Plausível",
  controle="Nenhum observado.",
  dread=(6, 9, 7, 9, 5),
  just=("indisponibilidade total", "repetível", "script simples",
        "todos os clientes", "exige observar a gravação dos arquivos"),
  mitigacao="Limitar checkouts por usuário e por intervalo, impor cota de armazenamento e monitorar disco e memória. "
            "Ref.: ASVS 5.0 2.4.1; Denial of Service Cheat Sheet.",
  tipo="Preventivo e detectivo", camada="Aplicação", decisao="Mitigar")

ameaca(id="T-FX5-08", fx="FX5", elementos=["P2", "F28"], stride="E",
  cenario="Um cliente autenticado pode finalizar a cesta de outro cliente trocando o {bid} na URL do checkout (F28), "
          "explorando a falta de verificação de propriedade da cesta em P2, "
          "resultando em pedido criado sobre a cesta alheia.",
  cwe="CWE-285 / A01", status="Plausível",
  controle="Exigência de token apenas.",
  dread=(7, 9, 8, 8, 7),
  just=("pedido indevido em nome de terceiros", "repetível", "trocar um número na URL",
        "todas as cestas", "o bid está na URL"),
  mitigacao="Obter a cesta pela sessão no servidor e ignorar o bid da URL. Ref.: ASVS 5.0 8.2.2 e 8.3.1.",
  tipo="Preventivo", camada="Aplicação", decisao="Mitigar")

for a in A:
    a["media"] = round(sum(a["dread"]) / 5, 1)
    a["risco"] = nivel(a["media"])

# ---------------------------------------------------------------------------
# Matrizes STRIDE por elemento (Secao 7.2)
# Linhas: (rotulo, tipo, {categoria: [ids] ou "N/A: justificativa"})
# ---------------------------------------------------------------------------
LOCAL_NAV = "N/A: interação local no navegador do próprio usuário; não cruza fronteira."
INTERNO = "N/A: comunicação dentro do mesmo contêiner (TB2), sem rede exposta."
TUNEL = "N/A: HTTPS até o túnel; o trecho túnel e contêiner está fora do escopo (C9)."

MATRIZES = {
 "FX1": [
  ("E1 Cliente", "E", {"S": ["T-FX1-01"], "R": ["T-FX1-06"]}),
  ("F01 e-mail e senha", "F", {"T": LOCAL_NAV, "I": LOCAL_NAV, "D": LOCAL_NAV}),
  ("P1 SPA Angular", "P", {"S": "N/A: P1 é servida pela própria aplicação; falsificá-la exige comprometer P2 ou o túnel (fora do escopo).",
                            "T": "N/A: o cliente é não confiável por definição; a adulteração aparece em F02 e F08 (T-FX1-02, T-FX1-03).",
                            "R": "N/A: P1 não registra eventos; o repúdio é tratado em P2 (T-FX1-06).",
                            "I": "N/A: a exposição do token está registrada em D5 (T-FX1-04).",
                            "D": "N/A: a indisponibilidade de P1 afeta só o próprio usuário.",
                            "E": "N/A: P1 não decide autorização; a decisão é de P2."}),
  ("F02, F05, F08, F09 (P1 e P2)", "F", {"T": ["T-FX1-03"], "I": TUNEL, "D": ["T-FX1-07"]}),
  ("P2 API REST", "P", {"S": "N/A: P2 é acessada pela URL do Codespaces com TLS do túnel; falsificar o servidor exige comprometer a infraestrutura.",
                         "T": ["T-FX1-03"], "R": ["T-FX1-06"], "I": ["T-FX1-05"],
                         "D": ["T-FX1-07"], "E": ["T-FX1-02"]}),
  ("F03, F04 (P2 e D1)", "F", {"T": INTERNO, "I": INTERNO, "D": "N/A: a carga chega a D1 por P2 (ver T-FX1-07)."}),
  ("D1 Banco SQLite", "D", {"T": "N/A: alterar D1 exige passar por P2 (ver T-FX1-02).",
                             "I": ["T-FX1-05"], "D": "N/A: ver T-FX1-07."}),
  ("F06, F07 (P1 e D5)", "F", {"T": LOCAL_NAV, "I": LOCAL_NAV, "D": LOCAL_NAV}),
  ("D5 Armazenamento do navegador", "D", {"T": "N/A: alterar o próprio bid é tratado em FX2 (T-FX2-03).",
                                           "I": ["T-FX1-04"],
                                           "D": "N/A: apagar o armazenamento só encerra a sessão do próprio usuário."}),
 ],
 "FX2": [
  ("E1 Cliente", "E", {"S": ["T-FX2-04"], "R": "N/A: o repúdio é tratado em P2 (T-FX2-05)."}),
  ("D5 Armazenamento do navegador", "D", {"T": ["T-FX2-03"], "I": "N/A: ver FX1 (T-FX1-04).",
                                           "D": "N/A: afeta só o próprio usuário."}),
  ("F07 lê token e bid", "F", {"T": ["T-FX2-03"], "I": LOCAL_NAV, "D": LOCAL_NAV}),
  ("P1 SPA Angular", "P", {"S": "N/A: ver FX1.", "T": "N/A: ver D5 e F07 (T-FX2-03).", "R": "N/A: P1 não registra eventos.",
                            "I": "N/A: P1 só exibe a resposta de P2.", "D": "N/A: afeta só o próprio usuário.",
                            "E": "N/A: P1 não decide autorização."}),
  ("F10, F13 (P1 e P2)", "F", {"T": "N/A: a troca do id é registrada como E e I em P2 (T-FX2-01, T-FX2-02).",
                               "I": ["T-FX2-01"], "D": ["T-FX2-06"]}),
  ("P2 API REST", "P", {"S": "N/A: ver FX1.", "T": "N/A: ver T-FX2-02 (alteração de cesta alheia classificada como E).",
                         "R": ["T-FX2-05"], "I": ["T-FX2-01"], "D": ["T-FX2-06"], "E": ["T-FX2-02"]}),
  ("F11, F12 (P2 e D1)", "F", {"T": INTERNO, "I": INTERNO, "D": "N/A: ver T-FX2-06."}),
  ("D1 Banco SQLite", "D", {"T": "N/A: ver T-FX2-02.", "I": "N/A: ver T-FX2-01.", "D": "N/A: ver T-FX2-06."}),
  ("F14 exibição da cesta", "F", {"T": LOCAL_NAV, "I": LOCAL_NAV, "D": LOCAL_NAV}),
 ],
 "FX4": [
  ("E1 Cliente", "E", {"S": "N/A: a rota não autentica ninguém; não há identidade a falsificar (a falta de autenticação é T-FX4-02).",
                        "R": "N/A: o repúdio é tratado em P2 (T-FX4-04)."}),
  ("F15 abre a aplicação", "F", {"T": LOCAL_NAV, "I": LOCAL_NAV, "D": LOCAL_NAV}),
  ("P1 SPA Angular", "P", {"S": "N/A: ver FX1.", "T": "N/A: a SPA apenas consome a configuração.", "R": "N/A: P1 não registra eventos.",
                            "I": "N/A: ver F19 (T-FX4-06).", "D": "N/A: afeta só o próprio usuário.", "E": "N/A: P1 não decide autorização."}),
  ("F16, F19 (P1 e P2)", "F", {"T": TUNEL, "I": ["T-FX4-01", "T-FX4-06"], "D": ["T-FX4-05"]}),
  ("P2 API REST", "P", {"S": "N/A: ver FX1.", "T": "N/A: a alteração da configuração ocorre em D3 (T-FX4-03).",
                         "R": ["T-FX4-04"], "I": ["T-FX4-01"], "D": ["T-FX4-05"], "E": ["T-FX4-02"]}),
  ("F17, F18 (P2 e D3)", "F", {"T": INTERNO, "I": INTERNO, "D": INTERNO}),
  ("D3 Configuração da aplicação", "D", {"T": ["T-FX4-03"], "I": "N/A: a exposição ocorre pela rota (T-FX4-01).",
                                          "D": "N/A: arquivos lidos só na inicialização."}),
 ],
 "FX5": [
  ("E1 Cliente", "E", {"S": ["T-FX5-05"], "R": ["T-FX5-06"]}),
  ("F20 dados da compra", "F", {"T": LOCAL_NAV, "I": LOCAL_NAV, "D": LOCAL_NAV}),
  ("D5 e F07 (token e bid)", "D", {"T": "N/A: ver FX2 (T-FX2-03).", "I": "N/A: ver FX1 (T-FX1-04).", "D": "N/A: afeta só o próprio usuário."}),
  ("P1 SPA Angular", "P", {"S": "N/A: ver FX1.", "T": "N/A: adulterações aparecem nos fluxos F21 e F28.", "R": "N/A: P1 não registra eventos.",
                            "I": "N/A: P1 só exibe dados do próprio usuário.", "D": "N/A: afeta só o próprio usuário.",
                            "E": "N/A: P1 não decide autorização."}),
  ("F21, F23, F25, F26, F28, F32 (requisições)", "F", {"T": ["T-FX5-01", "T-FX5-02"], "I": TUNEL, "D": ["T-FX5-07"]}),
  ("F10, F13, F31, F34 (respostas)", "F", {"T": TUNEL, "I": TUNEL, "D": "N/A: ver T-FX5-07."}),
  ("P2 API REST", "P", {"S": "N/A: ver FX1.", "T": ["T-FX5-01", "T-FX5-02"], "R": ["T-FX5-06"],
                         "I": "N/A: a exposição ocorre nos armazenamentos (T-FX5-03, T-FX5-04).",
                         "D": ["T-FX5-07"], "E": ["T-FX5-08"]}),
  ("F11, F12, F22, F24, F27 (P2 e D1)", "F", {"T": INTERNO, "I": INTERNO, "D": INTERNO}),
  ("D1 Banco SQLite", "D", {"T": "N/A: alterar D1 exige passar por P2 (T-FX5-01, T-FX5-02).", "I": ["T-FX5-04"],
                             "D": "N/A: ver T-FX5-07."}),
  ("F29, F33 (P2 e D2)", "F", {"T": INTERNO, "I": INTERNO, "D": INTERNO}),
  ("D2 MarsDB", "D", {"T": "N/A: gravação só por P2.", "I": "N/A: a leitura de pedidos alheios por id é análoga a T-FX5-03.",
                       "D": ["T-FX5-07"]}),
  ("F30 grava PDF", "F", {"T": INTERNO, "I": INTERNO, "D": "N/A: ver D4 (T-FX5-07)."}),
  ("D4 Pasta pública ftp/", "D", {"T": "N/A: gravação só por P2.", "I": ["T-FX5-03"], "D": ["T-FX5-07"]}),
  ("F35 confirmação", "F", {"T": LOCAL_NAV, "I": LOCAL_NAV, "D": LOCAL_NAV}),
 ],
}


# ---------------------------------------------------------------------------
# Validacao das regras do roteiro
# ---------------------------------------------------------------------------
def tipo_do(eid):
    return "F" if eid.startswith("F") else ELEMENTOS[eid]["tipo"]


def validar():
    erros = []
    ids = [a["id"] for a in A]
    if len(ids) != len(set(ids)):
        erros.append("IDs de ameaça repetidos")
    fids = {f["id"] for f in FLUXOS_DADOS}
    for a in A:
        if not a["status"].startswith(STATUS):
            erros.append(f"{a['id']}: status fora da lista")
        if len(a["dread"]) != 5 or not all(1 <= n <= 10 for n in a["dread"]) or len(a["just"]) != 5:
            erros.append(f"{a['id']}: DREAD precisa de 5 notas de 1 a 10 e 5 justificativas")
        ok_cat = False
        for el in a["elementos"]:
            if el.startswith("F") and el not in fids:
                erros.append(f"{a['id']}: fluxo {el} inexistente")
            if not el.startswith("F") and el not in ELEMENTOS:
                erros.append(f"{a['id']}: elemento {el} inexistente")
            if a["stride"] in APLICAVEL[tipo_do(el)]:
                ok_cat = True
        if not ok_cat:
            erros.append(f"{a['id']}: categoria {a['stride']} não se aplica a nenhum dos elementos {a['elementos']}")
        if "explorando" not in a["cenario"] or "resultando" not in a["cenario"]:
            erros.append(f"{a['id']}: cenário fora do formato padrão (Seção 6.4)")
        if "Ref.:" not in a["mitigacao"]:
            erros.append(f"{a['id']}: mitigação sem referência")
    for fx in FLUXOS:
        do_fx = [a for a in A if a["fx"] == fx]
        if len(do_fx) < 6:
            erros.append(f"{fx}: menos de 6 ameaças")
        cats = {a["stride"] for a in do_fx}
        faltam = set(STRIDE) - cats
        # categoria ausente precisa estar justificada na matriz (linhas E ou P com N/A)
        for c in faltam:
            just = any(isinstance(v.get(c), str) for (_, t, v) in MATRIZES[fx] if c in v)
            if not just:
                erros.append(f"{fx}: categoria {c} sem ameaça e sem justificativa")
        citadas = set()
        for rot, t, cel in MATRIZES[fx]:
            for c in APLICAVEL[t]:
                if c == "R" and t == "D":
                    continue
                if c not in cel:
                    erros.append(f"{fx} / {rot}: célula {c} sem ameaça nem N/A")
            for c, v in cel.items():
                if c not in APLICAVEL[t]:
                    erros.append(f"{fx} / {rot}: categoria {c} não se aplica ao tipo {t}")
                if isinstance(v, list):
                    citadas.update(v)
                    for tid in v:
                        if not any(a["id"] == tid for a in A):
                            erros.append(f"{fx} / {rot}: ameaça {tid} inexistente")
                elif not v.startswith("N/A:"):
                    erros.append(f"{fx} / {rot}: célula {c} sem ID nem N/A")
        for a in do_fx:
            if a["id"] not in citadas:
                erros.append(f"{a['id']}: não aparece na matriz do {fx}")
    return erros


def top10():
    return sorted(A, key=lambda a: (-a["media"], -a["dread"][0], a["id"]))[:10]


def fmt(n):
    return f"{n:.1f}".replace(".", ",")


def gerar_md():
    L = ["# Análise STRIDE dos fluxos: OWASP Juice Shop", "", "Gerado por `analise.py`.", ""]
    for fx, nome in FLUXOS.items():
        fi = FICHAS[fx]
        L += [f"## {fx}: {nome}", "", f"**Descrição:** {fi['descricao']}", "",
              f"**Ator e gatilho:** {fi['ator']}  ", f"**Pré-condições:** {fi['precondicoes']}  ",
              f"**Resultado esperado:** {fi['resultado']}", "", "**Requisições observadas:** " + "; ".join(fi["requisicoes"]), "",
              "### Matriz STRIDE por elemento", "", "| Elemento | S | T | R | I | D | E |", "|---|---|---|---|---|---|---|"]
        for rot, t, cel in MATRIZES[fx]:
            linha = [rot]
            for c in STRIDE:
                v = cel.get(c, "")
                linha.append(", ".join(v) if isinstance(v, list) else ("N/A" if v else ""))
            L.append("| " + " | ".join(linha) + " |")
        L += ["", "### Registro de ameaças", "", "| ID | Elem. | STRIDE | Cenário | CWE / OWASP | Status | D | R | E | A | D | Média | Risco | Decisão |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for a in [x for x in A if x["fx"] == fx]:
            d = a["dread"]
            L.append(f"| {a['id']} | {', '.join(a['elementos'])} | {a['stride']} | {a['cenario']} | {a['cwe']} | {a['status']} | "
                     f"{d[0]} | {d[1]} | {d[2]} | {d[3]} | {d[4]} | {fmt(a['media'])} | {a['risco']} | {a['decisao']} |")
        L.append("")
    L += ["## Top 10", "", "| # | ID | STRIDE | Média | Risco | Decisão |", "|---|---|---|---|---|---|"]
    for i, a in enumerate(top10(), 1):
        L.append(f"| {i} | {a['id']} | {a['stride']} | {fmt(a['media'])} | {a['risco']} | {a['decisao']} |")
    L += ["", "## Distribuição por categoria STRIDE", "", "| Categoria | Quantidade |", "|---|---|"]
    for c in STRIDE:
        L.append(f"| {c} {NOME_STRIDE[c]} | {sum(1 for a in A if a['stride'] == c)} |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    erros = validar()
    if erros:
        print("Erros de validação da análise:")
        print("\n".join(erros))
        sys.exit(1)
    os.makedirs("saida", exist_ok=True)
    with open("saida/analise_fluxos.md", "w", encoding="utf-8") as fh:
        fh.write(gerar_md())
    with open("saida/registro_ameacas.json", "w", encoding="utf-8") as fh:
        json.dump({"fichas": FICHAS, "ameacas": A, "matrizes": MATRIZES,
                   "top10": [a["id"] for a in top10()]}, fh, ensure_ascii=False, indent=2)
    altos = sum(1 for a in A if a["risco"] == "Alto")
    print(f"Validação da análise: OK. {len(A)} ameaças em {len(FLUXOS)} fluxos ({altos} de risco alto).")
    for fx in FLUXOS:
        do_fx = [a for a in A if a["fx"] == fx]
        print(f"  {fx}: {len(do_fx)} ameaças, categorias {''.join(sorted({a['stride'] for a in do_fx}, key=STRIDE.index))}")
    print("Top 10: " + ", ".join(f"{a['id']} ({fmt(a['media'])})" for a in top10()))
