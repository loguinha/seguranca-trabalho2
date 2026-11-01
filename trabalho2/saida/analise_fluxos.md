# Análise STRIDE dos fluxos: OWASP Juice Shop

Gerado por `analise.py`.

## FX1: Login com e-mail e senha, emissão e uso do token

**Descrição:** O cliente informa e-mail e senha na SPA (P1), que envia POST /rest/user/login à API (P2). P2 consulta a tabela Users em D1 e, se a combinação existir, emite um JWT assinado em RS256 e devolve também o identificador da cesta (bid) e o e-mail. P1 guarda token e bid no navegador (D5) e passa a enviar o token no cabeçalho Authorization em cada chamada, como em GET /rest/user/whoami.

**Ator e gatilho:** E1 Cliente (ainda anônimo), ao clicar em Log in.  
**Pré-condições:** Conta cadastrada; aplicação acessível pelo encaminhamento de portas do Codespaces.  
**Resultado esperado:** Sessão ativa no navegador: o menu da conta exibe o e-mail e as chamadas com o token são aceitas.

**Requisições observadas:** POST /rest/user/login (200 OK); GET /rest/user/whoami (200 OK)

### Matriz STRIDE por elemento

| Elemento | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| E1 Cliente | T-FX1-01 |  | T-FX1-06 |  |  |  |
| F01 e-mail e senha |  | N/A |  | N/A | N/A |  |
| P1 SPA Angular | N/A | N/A | N/A | N/A | N/A | N/A |
| F02, F05, F08, F09 (P1 e P2) |  | T-FX1-03 |  | N/A | T-FX1-07 |  |
| P2 API REST | N/A | T-FX1-03 | T-FX1-06 | T-FX1-05 | T-FX1-07 | T-FX1-02 |
| F03, F04 (P2 e D1) |  | N/A |  | N/A | N/A |  |
| D1 Banco SQLite |  | N/A |  | T-FX1-05 | N/A |  |
| F06, F07 (P1 e D5) |  | N/A |  | N/A | N/A |  |
| D5 Armazenamento do navegador |  | N/A |  | T-FX1-04 | N/A |  |

### Registro de ameaças

| ID | Elem. | STRIDE | Cenário | CWE / OWASP | Status | D | R | E | A | D | Média | Risco | Decisão |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T-FX1-01 | E1, F02 | S | Um atacante anônimo com uma lista de senhas vazadas pode se passar por qualquer cliente, inclusive o administrador, enviando tentativas em massa no fluxo F02, explorando a ausência de limite de tentativas, bloqueio e MFA na aplicação, resultando no sequestro de contas e na exposição dos dados pessoais dos titulares. | CWE-307 / A07 | Confirmada no T1 (V5) | 8 | 9 | 7 | 8 | 8 | 8,0 | Alto | Mitigar |
| T-FX1-02 | P2, F02 | E | Um atacante anônimo pode obter a sessão do administrador enviando ' OR 1=1-- no campo e-mail do fluxo F02, explorando a concatenação da entrada na consulta SQL que P2 envia a D1 (F03), resultando em acesso administrativo sem credenciais e em acesso aos dados de todos os titulares. | CWE-89 / A03 | Confirmada no T1 (V1) e observada no T2 | 10 | 10 | 9 | 10 | 8 | 9,4 | Alto | Mitigar |
| T-FX1-03 | F08, P2 | T | Um usuário autenticado pode alterar o conteúdo do seu JWT (por exemplo, o e-mail ou o papel) e reassiná-lo com HS256 usando a chave pública RSA como segredo, enviando-o no fluxo F08, explorando as versões antigas de jsonwebtoken (0.4.0) e express-jwt (0.1.3) usadas por P2, que não restringem o algoritmo aceito (confusão de algoritmo, CVE-2015-9235), resultando em um token forjado aceito como de outro usuário. | CWE-347 / A02 | Plausível | 9 | 8 | 5 | 10 | 6 | 7,6 | Alto | Mitigar |
| T-FX1-04 | D5 | I | Um script malicioso injetado na página (por exemplo, por XSS) pode ler o token guardado em D5, explorando o armazenamento em localStorage e em cookie sem HttpOnly e sem Secure gravado pelo próprio JavaScript de P1, resultando no sequestro da sessão e no acesso aos dados pessoais da vítima. | CWE-1004 / A05 | Confirmada no T1 (V3) | 8 | 7 | 5 | 7 | 7 | 6,8 | Médio | Mitigar |
| T-FX1-05 | D1, P2 | I | Um atacante que obtenha os registros de Users (por exemplo, via T-FX1-02) ou um token de outro usuário pode recuperar senhas em texto claro, explorando o armazenamento em MD5 sem sal em D1 e a cópia do registro do usuário no payload do JWT emitido por P2, resultando no comprometimento das contas e de outras contas em que os titulares reutilizam a senha. | CWE-916 / A02 | Plausível | 8 | 6 | 6 | 9 | 5 | 6,8 | Médio | Mitigar |
| T-FX1-06 | E1, P2 | R | Um cliente, ou quem tenha usado a conta dele, pode negar ter feito um login ou uma ação autenticada em P2, explorando a ausência de registro das tentativas de login (resultado, data, hora e origem) e o logout que apenas apaga o token no navegador sem invalidá-lo no servidor, resultando na impossibilidade de apurar incidentes e de atribuir ações ao titular. | CWE-778 / A09 | Confirmada no T1 (V6) | 5 | 9 | 7 | 8 | 4 | 6,6 | Médio | Mitigar |
| T-FX1-07 | F02, P2 | D | Um atacante anônimo pode enviar milhares de requisições ao fluxo F02, cada uma gerando uma consulta em D1, explorando a ausência de limite de taxa na aplicação, que roda em um único processo Node.js, resultando em lentidão ou indisponibilidade do login para todos os clientes. | CWE-770 / A04 | Plausível | 5 | 8 | 8 | 9 | 6 | 7,2 | Alto | Mitigar |

## FX2: Visualização da cesta por identificador

**Descrição:** Com a sessão ativa, P1 lê o bid em D5 e chama GET /rest/basket/{bid} com o token. P2 busca a cesta e seus produtos em D1 e devolve o JSON exibido ao cliente. O identificador da cesta é numérico e sequencial.

**Ator e gatilho:** E1 Cliente autenticado, ao abrir Your Basket ou ao carregar a loja já logado.  
**Pré-condições:** Sessão válida (token JWT) e bid gravado no navegador.  
**Resultado esperado:** A cesta do usuário é exibida com produtos e quantidades.

**Requisições observadas:** GET /rest/basket/1 (304 Not Modified, respondida do cache após a primeira carga)

### Matriz STRIDE por elemento

| Elemento | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| E1 Cliente | T-FX2-04 |  | N/A |  |  |  |
| D5 Armazenamento do navegador |  | T-FX2-03 |  | N/A | N/A |  |
| F07 lê token e bid |  | T-FX2-03 |  | N/A | N/A |  |
| P1 SPA Angular | N/A | N/A | N/A | N/A | N/A | N/A |
| F10, F13 (P1 e P2) |  | N/A |  | T-FX2-01 | T-FX2-06 |  |
| P2 API REST | N/A | N/A | T-FX2-05 | T-FX2-01 | T-FX2-06 | T-FX2-02 |
| F11, F12 (P2 e D1) |  | N/A |  | N/A | N/A |  |
| D1 Banco SQLite |  | N/A |  | N/A | N/A |  |
| F14 exibição da cesta |  | N/A |  | N/A | N/A |  |

### Registro de ameaças

| ID | Elem. | STRIDE | Cenário | CWE / OWASP | Status | D | R | E | A | D | Média | Risco | Decisão |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T-FX2-01 | P2, F13 | I | Um cliente autenticado pode ver a cesta de qualquer outro cliente trocando o número na requisição GET /rest/basket/{bid} (F10), explorando a falta de verificação de propriedade em P2, resultando na exposição dos hábitos de consumo de terceiros. | CWE-639 / A01 | Confirmada no T1 (V2) | 6 | 10 | 9 | 9 | 9 | 8,6 | Alto | Mitigar |
| T-FX2-02 | P2 | E | Um cliente autenticado pode agir sobre a cesta de outro cliente, adicionando ou removendo itens com o BasketId alheio, explorando o fato de P2 verificar apenas se há sessão, e não se o recurso pertence a quem a apresenta, resultando em escalonamento horizontal de privilégio e na alteração de dados de terceiros. | CWE-285 / A01 | Plausível | 7 | 9 | 8 | 9 | 7 | 8,0 | Alto | Mitigar |
| T-FX2-03 | D5, F07 | T | Um cliente pode alterar o bid guardado no sessionStorage (D5), que P1 lê no fluxo F07 e repassa a P2, explorando a confiança da aplicação em um identificador controlado pelo cliente, resultando no acesso às cestas de terceiros pela própria interface, sem ferramenta. | CWE-602 / A04 | Plausível | 4 | 10 | 9 | 8 | 7 | 7,6 | Alto | Mitigar |
| T-FX2-04 | E1 | S | Um atacante que tenha obtido o token de um cliente (por exemplo, via T-FX1-04) pode se passar por ele e consultar a cesta e os dados da conta, explorando a validade do token mesmo após o logout, resultando no acesso aos dados pessoais da vítima. | CWE-294 / A07 | Plausível | 7 | 6 | 5 | 6 | 5 | 5,8 | Médio | Mitigar |
| T-FX2-05 | P2 | R | Um cliente pode negar ter acessado a cesta de outro cliente em P2, explorando a ausência de registro dos acessos a objetos de terceiros e dos acessos negados, resultando na impossibilidade de detectar e comprovar a enumeração de cestas. | CWE-778 / A09 | Confirmada no T1 (V6) | 4 | 9 | 8 | 8 | 4 | 6,6 | Médio | Mitigar |
| T-FX2-06 | P2, F10 | D | Um cliente autenticado pode enumerar automaticamente /rest/basket/1 a N, cada chamada gerando consulta com junção de produtos em D1, explorando a ausência de limite de taxa e os ids sequenciais, resultando em sobrecarga de P2 e D1 e lentidão para todos os clientes. | CWE-799 / A04 | Plausível | 4 | 9 | 8 | 7 | 6 | 6,8 | Médio | Mitigar |

## FX4: Leitura da configuração administrativa

**Descrição:** Ao abrir a aplicação, P1 requisita GET /rest/admin/application-configuration para montar a interface. P2 lê os parâmetros de D3 e devolve a configuração completa, cerca de 36 kB de JSON, sem exigir token, embora a rota esteja no espaço /rest/admin.

**Ator e gatilho:** E1 Cliente anônimo, no carregamento da página.  
**Pré-condições:** Nenhuma.  
**Resultado esperado:** Interface configurada; a configuração completa fica disponível a qualquer consumidor.

**Requisições observadas:** GET /rest/admin/application-configuration (304 no navegador; 200 OK via curl anônimo, 36.154 bytes)

### Matriz STRIDE por elemento

| Elemento | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| E1 Cliente | N/A |  | N/A |  |  |  |
| F15 abre a aplicação |  | N/A |  | N/A | N/A |  |
| P1 SPA Angular | N/A | N/A | N/A | N/A | N/A | N/A |
| F16, F19 (P1 e P2) |  | N/A |  | T-FX4-01, T-FX4-06 | T-FX4-05 |  |
| P2 API REST | N/A | N/A | T-FX4-04 | T-FX4-01 | T-FX4-05 | T-FX4-02 |
| F17, F18 (P2 e D3) |  | N/A |  | N/A | N/A |  |
| D3 Configuração da aplicação |  | T-FX4-03 |  | N/A | N/A |  |

### Registro de ameaças

| ID | Elem. | STRIDE | Cenário | CWE / OWASP | Status | D | R | E | A | D | Média | Risco | Decisão |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T-FX4-01 | P2, F19 | I | Um usuário anônimo pode obter a configuração completa da aplicação chamando GET /rest/admin/application-configuration (F16), explorando a ausência de autenticação na rota, resultando na exposição de parâmetros internos (pelo código-fonte do projeto, inclusive os do login com Google) que facilitam ataques direcionados. | CWE-200 / A01 | Observada no T2 | 5 | 10 | 10 | 6 | 8 | 7,8 | Alto | Mitigar |
| T-FX4-02 | P2 | E | Um usuário anônimo pode executar funções do espaço /rest/admin, que deveriam ser exclusivas do administrador, explorando a ausência de verificação de papel por função em P2, resultando no uso de funções administrativas sem autenticação. | CWE-862 / A01 | Observada no T2 | 5 | 10 | 10 | 6 | 7 | 7,6 | Alto | Mitigar |
| T-FX4-03 | D3 | T | Um atacante que consiga gravar arquivos no contêiner, por exemplo por travessia de caminho no envio de arquivos compactados em outra funcionalidade da loja, pode alterar os arquivos YAML de D3, explorando a gravação com o mesmo usuário que executa a aplicação, resultando em configuração adulterada servida a todos os clientes após o reinício. | CWE-22 / A01 | Plausível | 7 | 4 | 3 | 9 | 3 | 5,2 | Médio | Mitigar |
| T-FX4-04 | P2 | R | Um agente anônimo pode coletar a configuração repetidamente sem deixar rastro em P2, explorando a ausência de registro dos acessos às rotas /rest/admin, resultando na impossibilidade de detectar a fase de reconhecimento de um ataque. | CWE-778 / A09 | Confirmada no T1 (V6) | 3 | 10 | 10 | 5 | 4 | 6,4 | Médio | Mitigar |
| T-FX4-05 | F19, P2 | D | Um atacante anônimo pode solicitar repetidamente a configuração de cerca de 36 kB, explorando a ausência de limite de taxa e de autenticação, resultando em consumo de banda e processamento de P2 que degrada o serviço. | CWE-770 / A04 | Plausível | 3 | 10 | 9 | 6 | 5 | 6,6 | Médio | Aceitar |
| T-FX4-06 | F19 | I | Um site malicioso visitado por alguém da rede interna pode ler a configuração pelo navegador dessa pessoa, explorando o cabeçalho Access-Control-Allow-Origin: * enviado por P2, resultando no vazamento de dados internos mesmo que a aplicação não esteja exposta à Internet. | CWE-942 / A05 | Observada no T2 | 5 | 9 | 6 | 6 | 6 | 6,4 | Médio | Mitigar |

## FX5: Checkout: endereço, pagamento e registro do pedido

**Descrição:** O cliente autenticado adiciona um produto (POST /api/BasketItems), cadastra endereço (POST /api/Addresss) e cartão (POST /api/Cards), escolhe a entrega (GET /api/Deliverys) e finaliza com POST /rest/basket/{bid}/checkout, enviando os IDs de endereço, pagamento e entrega. P2 registra o pedido em D2, grava o PDF de confirmação na pasta pública ftp/ (D4) e devolve o id do pedido, exibido via GET /rest/track-order/{id}.

**Ator e gatilho:** E1 Cliente autenticado, ao clicar em Checkout.  
**Pré-condições:** Sessão válida e cesta com ao menos um item.  
**Resultado esperado:** Pedido registrado, PDF gerado e tela de confirmação exibida.

**Requisições observadas:** POST /api/BasketItems/ (200 OK); POST /api/Addresss/ (201 Created); GET /api/Deliverys (304); POST /api/Cards/ (201 Created); POST /rest/basket/6/checkout (200 OK); GET /rest/track-order/{id} (200 OK); GET /ftp e GET /ftp/order_{id}.pdf (listagem e PDF acessíveis)

### Matriz STRIDE por elemento

| Elemento | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| E1 Cliente | T-FX5-05 |  | T-FX5-06 |  |  |  |
| F20 dados da compra |  | N/A |  | N/A | N/A |  |
| D5 e F07 (token e bid) |  | N/A |  | N/A | N/A |  |
| P1 SPA Angular | N/A | N/A | N/A | N/A | N/A | N/A |
| F21, F23, F25, F26, F28, F32 (requisições) |  | T-FX5-01, T-FX5-02 |  | N/A | T-FX5-07 |  |
| F10, F13, F31, F34 (respostas) |  | N/A |  | N/A | N/A |  |
| P2 API REST | N/A | T-FX5-01, T-FX5-02 | T-FX5-06 | N/A | T-FX5-07 | T-FX5-08 |
| F11, F12, F22, F24, F27 (P2 e D1) |  | N/A |  | N/A | N/A |  |
| D1 Banco SQLite |  | N/A |  | T-FX5-04 | N/A |  |
| F29, F33 (P2 e D2) |  | N/A |  | N/A | N/A |  |
| D2 MarsDB |  | N/A |  | N/A | T-FX5-07 |  |
| F30 grava PDF |  | N/A |  | N/A | N/A |  |
| D4 Pasta pública ftp/ |  | N/A |  | T-FX5-03 | T-FX5-07 |  |
| F35 confirmação |  | N/A |  | N/A | N/A |  |

### Registro de ameaças

| ID | Elem. | STRIDE | Cenário | CWE / OWASP | Status | D | R | E | A | D | Média | Risco | Decisão |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T-FX5-01 | F28, P2 | T | Um cliente autenticado pode trocar addressId e paymentId no corpo de POST /rest/basket/{bid}/checkout (F28) pelos ids de endereço e cartão de outro cliente, que são numéricos e sequenciais, explorando a falta de verificação de propriedade em P2, resultando em compra cobrada no cartão de terceiros (fraude). | CWE-639 / A01 | Plausível | 8 | 9 | 8 | 8 | 7 | 8,0 | Alto | Mitigar |
| T-FX5-02 | F21, P2 | T | Um cliente autenticado pode enviar quantidade negativa em POST /api/BasketItems (F21) ou um cupom forjado em couponData no checkout, explorando a ausência de validação de regras de negócio em P2, resultando em total negativo ou desconto indevido e prejuízo financeiro à loja. | CWE-840 / A04 | Plausível | 8 | 9 | 7 | 10 | 6 | 8,0 | Alto | Mitigar |
| T-FX5-03 | D4 | I | Um usuário anônimo pode listar a pasta /ftp e baixar os PDFs de confirmação de pedidos de todos os clientes, explorando a listagem de diretório habilitada e a gravação dos PDFs em pasta pública (D4) por P2, resultando no vazamento de e-mail, itens e valores das compras dos titulares. | CWE-548 / A01 | Observada no T2 | 7 | 10 | 10 | 9 | 9 | 9,0 | Alto | Eliminar |
| T-FX5-04 | D1, F26 | I | Um atacante que consiga ler D1 (por exemplo, via T-FX1-02) pode obter os números completos dos cartões, explorando o armazenamento do cardNum sem cifragem e sem tokenização, resultando em fraude com cartões e vazamento de dados financeiros dos titulares. | CWE-312 / A04 | Plausível | 9 | 6 | 5 | 9 | 4 | 6,6 | Médio | Transferir |
| T-FX5-05 | E1 | S | Um atacante com o token roubado de um cliente pode se passar por ele e finalizar compras com o cartão salvo da vítima, explorando a ausência de reautenticação ou de confirmação adicional no pagamento, resultando em compras fraudulentas atribuídas à vítima. | CWE-306 / A07 | Plausível | 8 | 6 | 5 | 6 | 5 | 6,0 | Médio | Mitigar |
| T-FX5-06 | E1, P2 | R | Um cliente pode contestar uma compra alegando não tê-la feito, explorando a ausência de registro, em P2, de quem finalizou o pedido, de qual origem e com qual cartão, resultando na impossibilidade de comprovar a transação. | CWE-778 / A09 | Confirmada no T1 (V6) | 6 | 8 | 7 | 7 | 4 | 6,4 | Médio | Mitigar |
| T-FX5-07 | P2, D4 | D | Um cliente autenticado pode automatizar checkouts em sequência, cada um gravando um PDF em D4 e um pedido em D2 (em memória), explorando a ausência de limite de taxa e de cota, resultando no esgotamento de disco e memória do contêiner e na queda da loja. | CWE-400 / A04 | Plausível | 6 | 9 | 7 | 9 | 5 | 7,2 | Alto | Mitigar |
| T-FX5-08 | P2, F28 | E | Um cliente autenticado pode finalizar a cesta de outro cliente trocando o {bid} na URL do checkout (F28), explorando a falta de verificação de propriedade da cesta em P2, resultando em pedido criado sobre a cesta alheia. | CWE-285 / A01 | Plausível | 7 | 9 | 8 | 8 | 7 | 7,8 | Alto | Mitigar |

## Top 10

| # | ID | STRIDE | Média | Risco | Decisão |
|---|---|---|---|---|---|
| 1 | T-FX1-02 | E | 9,4 | Alto | Mitigar |
| 2 | T-FX5-03 | I | 9,0 | Alto | Eliminar |
| 3 | T-FX2-01 | I | 8,6 | Alto | Mitigar |
| 4 | T-FX1-01 | S | 8,0 | Alto | Mitigar |
| 5 | T-FX5-01 | T | 8,0 | Alto | Mitigar |
| 6 | T-FX5-02 | T | 8,0 | Alto | Mitigar |
| 7 | T-FX2-02 | E | 8,0 | Alto | Mitigar |
| 8 | T-FX5-08 | E | 7,8 | Alto | Mitigar |
| 9 | T-FX4-01 | I | 7,8 | Alto | Mitigar |
| 10 | T-FX1-03 | T | 7,6 | Alto | Mitigar |

## Distribuição por categoria STRIDE

| Categoria | Quantidade |
|---|---|
| S Spoofing | 3 |
| T Tampering | 5 |
| R Repudiation | 4 |
| I Information Disclosure | 7 |
| D Denial of Service | 4 |
| E Elevation of Privilege | 4 |
