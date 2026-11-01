# Inventário do modelo de ameaças: OWASP Juice Shop

Gerado automaticamente por `modelo_ameacas.py`. Não editar à mão.

## Elementos

| ID | Tipo | Nome | Tecnologia | Descrição | Zona |
|---|---|---|---|---|---|
| E1 | Entidade externa | Cliente | Pessoa no navegador | Usuário anônimo ou autenticado da loja. | Internet: navegador do usuário (zona não confiável) |
| E2 | Entidade externa | Administrador | Pessoa no navegador | Usuário com papel admin. | Internet: navegador do usuário (zona não confiável) |
| E3 | Entidade externa | Google OAuth 2.0 | Provedor de identidade externo | Login federado com conta Google. | Terceiro: Google |
| P1 | Processo | SPA Angular | Angular (TypeScript), executa no navegador | Interface da loja; monta as requisições à API. | Internet: navegador do usuário (zona não confiável) |
| P2 | Processo | API REST | Node.js + Express (rotas /rest e /api) | Regras de negócio, autenticação e acesso aos dados. | Contêiner Docker juiceshop (Node.js, porta 3000) |
| P3 | Processo | Notificações WebSocket | Socket.IO | Envia notificações em tempo real ao navegador. | Contêiner Docker juiceshop (Node.js, porta 3000) |
| D1 | Armazenamento de dados | Banco SQLite | SQLite via ORM Sequelize | Users, Baskets, BasketItems, Addresses, Cards, Products. | Contêiner Docker juiceshop (Node.js, porta 3000) |
| D2 | Armazenamento de dados | MarsDB | Banco em memória compatível com MongoDB | Pedidos (orders) e avaliações. | Contêiner Docker juiceshop (Node.js, porta 3000) |
| D3 | Armazenamento de dados | Configuração da aplicação | Arquivos YAML em config/ | Parâmetros da loja, servida por /rest/admin/application-configuration. | Contêiner Docker juiceshop (Node.js, porta 3000) |
| D4 | Armazenamento de dados | Pasta pública ftp/ | Sistema de arquivos do contêiner | PDFs de confirmação de pedido. | Contêiner Docker juiceshop (Node.js, porta 3000) |
| D5 | Armazenamento de dados | Armazenamento do navegador | localStorage, sessionStorage e cookies | Guarda o token JWT e o identificador da cesta (bid). | Internet: navegador do usuário (zona não confiável) |

## Fronteiras de confiança

| ID | Descrição |
|---|---|
| TB1 | Internet \| infraestrutura do Codespaces. O TLS termina no túnel da Microsoft. |
| TB2 | Túnel e VM \| contêiner da aplicação. Daqui em diante o tráfego é HTTP e a aplicação processa os dados. |
| TB3 | Aplicação \| terceiro (Google OAuth 2.0). |

## Fluxos de dados

| ID | Origem | Destino | Dados | Protocolo / formato | Fronteira | Fluxos |
|---|---|---|---|---|---|---|
| F01 | E1 | P1 | e-mail e senha | formulário | nenhuma | FX1 |
| F02 | P1 | P2 | POST /rest/user/login {email, password} | HTTPS/JSON | TB1, TB2 | FX1 |
| F03 | P2 | D1 | consulta SQL em Users (senha em hash MD5) | driver SQLite | nenhuma | FX1 |
| F04 | D1 | P2 | registro do usuário | driver SQLite | nenhuma | FX1 |
| F05 | P2 | P1 | token JWT (RS256), bid, umail | HTTPS/JSON | TB1, TB2 | FX1 |
| F06 | P1 | D5 | grava token e bid | API do navegador | nenhuma | FX1 |
| F07 | D5 | P1 | lê token e bid | API do navegador | nenhuma | FX1, FX2, FX5 |
| F08 | P1 | P2 | GET /rest/user/whoami (Bearer JWT) | HTTPS/JSON | TB1, TB2 | FX1 |
| F09 | P2 | P1 | dados do usuário autenticado | HTTPS/JSON | TB1, TB2 | FX1 |
| F10 | P1 | P2 | GET /rest/basket/{bid} (Bearer JWT) | HTTPS/JSON | TB1, TB2 | FX2, FX5 |
| F11 | P2 | D1 | consulta da cesta pelo id | driver SQLite | nenhuma | FX2, FX5 |
| F12 | D1 | P2 | cesta e itens | driver SQLite | nenhuma | FX2, FX5 |
| F13 | P2 | P1 | cesta, produtos e quantidades | HTTPS/JSON | TB1, TB2 | FX2, FX5 |
| F14 | P1 | E1 | exibição da cesta | interface | nenhuma | FX2 |
| F15 | E1 | P1 | abre a aplicação (sem login) | navegador | nenhuma | FX4 |
| F16 | P1 | P2 | GET /rest/admin/application-configuration (sem token) | HTTPS/JSON | TB1, TB2 | FX4 |
| F17 | P2 | D3 | leitura da configuração | sistema de arquivos | nenhuma | FX4 |
| F18 | D3 | P2 | parâmetros da aplicação | sistema de arquivos | nenhuma | FX4 |
| F19 | P2 | P1 | configuração completa (JSON, cerca de 36 kB) | HTTPS/JSON | TB1, TB2 | FX4 |
| F20 | E1 | P1 | produto, endereço, entrega e cartão | formulário | nenhuma | FX5 |
| F21 | P1 | P2 | POST /api/BasketItems {BasketId, ProductId, quantity} | HTTPS/JSON | TB1, TB2 | FX5 |
| F22 | P2 | D1 | insere item na cesta | driver SQLite | nenhuma | FX5 |
| F23 | P1 | P2 | POST /api/Addresss {fullName, mobileNum, endereço, zipCode} | HTTPS/JSON | TB1, TB2 | FX5 |
| F24 | P2 | D1 | grava endereço | driver SQLite | nenhuma | FX5 |
| F25 | P1 | P2 | GET /api/Deliverys | HTTPS/JSON | TB1, TB2 | FX5 |
| F26 | P1 | P2 | POST /api/Cards {fullName, cardNum, expMonth, expYear} | HTTPS/JSON | TB1, TB2 | FX5 |
| F27 | P2 | D1 | grava cartão | driver SQLite | nenhuma | FX5 |
| F28 | P1 | P2 | POST /rest/basket/{bid}/checkout {addressId, paymentId, deliveryMethodId} | HTTPS/JSON | TB1, TB2 | FX5 |
| F29 | P2 | D2 | grava pedido | API MarsDB | nenhuma | FX5 |
| F30 | P2 | D4 | grava PDF order_{id}.pdf | sistema de arquivos | nenhuma | FX5 |
| F31 | P2 | P1 | confirmação com id do pedido | HTTPS/JSON | TB1, TB2 | FX5 |
| F32 | P1 | P2 | GET /rest/track-order/{id} | HTTPS/JSON | TB1, TB2 | FX5 |
| F33 | D2 | P2 | dados do pedido | API MarsDB | nenhuma | FX5 |
| F34 | P2 | P1 | resumo do pedido | HTTPS/JSON | TB1, TB2 | FX5 |
| F35 | P1 | E1 | confirmação da compra | interface | nenhuma | FX5 |
| F36 | E2 | P1 | acesso à área administrativa | navegador | nenhuma | GERAL |
| F37 | P1 | P2 | GET /rest/user/authentication-details (JWT admin) | HTTPS/JSON | TB1, TB2 | GERAL |
| F38 | P2 | P1 | lista de usuários | HTTPS/JSON | TB1, TB2 | GERAL |
| F39 | P1 | E2 | painel administrativo | interface | nenhuma | GERAL |
| F40 | P2 | P3 | eventos da aplicação | chamada interna | nenhuma | GERAL |
| F41 | P3 | P1 | notificações em tempo real | WebSocket (Socket.IO) | TB1, TB2 | GERAL |
| F42 | P1 | E3 | redirecionamento de autorização | HTTPS (OAuth 2.0) | TB3 | GERAL |
| F43 | E3 | P1 | access token e e-mail | HTTPS (OAuth 2.0) | TB3 | GERAL |

## FX1: Login com e-mail e senha, emissão e uso do token

| Passo | Origem | Destino | Fluxo (ID) | Dados trafegados | Protocolo / formato | Fronteira |
|---|---|---|---|---|---|---|
| 1 | E1 | P1 | F01 | e-mail e senha | formulário | nenhuma |
| 2 | P1 | P2 | F02 | POST /rest/user/login {email, password} | HTTPS/JSON | TB1, TB2 |
| 3 | P2 | D1 | F03 | consulta SQL em Users (senha em hash MD5) | driver SQLite | nenhuma |
| 4 | D1 | P2 | F04 | registro do usuário | driver SQLite | nenhuma |
| 5 | P2 | P1 | F05 | token JWT (RS256), bid, umail | HTTPS/JSON | TB1, TB2 |
| 6 | P1 | D5 | F06 | grava token e bid | API do navegador | nenhuma |
| 7 | D5 | P1 | F07 | lê token e bid | API do navegador | nenhuma |
| 8 | P1 | P2 | F08 | GET /rest/user/whoami (Bearer JWT) | HTTPS/JSON | TB1, TB2 |
| 9 | P2 | P1 | F09 | dados do usuário autenticado | HTTPS/JSON | TB1, TB2 |

## FX2: Visualização da cesta por identificador

| Passo | Origem | Destino | Fluxo (ID) | Dados trafegados | Protocolo / formato | Fronteira |
|---|---|---|---|---|---|---|
| 1 | D5 | P1 | F07 | lê token e bid | API do navegador | nenhuma |
| 2 | P1 | P2 | F10 | GET /rest/basket/{bid} (Bearer JWT) | HTTPS/JSON | TB1, TB2 |
| 3 | P2 | D1 | F11 | consulta da cesta pelo id | driver SQLite | nenhuma |
| 4 | D1 | P2 | F12 | cesta e itens | driver SQLite | nenhuma |
| 5 | P2 | P1 | F13 | cesta, produtos e quantidades | HTTPS/JSON | TB1, TB2 |
| 6 | P1 | E1 | F14 | exibição da cesta | interface | nenhuma |

## FX4: Leitura da configuração administrativa

| Passo | Origem | Destino | Fluxo (ID) | Dados trafegados | Protocolo / formato | Fronteira |
|---|---|---|---|---|---|---|
| 1 | E1 | P1 | F15 | abre a aplicação (sem login) | navegador | nenhuma |
| 2 | P1 | P2 | F16 | GET /rest/admin/application-configuration (sem token) | HTTPS/JSON | TB1, TB2 |
| 3 | P2 | D3 | F17 | leitura da configuração | sistema de arquivos | nenhuma |
| 4 | D3 | P2 | F18 | parâmetros da aplicação | sistema de arquivos | nenhuma |
| 5 | P2 | P1 | F19 | configuração completa (JSON, cerca de 36 kB) | HTTPS/JSON | TB1, TB2 |

## FX5: Checkout: endereço, pagamento e registro do pedido

| Passo | Origem | Destino | Fluxo (ID) | Dados trafegados | Protocolo / formato | Fronteira |
|---|---|---|---|---|---|---|
| 1 | D5 | P1 | F07 | lê token e bid | API do navegador | nenhuma |
| 2 | P1 | P2 | F10 | GET /rest/basket/{bid} (Bearer JWT) | HTTPS/JSON | TB1, TB2 |
| 3 | P2 | D1 | F11 | consulta da cesta pelo id | driver SQLite | nenhuma |
| 4 | D1 | P2 | F12 | cesta e itens | driver SQLite | nenhuma |
| 5 | P2 | P1 | F13 | cesta, produtos e quantidades | HTTPS/JSON | TB1, TB2 |
| 6 | E1 | P1 | F20 | produto, endereço, entrega e cartão | formulário | nenhuma |
| 7 | P1 | P2 | F21 | POST /api/BasketItems {BasketId, ProductId, quantity} | HTTPS/JSON | TB1, TB2 |
| 8 | P2 | D1 | F22 | insere item na cesta | driver SQLite | nenhuma |
| 9 | P1 | P2 | F23 | POST /api/Addresss {fullName, mobileNum, endereço, zipCode} | HTTPS/JSON | TB1, TB2 |
| 10 | P2 | D1 | F24 | grava endereço | driver SQLite | nenhuma |
| 11 | P1 | P2 | F25 | GET /api/Deliverys | HTTPS/JSON | TB1, TB2 |
| 12 | P1 | P2 | F26 | POST /api/Cards {fullName, cardNum, expMonth, expYear} | HTTPS/JSON | TB1, TB2 |
| 13 | P2 | D1 | F27 | grava cartão | driver SQLite | nenhuma |
| 14 | P1 | P2 | F28 | POST /rest/basket/{bid}/checkout {addressId, paymentId, deliveryMethodId} | HTTPS/JSON | TB1, TB2 |
| 15 | P2 | D2 | F29 | grava pedido | API MarsDB | nenhuma |
| 16 | P2 | D4 | F30 | grava PDF order_{id}.pdf | sistema de arquivos | nenhuma |
| 17 | P2 | P1 | F31 | confirmação com id do pedido | HTTPS/JSON | TB1, TB2 |
| 18 | P1 | P2 | F32 | GET /rest/track-order/{id} | HTTPS/JSON | TB1, TB2 |
| 19 | D2 | P2 | F33 | dados do pedido | API MarsDB | nenhuma |
| 20 | P2 | P1 | F34 | resumo do pedido | HTTPS/JSON | TB1, TB2 |
| 21 | P1 | E1 | F35 | confirmação da compra | interface | nenhuma |
