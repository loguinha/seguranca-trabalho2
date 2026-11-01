#!/usr/bin/env python3
"""
Modelo de ameacas (modelo como codigo) do OWASP Juice Shop.
Trabalho 2: Modelagem de Ameacas com DFD e STRIDE
Seguranca de Sistemas Computacionais 2026/2, UNIVALI.

Fonte unica do modelo: elementos, fronteiras de confianca e fluxos de dados.
Gera, com Graphviz:
  - DFD nivel 1 completo
  - um recorte de DFD por fluxo analisado (FX1, FX2, FX4, FX5)
  - inventario dos elementos e tabela de passos de cada fluxo (Markdown)
  - exportacao do modelo em JSON
e valida as regras de qualidade do DFD da Secao 5.1 do roteiro.

Uso:
  python3 modelo_ameacas.py gerar          # gera tudo em ./saida
  python3 modelo_ameacas.py dot [FX1]      # imprime o DOT (nivel 1 ou recorte)
  python3 modelo_ameacas.py validar        # so valida as regras
Requisito: Graphviz instalado (comando "dot").
"""
import json
import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# 1. Zonas e fronteiras de confianca
#    Cada zona e desenhada como um quadro. A borda das zonas com "tb"
#    e a fronteira de confianca correspondente.
# ---------------------------------------------------------------------------
ZONAS = {
    "nav": {"nome": "Internet: navegador do usuário (zona não confiável)", "pai": None, "tb": None},
    "infra": {"nome": "GitHub Codespaces: túnel HTTPS e VM (fora do escopo)", "pai": None, "tb": "TB1"},
    "cont": {"nome": "Contêiner Docker juiceshop (Node.js, porta 3000)", "pai": "infra", "tb": "TB2"},
    "google": {"nome": "Terceiro: Google", "pai": None, "tb": "TB3"},
}

FRONTEIRAS = {
    "TB1": "Internet | infraestrutura do Codespaces. O TLS termina no túnel da Microsoft.",
    "TB2": "Túnel e VM | contêiner da aplicação. Daqui em diante o tráfego é HTTP e a aplicação processa os dados.",
    "TB3": "Aplicação | terceiro (Google OAuth 2.0).",
}

# ---------------------------------------------------------------------------
# 2. Elementos do DFD (prefixos E, P e D da Secao 5.1 do roteiro)
# ---------------------------------------------------------------------------
ELEMENTOS = {
    "E1": {"tipo": "E", "nome": "Cliente", "zona": "nav",
           "tec": "Pessoa no navegador",
           "desc": "Usuário anônimo ou autenticado da loja."},
    "E2": {"tipo": "E", "nome": "Administrador", "zona": "nav",
           "tec": "Pessoa no navegador",
           "desc": "Usuário com papel admin."},
    "E3": {"tipo": "E", "nome": "Google OAuth 2.0", "zona": "google",
           "tec": "Provedor de identidade externo",
           "desc": "Login federado com conta Google."},
    "P1": {"tipo": "P", "nome": "SPA Angular", "zona": "nav",
           "tec": "Angular (TypeScript), executa no navegador",
           "desc": "Interface da loja; monta as requisições à API."},
    "P2": {"tipo": "P", "nome": "API REST", "zona": "cont",
           "tec": "Node.js + Express (rotas /rest e /api)",
           "desc": "Regras de negócio, autenticação e acesso aos dados."},
    "P3": {"tipo": "P", "nome": "Notificações WebSocket", "zona": "cont",
           "tec": "Socket.IO",
           "desc": "Envia notificações em tempo real ao navegador."},
    "D1": {"tipo": "D", "nome": "Banco SQLite", "zona": "cont",
           "tec": "SQLite via ORM Sequelize",
           "desc": "Users, Baskets, BasketItems, Addresses, Cards, Products."},
    "D2": {"tipo": "D", "nome": "MarsDB", "zona": "cont",
           "tec": "Banco em memória compatível com MongoDB",
           "desc": "Pedidos (orders) e avaliações."},
    "D3": {"tipo": "D", "nome": "Configuração da aplicação", "zona": "cont",
           "tec": "Arquivos YAML em config/",
           "desc": "Parâmetros da loja, servida por /rest/admin/application-configuration."},
    "D4": {"tipo": "D", "nome": "Pasta pública ftp/", "zona": "cont",
           "tec": "Sistema de arquivos do contêiner",
           "desc": "PDFs de confirmação de pedido."},
    "D5": {"tipo": "D", "nome": "Armazenamento do navegador", "zona": "nav",
           "tec": "localStorage, sessionStorage e cookies",
           "desc": "Guarda o token JWT e o identificador da cesta (bid)."},
}

# ---------------------------------------------------------------------------
# 3. Fluxos de ponta a ponta analisados (Secao 5.3 do roteiro)
# ---------------------------------------------------------------------------
FLUXOS = {
    "FX1": "Login com e-mail e senha, emissão e uso do token",
    "FX2": "Visualização da cesta por identificador",
    "FX4": "Leitura da configuração administrativa",
    "FX5": "Checkout: endereço, pagamento e registro do pedido",
}

# ---------------------------------------------------------------------------
# 4. Fluxos de dados. A ordem da lista e a ordem dos passos em cada fluxo.
#    "fx" indica a quais fluxos de ponta a ponta o fluxo de dados pertence;
#    "GERAL" aparece so no DFD nivel 1.
# ---------------------------------------------------------------------------
F = [
    # FX1: login e uso do token
    ("F01", "E1", "P1", "e-mail e senha", "formulário", ["FX1"]),
    ("F02", "P1", "P2", "POST /rest/user/login {email, password}", "HTTPS/JSON", ["FX1"]),
    ("F03", "P2", "D1", "consulta SQL em Users (senha em hash MD5)", "driver SQLite", ["FX1"]),
    ("F04", "D1", "P2", "registro do usuário", "driver SQLite", ["FX1"]),
    ("F05", "P2", "P1", "token JWT (RS256), bid, umail", "HTTPS/JSON", ["FX1"]),
    ("F06", "P1", "D5", "grava token e bid", "API do navegador", ["FX1"]),
    ("F07", "D5", "P1", "lê token e bid", "API do navegador", ["FX1", "FX2", "FX5"]),
    ("F08", "P1", "P2", "GET /rest/user/whoami (Bearer JWT)", "HTTPS/JSON", ["FX1"]),
    ("F09", "P2", "P1", "dados do usuário autenticado", "HTTPS/JSON", ["FX1"]),
    # FX2: cesta por identificador
    ("F10", "P1", "P2", "GET /rest/basket/{bid} (Bearer JWT)", "HTTPS/JSON", ["FX2", "FX5"]),
    ("F11", "P2", "D1", "consulta da cesta pelo id", "driver SQLite", ["FX2", "FX5"]),
    ("F12", "D1", "P2", "cesta e itens", "driver SQLite", ["FX2", "FX5"]),
    ("F13", "P2", "P1", "cesta, produtos e quantidades", "HTTPS/JSON", ["FX2", "FX5"]),
    ("F14", "P1", "E1", "exibição da cesta", "interface", ["FX2"]),
    # FX4: configuracao administrativa
    ("F15", "E1", "P1", "abre a aplicação (sem login)", "navegador", ["FX4"]),
    ("F16", "P1", "P2", "GET /rest/admin/application-configuration (sem token)", "HTTPS/JSON", ["FX4"]),
    ("F17", "P2", "D3", "leitura da configuração", "sistema de arquivos", ["FX4"]),
    ("F18", "D3", "P2", "parâmetros da aplicação", "sistema de arquivos", ["FX4"]),
    ("F19", "P2", "P1", "configuração completa (JSON, cerca de 36 kB)", "HTTPS/JSON", ["FX4"]),
    # FX5: checkout
    ("F20", "E1", "P1", "produto, endereço, entrega e cartão", "formulário", ["FX5"]),
    ("F21", "P1", "P2", "POST /api/BasketItems {BasketId, ProductId, quantity}", "HTTPS/JSON", ["FX5"]),
    ("F22", "P2", "D1", "insere item na cesta", "driver SQLite", ["FX5"]),
    ("F23", "P1", "P2", "POST /api/Addresss {fullName, mobileNum, endereço, zipCode}", "HTTPS/JSON", ["FX5"]),
    ("F24", "P2", "D1", "grava endereço", "driver SQLite", ["FX5"]),
    ("F25", "P1", "P2", "GET /api/Deliverys", "HTTPS/JSON", ["FX5"]),
    ("F26", "P1", "P2", "POST /api/Cards {fullName, cardNum, expMonth, expYear}", "HTTPS/JSON", ["FX5"]),
    ("F27", "P2", "D1", "grava cartão", "driver SQLite", ["FX5"]),
    ("F28", "P1", "P2", "POST /rest/basket/{bid}/checkout {addressId, paymentId, deliveryMethodId}", "HTTPS/JSON", ["FX5"]),
    ("F29", "P2", "D2", "grava pedido", "API MarsDB", ["FX5"]),
    ("F30", "P2", "D4", "grava PDF order_{id}.pdf", "sistema de arquivos", ["FX5"]),
    ("F31", "P2", "P1", "confirmação com id do pedido", "HTTPS/JSON", ["FX5"]),
    ("F32", "P1", "P2", "GET /rest/track-order/{id}", "HTTPS/JSON", ["FX5"]),
    ("F33", "D2", "P2", "dados do pedido", "API MarsDB", ["FX5"]),
    ("F34", "P2", "P1", "resumo do pedido", "HTTPS/JSON", ["FX5"]),
    ("F35", "P1", "E1", "confirmação da compra", "interface", ["FX5"]),
    # Somente no nivel 1 (completude do modelo)
    ("F36", "E2", "P1", "acesso à área administrativa", "navegador", ["GERAL"]),
    ("F37", "P1", "P2", "GET /rest/user/authentication-details (JWT admin)", "HTTPS/JSON", ["GERAL"]),
    ("F38", "P2", "P1", "lista de usuários", "HTTPS/JSON", ["GERAL"]),
    ("F39", "P1", "E2", "painel administrativo", "interface", ["GERAL"]),
    ("F40", "P2", "P3", "eventos da aplicação", "chamada interna", ["GERAL"]),
    ("F41", "P3", "P1", "notificações em tempo real", "WebSocket (Socket.IO)", ["GERAL"]),
    ("F42", "P1", "E3", "redirecionamento de autorização", "HTTPS (OAuth 2.0)", ["GERAL"]),
    ("F43", "E3", "P1", "access token e e-mail", "HTTPS (OAuth 2.0)", ["GERAL"]),
]
# Descricao resumida usada no DFD nivel 1, quando varios fluxos ligam o mesmo par.
RESUMO_PAR = {
    ("E1", "P1"): "ações do cliente (login, compra)",
    ("P1", "E1"): "telas da loja",
    ("P1", "P2"): "requisições REST (HTTPS/JSON)",
    ("P2", "P1"): "respostas JSON (token, cesta, pedido, configuração)",
    ("P2", "D1"): "consultas e gravações (usuários, cesta, endereço, cartão)",
    ("D1", "P2"): "registros lidos",
    ("P2", "D2"): "grava pedido",
    ("P1", "D5"): "grava token e bid",
    ("D5", "P1"): "lê token e bid",
}

FLUXOS_DADOS = [
    {"id": a, "origem": b, "destino": c, "dados": d, "protocolo": e, "fx": f}
    for (a, b, c, d, e, f) in F
]


# ---------------------------------------------------------------------------
# Funcoes auxiliares
# ---------------------------------------------------------------------------
def cadeia_zonas(zona):
    """Zona do elemento e todas as zonas que a contem."""
    out = []
    while zona:
        out.append(zona)
        zona = ZONAS[zona]["pai"]
    return set(out)


def fronteiras_cruzadas(origem, destino):
    """Fronteiras de confianca atravessadas por um fluxo, calculadas pelas zonas."""
    za = cadeia_zonas(ELEMENTOS[origem]["zona"])
    zb = cadeia_zonas(ELEMENTOS[destino]["zona"])
    tbs = sorted(ZONAS[z]["tb"] for z in (za ^ zb) if ZONAS[z]["tb"])
    return tbs


def validar():
    """Regras de qualidade do DFD (Secao 5.1 do roteiro). Retorna lista de erros."""
    erros = []
    ids = set()
    for f in FLUXOS_DADOS:
        if f["id"] in ids:
            erros.append(f"{f['id']}: identificador repetido")
        ids.add(f["id"])
        to, td = ELEMENTOS[f["origem"]]["tipo"], ELEMENTOS[f["destino"]]["tipo"]
        if to == "E" and td != "P" or td == "E" and to != "P":
            erros.append(f"{f['id']}: entidade externa deve se comunicar só com processos")
        if to == "D" and td != "P" or td == "D" and to != "P":
            erros.append(f"{f['id']}: armazenamento deve se conectar só a processos")
        for fx in f["fx"]:
            if fx != "GERAL" and fx not in FLUXOS:
                erros.append(f"{f['id']}: fluxo {fx} inexistente")
    for eid, e in ELEMENTOS.items():
        if e["tipo"] == "P":
            ent = any(f["destino"] == eid for f in FLUXOS_DADOS)
            sai = any(f["origem"] == eid for f in FLUXOS_DADOS)
            if not (ent and sai):
                erros.append(f"{eid}: processo precisa de ao menos uma entrada e uma saída")
        if not any(eid in (f["origem"], f["destino"]) for f in FLUXOS_DADOS):
            erros.append(f"{eid}: elemento sem fluxo")
    for fx in FLUXOS:
        tbs = set()
        for f in FLUXOS_DADOS:
            if fx in f["fx"]:
                tbs.update(fronteiras_cruzadas(f["origem"], f["destino"]))
        if not tbs:
            erros.append(f"{fx}: o fluxo precisa cruzar ao menos uma fronteira de confiança")
    return erros


# ---------------------------------------------------------------------------
# Geracao do DOT (Graphviz)
# ---------------------------------------------------------------------------
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def no_dot(eid):
    e = ELEMENTOS[eid]
    rot = f"<b>{eid}</b><br/>{esc(e['nome'])}<br/><font point-size='9'>{esc(e['tec'])}</font>"
    if e["tipo"] == "E":
        return (f'"{eid}" [shape=box, style="filled", fillcolor="#DCE9F5", color="#1F4E79", '
                f'penwidth=2, margin="0.15,0.1", label=<{rot}>];')
    if e["tipo"] == "P":
        return (f'"{eid}" [shape=circle, style="filled", fillcolor="#DCE9F5", color="#1F4E79", '
                f'penwidth=2, label=<{rot}>];')
    # Armazenamento: duas linhas paralelas (notacao da Figura 1 do roteiro)
    return (f'"{eid}" [shape=plain, label=<<table border="0" cellborder="1" cellspacing="0" '
            f'cellpadding="6" color="#2E7D32"><tr><td sides="TB" bgcolor="#EEF6EE">{rot}</td></tr></table>>];')


def gerar_dot(fx=None):
    fluxos = [f for f in FLUXOS_DADOS if fx is None or fx in f["fx"]]
    usados = set()
    for f in fluxos:
        usados.update([f["origem"], f["destino"]])
    titulo = "DFD nível 1: OWASP Juice Shop 20.3.0" if fx is None else f"Recorte do DFD: {fx} {FLUXOS[fx]}"

    L = ["digraph DFD {",
         f'  graph [rankdir=LR, fontname="Helvetica", fontsize=16, labelloc=t, label=<<b>{esc(titulo)}</b>>, '
         'nodesep=0.45, ranksep=1.1, pad=0.3, newrank=true];',
         '  node [fontname="Helvetica", fontsize=11];',
         '  edge [fontname="Helvetica", fontsize=9, color="#333333", arrowsize=0.8];']

    def zona_dot(z, ind):
        filhos = [k for k, v in ZONAS.items() if v["pai"] == z]
        nos = [eid for eid, e in ELEMENTOS.items() if e["zona"] == z and eid in usados]
        tem_conteudo = nos or any(zona_tem(fz) for fz in filhos)
        if not tem_conteudo:
            return []
        tb = ZONAS[z]["tb"]
        rot = (f"{tb} | " if tb else "") + ZONAS[z]["nome"]
        cor = "#C0392B" if tb else "#7F8C8D"
        out = [f"{ind}subgraph cluster_{z} {{",
               f'{ind}  label=<<b>{esc(rot)}</b>>; fontcolor="{cor}"; fontsize=12; '
               f'style="dashed,rounded"; color="{cor}"; penwidth=2; labeljust=l;']
        for eid in nos:
            out.append(f"{ind}  {no_dot(eid)}")
        for fz in filhos:
            out += zona_dot(fz, ind + "  ")
        out.append(f"{ind}}}")
        return out

    def zona_tem(z):
        if any(e["zona"] == z and eid in usados for eid, e in ELEMENTOS.items()):
            return True
        return any(zona_tem(k) for k, v in ZONAS.items() if v["pai"] == z)

    for z, v in ZONAS.items():
        if v["pai"] is None:
            L += zona_dot(z, "  ")

    if fx is None:
        # Nivel 1: um fluxo por par de elementos, com a lista de IDs agrupados.
        grupos = {}
        for f in fluxos:
            grupos.setdefault((f["origem"], f["destino"]), []).append(f)
        for (o, d), fs in grupos.items():
            tbs = fronteiras_cruzadas(o, d)
            cor = "#C0392B" if tbs else "#333333"
            ids = [x["id"] for x in fs]
            linhas = [", ".join(ids[i:i + 5]) for i in range(0, len(ids), 5)]
            desc = RESUMO_PAR.get((o, d), fs[0]["dados"] if len(fs) == 1 else "")
            rot = "<br/>".join(f"<b>{esc(x)}</b>" for x in linhas)
            if desc:
                rot += f"<br/>{esc(desc)}"
            L.append(f'  "{o}" -> "{d}" [label=<{rot}>, fontcolor="{cor}"];')
    else:
        for f in fluxos:
            tbs = fronteiras_cruzadas(f["origem"], f["destino"])
            cor = "#C0392B" if tbs else "#333333"
            rot = f"<b>{f['id']}</b> {esc(f['dados'])}"
            L.append(f'  "{f["origem"]}" -> "{f["destino"]}" [label=<{rot}>, fontcolor="{cor}"];')
    L.append("}")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Inventario em Markdown e exportacao JSON
# ---------------------------------------------------------------------------
NOME_TIPO = {"E": "Entidade externa", "P": "Processo", "D": "Armazenamento de dados"}


def gerar_markdown():
    L = ["# Inventário do modelo de ameaças: OWASP Juice Shop", "",
         "Gerado automaticamente por `modelo_ameacas.py`. Não editar à mão.", "",
         "## Elementos", "", "| ID | Tipo | Nome | Tecnologia | Descrição | Zona |",
         "|---|---|---|---|---|---|"]
    for eid, e in ELEMENTOS.items():
        L.append(f"| {eid} | {NOME_TIPO[e['tipo']]} | {e['nome']} | {e['tec']} | {e['desc']} | {ZONAS[e['zona']]['nome']} |")
    L += ["", "## Fronteiras de confiança", "", "| ID | Descrição |", "|---|---|"]
    for tb, d in FRONTEIRAS.items():
        L.append(f"| {tb} | {d.replace('|', chr(92) + '|')} |")
    L += ["", "## Fluxos de dados", "", "| ID | Origem | Destino | Dados | Protocolo / formato | Fronteira | Fluxos |",
          "|---|---|---|---|---|---|---|"]
    for f in FLUXOS_DADOS:
        tbs = ", ".join(fronteiras_cruzadas(f["origem"], f["destino"])) or "nenhuma"
        L.append(f"| {f['id']} | {f['origem']} | {f['destino']} | {f['dados']} | {f['protocolo']} | {tbs} | {', '.join(f['fx'])} |")
    for fx, nome in FLUXOS.items():
        L += ["", f"## {fx}: {nome}", "",
              "| Passo | Origem | Destino | Fluxo (ID) | Dados trafegados | Protocolo / formato | Fronteira |",
              "|---|---|---|---|---|---|---|"]
        passo = 1
        for f in FLUXOS_DADOS:
            if fx in f["fx"]:
                tbs = ", ".join(fronteiras_cruzadas(f["origem"], f["destino"])) or "nenhuma"
                L.append(f"| {passo} | {f['origem']} | {f['destino']} | {f['id']} | {f['dados']} | {f['protocolo']} | {tbs} |")
                passo += 1
    return "\n".join(L) + "\n"


def gerar_json():
    return json.dumps({
        "sistema": "OWASP Juice Shop 20.3.0",
        "zonas": ZONAS, "fronteiras": FRONTEIRAS, "elementos": ELEMENTOS,
        "fluxos": FLUXOS,
        "fluxos_de_dados": [dict(f, fronteiras=fronteiras_cruzadas(f["origem"], f["destino"])) for f in FLUXOS_DADOS],
    }, ensure_ascii=False, indent=2)


def renderizar(dot_txt, png):
    subprocess.run(["dot", "-Tpng", "-Gdpi=170", "-o", png], input=dot_txt.encode("utf-8"), check=True)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "gerar"
    erros = validar()
    if cmd == "validar":
        print("\n".join(erros) if erros else "Validação do DFD: OK (nenhuma regra violada)")
        sys.exit(1 if erros else 0)
    if cmd == "dot":
        fx = sys.argv[2] if len(sys.argv) > 2 else None
        print(gerar_dot(fx))
        return
    if erros:
        print("Erros de validação:\n" + "\n".join(erros))
        sys.exit(1)
    os.makedirs("saida", exist_ok=True)
    renderizar(gerar_dot(), "saida/dfd_nivel1.png")
    for fx in FLUXOS:
        renderizar(gerar_dot(fx), f"saida/recorte_{fx.lower()}.png")
    with open("saida/inventario.md", "w", encoding="utf-8") as fh:
        fh.write(gerar_markdown())
    with open("saida/modelo.json", "w", encoding="utf-8") as fh:
        fh.write(gerar_json())
    print("Validação do DFD: OK")
    print("Gerados em ./saida: dfd_nivel1.png, " +
          ", ".join(f"recorte_{fx.lower()}.png" for fx in FLUXOS) + ", inventario.md, modelo.json")


if __name__ == "__main__":
    main()
