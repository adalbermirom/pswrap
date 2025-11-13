# pswrap (Biblioteca de Sockets para Linguagem Prisma)

[![Licença: CC0](https://licensebuttons.net/p/zero/1.0/88x31.png)](http://creativecommons.org/publicdomain/zero/1.0/)

`pswrap` é uma biblioteca C (binding) que expõe a API de sockets (TCP e UDP) para a linguagem Prisma.

O seu principal recurso é um multiplexador de I/O (`multi_seletor`) que permite a criação de servidores assíncronos (não-bloqueantes) de alta performance, capazes de lidar com milhares de conexões simultâneas, similar à arquitetura do Node.js ou Nginx.

Este repositório contém:
* `pswrap.plib.c`: O código-fonte do *binding* escrito na metalinguagem `Plibc`.
* `swrap.h`: A biblioteca C base (CC0/Domínio Público) que fornece a funcionalidade de socket.
* `plibc`: A ferramenta (escrita em Prisma) necessária para transpilar e compilar o projeto.
* `exemplos/`: Diversos exemplos, incluindo um mini-servidor HTTP (`httpmini.pris`).

## Recursos

* API 100% em português, seguindo o padrão da linguagem Prisma (`escute`, `aceitar`, `envie`).
* Servidores e Clientes TCP.
* Servidores e Clientes UDP.
* Manipulador de I/O assíncrono `multi_seletor` (baseado em `select()`) para alta concorrência.
* Código-fonte do *binding* (`.plib.c`) totalmente documentado com `minidoc`.

## Requisitos para Compilação

Para compilar esta biblioteca, você precisará de:

1.  **O Interpretador Prisma:** A ferramenta `plibc` (inclusa no projeto) depende do interpretador `prisma` para ser executada.
    * **Download em:** `https://linguagemprisma.br4.biz/`
2.  **Um Compilador C:** Um compilador C padrão como `gcc` (Linux) ou `MinGW` (Windows).

## Como Compilar (Build)

O `plibc` é a ferramenta que orquestra todo o processo de build:

1.  Ele transpila o `pswrap.plib.c` para o código C padrão (`pswrap.c`).
2.  Ele gera os *headers* necessários (`lua.h`, `prisma.h`, etc.) em um diretório de build.
3.  Ele invoca o `gcc` (ou compilador C) para gerar a biblioteca final (`.so` ou `.dll`).

Para compilar tudo, simplesmente execute o script de build:

```bash
./compila.sh
```

## Como Usar (Exemplo)

Após a compilação, você pode rodar o servidor HTTP de exemplo:


```
prisma exemplos/teste_http.prisma
O servidor será iniciado em http://127.0.0.1:12345.
```
## Documentação

Toda a API pswrap está documentada diretamente no arquivo pswrap.plib.c usando comentários no formato minidoc.

## Licença

O código-fonte da biblioteca swrap.h original é dedicado ao Domínio Público (CC0).

Todo o código de binding (pswrap.plib.c) e os exemplos neste repositório seguem a mesma licença. Você está livre para usar, modificar e distribuir este projeto para qualquer fim, comercial ou não, sem necessidade de atribuição.

## Exemplos:

### Servidor mínimo:
```lua
local swrap = inclua'pswrap';
local escreva = imprima;

local ip, porta = "127.0.0.1", "12346";
local mensagem;

funcao principal()
    // Inicializa a biblioteca de sockets
    swrap.inicialize()

    // Cria socket TCP e vincula
    local sock, msg = swrap.socket(swrap.TCP, swrap.SERVIDOR, swrap.PADRAO, ip, porta)
    
    //escreva(swrap.valide_socket(sock));
    se sock == nulo entao
        escreva("Erro ao criar socket: ", msg)
        retorne
    fim
    //leia();
    // Coloca para escutar
    local sucesso, msg = swrap.escute(sock, 5)
    se sucesso == nulo entao
        escreva("Erro ao escutar: ", swrap.obt_ultimo_erro())
        retorne
    fim

    escreva("Servidor TCP iniciado na porta " .. porta.."...")

    enquanto verdadeiro inicio
        // Aceita nova conexão
        local cliente, addr = swrap.aceitar(sock)
        se cliente <> nulo entao
            local host, porta = swrap.endereco_info(cliente)
            escreva("Nova conexão de ", host, ":", porta)

            // Recebe dados do cliente
            dados, n = swrap.receba(cliente, 1024)
            se dados <> nulo entao
            //GET / HTTP/1.1
                escreva("Recebido:\n", dados)
                local mensagem = 'Oi, servidor responde!';
                swrap.envie(cliente, mensagem) // eco
            fim

            swrap.feche(cliente)
        fim
    fim
    
    swrap.feche(sock);                  
    swrap.finalize();
fim
```

### Para outros exemplos veja a pasta ./exemplos/

