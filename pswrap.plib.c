/* Binding swrap.h para linguagem Prisma-1.0 */
/**
    \fonte PSwrap-1.2
    \resumo Binding da lib swrap.h em C para Prisma com funções de rede baixo nível (sockets)
    \autor Adalberto Amorim Felipe
    \versao 1.2
*/

    $.modulo: pswrap
    $.AUTOR: "Adalberto"
    $.VERSAO: "lib-pswrap-1.01"

#define SWRAP_IMPLEMENTATION 
//#include "swrap.h"
$.inclua: swrap.h
#include <stdlib.h>




#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <errno.h>
#endif
#include <string.h>
#include <stdio.h>


/**** ERROR FUNCTIONS ***/
// helper para Windows
#ifdef _WIN32
static void winsock_strerror(int err, char *buf, int size) {
    DWORD len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL, err,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               buf, size, NULL);
    if (len == 0) snprintf(buf, size, "Winsock error %d", err);
}
#endif

// Valida se o socket é um descritor válido, do tipo TCP (SOCK_STREAM) e está vinculado.
//retornos: 
// -1 - erro
// 0 - SWRAP_TCP
// 1 - SWRAP_UDP
//TCP (stream)	SOCK_STREAM
//UDP (datagram)	SOCK_DGRAM
//Raw	SOCK_RAW
static int validate_socket(int sock, char* err_msg, int err_msg_size) {
	
    if (sock < 0) {
        if (err_msg) snprintf(err_msg, err_msg_size, "Socket inválido: valor deve ser não negativo");
        return -1;
    }
    
    // Verifica se é um socket válido e do tipo TCP
    int type;
    socklen_t len = sizeof(type);
    if (getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&type, &len) == -1) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAENOTSOCK) {
            if (err_msg) snprintf(err_msg, err_msg_size, "Socket inválido: não é um descritor de socket");
        } else {
            if (err_msg) winsock_strerror(err, err_msg, err_msg_size);
        }
#else
        if (errno == EBADF) {
            if (err_msg) snprintf(err_msg, err_msg_size, "Socket inválido: descritor não é válido");
        } else {
            if (err_msg) strerror_r(errno, err_msg, err_msg_size);
        }
#endif
        return -1;
    }
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        if (err_msg) snprintf(err_msg, err_msg_size, "Socket inválido: deve ser um socket TCP ou UDP");
        return -1;
    }
    
    // Verifica se o socket está vinculado (SWRAP_BIND)
    struct swrap_addr addr = {0};
    if (swrapAddress(sock, &addr) == -1) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEINVAL) {
            if (err_msg) snprintf(err_msg, err_msg_size, "Socket inválido: não está vinculado (SWRAP_BIND)");
        } else {
            if (err_msg) winsock_strerror(err, err_msg, err_msg_size);
        }
#else
        if (errno == EINVAL) {
            if (err_msg) snprintf(err_msg, err_msg_size, "Socket inválido: não está vinculado (SWRAP_BIND)");
        } else {
            if (err_msg) strerror_r(errno, err_msg, err_msg_size);
        }
#endif
        return -1;
    }
    int ret = 0;
    if ( type == SOCK_STREAM ) ret = SWRAP_TCP;
    else if (type == SOCK_DGRAM) ret = SWRAP_UDP;
    return ret;
}

// ret = swrap.valide_socket(sock); --> nulo, err ou 0 = TCP | 1 = UDP
/*
--[[[
    \fn pswrap.valide_socket
    \resumo Faz a validacao de um socket passado como argumento.
    \param socket {numero} - O identificador do socket aberto.
    \retorno ret {string|nulo} - "TCP" ou "UDP" em sucesso, ou nulo em caso de erro.
    \retorno err {string|nulo} - string de erro em caso de erro ou nulo.
    
\codigo ex1.prisma
local pswrap = inclua'pswrap'
local ret, err = pswrap.valide_socket(sock)
se nao ret entao erro(err) fim

se ret == "TCP" entao
    -- E um socket TCP
senaose ret == "UDP" entao
    -- E um socket UDP
fim
\codigo--

]]

funcao pswrap.valide_socket(socket)
*/
funcao swrapValidateSocket(sock) #[export valide_socket]

    
    if(!$.is_number(sock)){
		lua_pushnil(L);
		lua_pushfstring(L, "Espera-se 'numero' em vez de '%s'.", lua_typename(L, lua_type(L, 1)));
		return 2;
	}
    int sock = $.int(sock);
    char buff[256] = {0};
    int ret = validate_socket(sock, buff, sizeof(buff));
    if( ret == -1 ){
        retorne $.nulo, $.string(buff);
    }

    // Retorna string mais legível:
    //TCP
    if( ret == 0 ){
        retorne $.string("TCP");
    }
    // UDP
    if(ret == 1){
        retorne $.string("UDP");
    }
    
    retorne $.nulo, $.string("Tipo de socket desconhecido");
fim




/**** FIM ERROR FUNCTIONS ***/


/*
--[[[
    \fn pswrap.inicialize
    \resumo Inicializa a biblioteca de sockets. (Obrigatório no Windows).
    \retorno ret {numero|nulo} - 0 em sucesso, ou nulo em caso de falha.
    \retorno err {string|nulo} - Mensagem de erro se houver falha.
    
\codigo ex_inicialize.prisma
local pswrap = inclua'pswrap'
local ret, err = pswrap.inicialize()
se nao ret entao erro(err) fim
\codigo--

]]
funcao pswrap.inicialize()
*/
funcao swrapInit()   #[export inicialize]
    int ret = swrapInit();
    if (ret!=0){
		retorne $.nulo, $.string("Falha na inicialização socket.");
	}
    retorne $.int(ret);
fim


/*
--[[[
    \fn pswrap.socket
    \resumo Cria um novo handle de socket (servidor ou cliente).
    \param protocolo {numero} - O protocolo: `pswrap.TCP` (0) ou `pswrap.UDP` (1).
    \param modo {numero} - O modo de operacao: `pswrap.SERVIDOR` (0) para servidores ou `pswrap.CLIENTE` (1) para clientes.
    \param flags {numero} - Flags de configuracao, ex: `pswrap.PADRAO` (0), `pswrap.NAO_BLOQUEANTE` (1), `pswrap.SEM_ESPERA`
    \param host {string} - O endereco de host (ex: "0.0.0.0", "127.0.0.1").
    \param porta {string} - A porta de servico (ex: "8080", "12345").
    \retorno sock {numero|nulo} - O handle do socket em caso de sucesso, ou nulo.
    \retorno err {string|nulo} - Mensagem de erro se houver falha.
    
\codigo ex_servidor.prisma
local pswrap = inclua'pswrap'
local ip, porta = "0.0.0.0", "12345"

-- Cria um socket de servidor TCP na porta 12345
local sock_servidor, err = pswrap.socket(pswrap.TCP, pswrap.SERVIDOR, pswrap.PADRAO, ip, porta)
se nao sock_servidor entao erro(err) fim
\codigo--

]]
funcao pswrap.socket(protocolo, modo, flags, host_addr, porta)
*/

funcao swrapSocket(protocolo, modo, flags, host_addr, porta) #[export socket]
    //int swrapSocket(int, int, char, const char*, const char*);
    int protocolo = $.int(protocolo); //SWRAP_TCP ou SWRAP_UDP
    int modo = $.int(modo);//SWRAP_BIND ou SWRAP_CONNECT
    char flags = $.int(flags); //SWRAP_DEFAULT or a bitwise combination of flags SWRAP_NOBLOCK e SWRAP_NODELAY
    const char *host_addr = $.string(host_addr);//Host/address as a string, can be IPv4, IPv6, etc...
    const char *porta = $.string(porta);//Service/port as a string, e.g. "1728" or "http"
    //returns socket handle, or -1 on failure
    int ret = swrapSocket(protocolo, modo, flags, host_addr, porta);
    if (ret == -1 ){
		retorne $.nulo, $.string("Erro ao criar socket handle.");
	}
	retorne $.int(ret);
fim


//closes the given socket
/*
--[[[
    \fn pswrap.feche
    \resumo Fecha um handle de socket.
    \param socket {numero} - O handle do socket a ser fechado.
    \retorno (nenhum)
    
\codigo ex_feche.prisma
pswrap.feche(cliente_socket)
\codigo--

]]
funcao pswrap.feche(socket)
*/
funcao swrapClose(socket_handler) #[export feche]
    //void swrapClose(int);
    int handler = $.int(socket_handler);
    swrapClose(handler);
fim


/*
--[[[
    \fn pswrap.finalize
    \resumo Limpa e finaliza a biblioteca de socket (Obrigatorio no Windows).
    \param (nenhum)
    \retorno (nenhum)
    
\codigo ex_finalize.prisma
pswrap.inicialize()
-- ... (todo o codigo do servidor)
pswrap.feche(sock_servidor)
pswrap.finalize()
\codigo--

]]
funcao pswrap.finalize()
*/

   //terminates socket functionality
funcao swrapTerminate() #[export finalize]
    //void swrapTerminate();
    swrapTerminate();
fim



//SWDEF int swrapListen(int, int);
// Configura o socket fornecido (deve estar configurado com SWRAP_TCP + SWRAP_BIND) para escutar novas conexões com o backlog especificado.
// Retorna 0 em sucesso, diferente de zero em caso de falha.

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <errno.h>
#endif
#include <string.h>

#ifndef SOMAXCONN
#define SOMAXCONN 128 // Valor padrão se SOMAXCONN não estiver definido
#endif

#define MAX_HOST 256
#define MAX_SERV 64

//returns 0 on success, non-zero on failure
/*
--[[[
    \fn pswrap.escute
    \resumo Coloca um socket de servidor em modo de escuta (listen).
    \param socket {numero} - O handle do socket do servidor (criado com `pswrap.BIND`).
    \param backlog {numero} - O numero de conexoes pendentes permitidas na fila.
    \retorno sock {numero|nulo} - O handle do socket em sucesso, ou nulo.
    \retorno err {string|nulo} - Mensagem de erro se houver falha.
    
\codigo ex_escute.prisma
-- (continuacao do exemplo anterior)
local sucesso, err = pswrap.escute(sock_servidor, 128) -- 128 conexoes pendentes
se nao sucesso entao erro(err) fim
imprima("Servidor escutando na porta 12345...")
\codigo--

]]
funcao pswrap.escute(sock, backlog)
*/
funcao bind_swrapListen(sock, backlog) #[export escute]
    int sock = $.int(sock);
    int backlog = $.int(backlog);
    
    // Validação do socket
    char err_msg[256];
    puts("antes de validate");
    int ret_validate = validate_socket(sock, err_msg, sizeof(err_msg));
    if (ret_validate == -1) {
		printf("Socket: %d\n", sock);
		printf("Ret validate: %d\n", ret_validate);
		printf("------------------> %s\n", err_msg);
        retorne $.nulo, $.string(err_msg);
    }
    puts("depois de validate");
    
    // Validação do backlog
    if (backlog < 0) {
        retorne $.nulo, $.string("Backlog deve ser não negativo");
    }
    if (backlog > SOMAXCONN) {
        backlog = SOMAXCONN; // Limita ao máximo permitido pelo sistema
    }
    
    int ret = swrapListen(sock, backlog);
    if (ret != 0) {
        char buf[256];
         swrapGetLastSocketError(buf, sizeof(buf));
         retorne $.nulo, $.string(buf);
    }
    retorne $.int(sock);
fim


//SWDEF int swrapAccept(int, struct swrap_addr*);
// Usa o socket fornecido (deve estar configurado com SWRAP_TCP + SWRAP_BIND) para aceitar uma nova conexão,
// retornando opcionalmente o endereço da conexão.
// Retorna um handle de socket para a nova conexão ou -1 em caso de falha.

#ifdef _WIN32
#define TEST_RET_SOCK(sock) \
    if ((sock) == -1) { \
        int err = WSAGetLastError(); \
        char buf[512]; \
        DWORD len = FormatMessageA( \
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), \
            buf, sizeof(buf), NULL); \
        if (len == 0) strcpy(buf, "Unknown socket error"); \
        lua_pushnil(L); \
        lua_pushstring(L, buf); \
        return 2; \
    }
#else
#define TEST_RET_SOCK(sock) \
    if ((sock) == -1) { \
        char buf[512]; \
        strerror_r(errno, buf, sizeof(buf)); \
        lua_pushnil(L); \
        lua_pushstring(L, buf); \
        return 2; \
    }
#endif


/*
--[[[
    \fn pswrap.aceitar
    \resumo Aceita uma nova conexao em um socket de escuta.
    \param socket {numero} - O handle do socket do servidor (que esta escutando).
    \retorno cliente_socket {numero|nulo} - O handle do novo socket do cliente, ou nulo.
    \retorno ip_cliente {string|nulo} - O endereco IP do cliente conectado.
    
\codigo ex_aceitar.prisma
// (servidor em modo bloqueante, para exemplo)
local cliente, ip = pswrap.aceitar(sock_servidor)
se cliente entao
    imprima("Cliente conectado:", ip)
    pswrap.envie(cliente, "Ola!")
    pswrap.feche(cliente)
fim
\codigo--

]]

funcao pswrap.aceitar(socket)
*/
funcao swrapAccept(sock) #[export aceitar]
    int sock = $.int(sock);
    struct swrap_addr add = {0};
    
    // Validação do socket
    char err_msg[256];
    if (validate_socket(sock, err_msg, sizeof(err_msg)) != 0) {
        retorne $.nulo, $.string(err_msg);
    }
    
    int new_sock = swrapAccept(sock, &add);
    TEST_RET_SOCK(new_sock);
    retorne $.int(new_sock), $.string(add.data);
fim


//retorna as informações: host e porta ou nulo e mensagem de erro.
/*
--[[[
    \fn pswrap.endereco_info
    \resumo Obtem o endereco (host) e a porta de um socket em formato legivel.
    \param socket {numero} - O handle do socket (de servidor ou cliente).
    \retorno host {string|nulo} - O endereco de host (ex: "127.0.0.1") em sucesso, ou nulo em erro.
    \retorno porta {string} - O numero da porta (ex: "12345") em sucesso ou nulo em erro.
    \retorno err {string} - A string de erro em caso de falha.
\codigo ex_endereco_info.prisma
// Supondo que 'cliente_socket' seja um handle valido retornado por 'pswrap.aceitar'
local host, porta, err = pswrap.endereco_info(cliente_socket)

se host entao
    imprima("O cliente esta no host '" .. host .. "' na porta '" .. porta .. "'")
senao
    // 'err' (o terceiro retorno) contém a mensagem de erro
    imprima("Falha ao obter endereco: ", err)
fim
\codigo--

]]
funcao pswrap.endereco_info(socket)
*/
funcao swrapAddressInfo(sock) #[export endereco_info]
    int sock = $.int(sock);

    // Validação do socket
    char err_msg[256];
    if( validate_socket(sock, err_msg, sizeof(err_msg)) != 0 ){
        retorne $.nulo, $.nulo, $.string(err_msg);
    }

    struct swrap_addr add = {0};
    int ret = swrapAddress(sock, &add);
    if( ret != 0 ){
        retorne $.nulo, $.nulo, $.string("Erro em função swrap.endereco");
    }

    // Converter para host e porta legíveis
    char host[MAX_HOST] = {0};;
    char serv[MAX_SERV] = {0};
    if( swrapAddressInfo(&add, host, sizeof(host), serv, sizeof(serv)) != 0) {
        retorne $.nulo, $.nulo, $.string("Erro ao converter endereço");
    }

    // Retorno múltiplo: host, porta
    retorne $.string(host), $.string(serv);
fim




/*
--[[[
    \fn pswrap.envie
    \resumo Envia dados (string) para um socket conectado (TCP).
    \param socket {numero} - O handle do socket (geralmente um cliente).
    \param dados {string} - Os dados a serem enviados.
    \param tamanho {numero|nulo} - (Opcional) O numero de bytes a enviar.
    \retorno bytes_enviados {numero|nulo} - O numero de bytes enviados, ou nulo em caso de erro.
    \retorno err {string|nulo} - Mensagem de erro.
    
\codigo ex_envie.prisma
local http_resp = "HTTP/1.1 200 OK\r\n\r\nOla Mundo!"
pswrap.envie(cliente_socket, http_resp)
\codigo--

]]

funcao pswrap.envie (socket, dados, tamanho)

*/

funcao swrapSend(sock, data, size_data) #[export envie]
    int sock = $.int(sock);
    // Validação do socket
    char err_msg[256];
    if(validate_socket(sock, err_msg, sizeof(err_msg)) != 0) {
        retorne $.nulo, $.string(err_msg);
    }
    size_t len_data = 0;
    const char *data = luaL_checklstring(L, 2, &len_data);
    if ($.is_number(size_data)){
		len_data = $.int(size_data);
	}
	int ret = swrapSend(sock, data, len_data);
	if( ret == -1 ){
		retorne $.nulo, $.string("Erro ao enviar dados.");
	}
	retorne $.int(ret);
fim


/*
--[[[
    \fn pswrap.receba
    \resumo Recebe dados de um socket conectado (TCP).
    \param socket {numero} - O handle do socket.
    \param tamanho {numero|nulo} - (Opcional) O numero maximo de bytes para ler (padrao: 1024).
    \retorno dados {string|nulo} - Os dados recebidos, ou nulo (se erro ou conexao fechada).
    \retorno bytes_recebidos {numero|nulo} - O numero de bytes recebidos (0 se cliente desconectou).
    
\codigo ex_receba.prisma
local dados, bytes = pswrap.receba(cliente_socket, 2048)
se dados e bytes > 0 entao
    imprima("Cliente disse:", dados)
senao
    imprima("Cliente desconectou.")
fim
\codigo--

]]
funcao pswrap.receba(socket, tamanho)
*/
funcao swrapReceive(sock, size) #[export receba]
    int sock = $.int(sock);
    // Validação do socket
    char err_msg[256];
    if(validate_socket(sock, err_msg, sizeof(err_msg)) != 0) {
        retorne $.nulo, $.string(err_msg);
    }
    size_t len_data = 1024;
    if($.is_number(size)){
	    len_data = $.int(size);
	}
    char *buf = malloc(len_data);
    int ret = swrapReceive(sock, buf, len_data);
    if(ret==-1){
		free(buf);
		retorne $.nulo, $.string("Erro ao receber dados.");
	}
    lua_pushlstring(L, buf, ret);
    free(buf);
    lua_pushinteger(L, ret);
    return 2;
fim 

/*
--[[[
    \fn pswrap.envie_para
    \resumo Envia dados (string) para um destino UDP (sem conexao).
    \param sock {numero} - O handle do socket UDP.
    \param host {string} - O endereco IP de destino (ex: "127.0.0.1").
    \param port {string} - A porta de destino (ex: "9000").
    \param data {string} - Os dados (string) a serem enviados.
    \param size {numero|nulo} - (Opcional) O numero de bytes a enviar.
    \retorno bytes_enviados {numero|nulo} - O numero de bytes enviados, ou nulo em erro.
    \retorno err {string|nulo} - Mensagem de erro.
    
\codigo ex_envie_para.prisma
local pswrap = inclua'pswrap'
-- (Assume que 'udp_sock' foi criado com pswrap.socket(pswrap.UDP, ...))
local host_destino = "127.0.0.1"
local porta_destino = "9000"

local bytes, err = pswrap.envie_para(udp_sock, host_destino, porta_destino, "Ola UDP!")
se nao bytes entao
    erro(err)
fim
imprima("Enviados " .. bytes .. " bytes.")
\codigo--

]]
funcao pswrap.envie_para(sock, host, port, data, size)
*/
funcao swrapSendTo(sock, host, port, data, size) #[export envie_para]
    int sock = $.int(sock);

    // Validação do socket
    char err_msg[256];
    if( validate_socket(sock, err_msg, sizeof(err_msg)) != 0 ){
        retorne $.nulo, $.string(err_msg);
    }

    // Resolver endereço destino
    struct swrap_addr addr = {0};
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;         // IPv4
    hints.ai_socktype = SOCK_DGRAM;    // UDP

    if(getaddrinfo($.string(host), $.string(port), &hints, &res) != 0){
        retorne $.nulo, $.string("Erro ao resolver endereço UDP");
    }

    memcpy(&addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    // Preparar dados
    size_t len_data = 0;
    const char *data_ptr = luaL_checklstring(L, 4, &len_data);
    if ($.is_number(size)){
        len_data = $.int(size);
    }

    // Enviar dados
    int ret = swrapSendTo(sock, &addr, data_ptr, len_data);
    if( ret == -1 ){
        retorne $.nulo, $.string("Erro ao enviar dados UDP");
    }

    retorne $.int(ret);
fim


/*
--[[[
    \fn pswrap.receba_de
    \resumo Recebe dados de um socket UDP, retornando tambem o remetente.
    \param sock {numero} - O handle do socket UDP (geralmente em modo `BIND`).
    \param tamanho {numero|nulo} - (Opcional) O tamanho maximo do buffer (padrao: 1024).
    \retorno dados {string|nulo} - Os dados recebidos, ou nulo em erro.
    \retorno host {string} - Em sucesso, o host do remetente ou nulo em erro.
    \retorno porta {string|nulo} - Em sucesso, a porta do remetente. Nulo em caso de erro.
    \retorno err {string|nulo} - String de erro em caso de erro ou nulo.
    
\codigo ex_receba_de.prisma
local pswrap = inclua'pswrap'
// (Assume que 'udp_sock' e um servidor UDP em 'BIND' na porta 9000)

imprima("Servidor UDP esperando por dados...")
local dados, host, porta, err = pswrap.receba_de(udp_sock, 2048)

se dados entao
    imprima("Recebido '" .. dados .. "' de " .. host .. ":" .. porta)
senao
    // 'err' (o quarto retorno) contem a string de erro
    erro(err) 
fim
\codigo--

]]
funcao pswrap.receba_de(sock, tamanho)
*/

funcao swrapReceiveFrom(sock, size) #[export receba_de]
    int sock = $.int(sock);
    char err_msg[256];
    if(validate_socket(sock, err_msg, sizeof(err_msg)) != 0){
        retorne $.nulo, $.nulo, $.nulo, $.string(err_msg);
    }
    
    int len_data = 1024;
    if( $.is_number(size) ){
        len_data = $.int(size);
    }
    
    char *buff = malloc(len_data);
    struct swrap_addr addr = {0};
    
    int ret = swrapReceiveFrom(sock, &addr, buff, len_data);
    if( ret == -1 ){
        free(buff);
        retorne $.nulo, $.nulo, $.nulo, $.string("Erro ao receber dados UDP");
    }
    
   //  Converte endereço do remetente
    char host[MAX_HOST] = {0};
    char serv[MAX_SERV] = {0};
    if( swrapAddressInfo(&addr, host, sizeof(host), serv, sizeof(serv)) != 0 ){
        free(buff);
        retorne $.nulo, $.nulo, $.nulo, $.string("Erro ao converter endereço UDP");
    }
    
    lua_pushlstring(L, buff, ret);
    free(buff);
    lua_pushstring(L, host);
    lua_pushstring(L, serv);
    return 3;
fim


/*
--[[[
    \fn pswrap.seletor
    \resumo Verifica (sonda) um *unico* socket por atividade de leitura.
    \obs Esta é uma sonda para um unico socket. Para monitorar múltiplos sockets (recomendado para servidores), use `pswrap.multi_seletor`.
    \param sock {numero} - O handle do socket a ser verificado.
    \param timeout {numero|nulo} - O tempo maximo para esperar (em segundos). Se 0.0, retorna imediatamente (sondagem/poll).
    \retorno status {numero|nulo} - 1 (pronto), 0 (timeout), ou nulo (erro).
    \retorno err {string|nulo} - Mensagem de erro.
    
\codigo ex_seletor.prisma
local pswrap = inclua'pswrap'
-- (Assume 'cliente_socket' valido)

-- Pergunta: O cliente_socket tem dados *agora*? (timeout 0.0)
local status, err = pswrap.seletor(cliente_socket, 0.0)

se status == 1 entao
    imprima("Socket esta pronto para ler!")
    local dados = pswrap.receba(cliente_socket)
senaose status == 0 entao
    imprima("Socket nao tem dados (timeout).")
senao
    erro(err)
fim
\codigo--

]]
funcao pswrap.seletor(sock, timeout)
*/
funcao swrapSelect(sock, timeout) #[export seletor]
    int sock = $.int(sock);
    double t = 0.0;
    if ( $.is_number(timeout) ){
        t = $.number(timeout);
    }
    
    int ret = swrapSelect(sock, t);
    if( ret == -1 ){
        retorne $.nulo, $.string("Erro no select");
    }
    
    retorne $.int(ret);
fim

//  multselect({1,2,3,4,5}, 5.0);
//returns 1 or more if new data is available, 0 if timeout was reached, and -1 on error
/*
--[[[
    \fn pswrap.multi_seletor
    \resumo Monitora uma lista de sockets e espera ate que um deles tenha atividade (leitura).
    \param lista_sockets {tabela} - Uma tabela (lista) de handles de socket para monitorar.
    \param timeout {numero} - O tempo maximo para esperar (em segundos).
    \retorno socket_pronto {numero|nulo} - O handle do socket que esta pronto, ou nulo (se timeout ou erro).
    \retorno err {string|nulo} - Mensagem de erro (ex: "Tempo limite atingido.").
    \retorno codigo {numero|nulo} - 1 (sucesso), 0 (timeout), ou -1 (erro).
    
\codigo ex_multi_seletor.prisma
-- (loop de eventos assincrono)
local todos_sockets = { [sock_servidor] = verdadeiro }
local lista_c = { sock_servidor }

local socket_pronto, err, codigo = pswrap.multi_seletor(lista_c, 60.0)

se codigo == 1 entao
    -- Sucesso, 'socket_pronto' tem o handle
    se socket_pronto == sock_servidor entao
        -- ... (aceita novo cliente)
    senao
        -- ... (recebe dados do cliente)
    fim
senaose codigo == 0 entao
    -- Apenas um timeout
senao
    -- Erro
    erro(err)
fim
\codigo--

]]
funcao pswrap.multi_seletor(lista_sockets, timeout)
*/
funcao swrapMultiSelect(list, timeout) #[export multi_seletor]
    // 1º argumento: tabela
    luaL_checktype(L, 1, LUA_TTABLE);

    size_t len = $.#list;
    int *socks = malloc(len * sizeof(int));
    if(!socks){
        retorne $.nulo, $.string("Erro ao alocar memória em swrap.multiselect");
    }

    // Copia os valores da tabela para o array de inteiros
    for (size_t i = 1; i <= len; i++) {
        lua_rawgeti(L, 1, i); 
        socks[i-1] = luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    double t = 0.0;
    if ($.is_number(timeout)) {
        t = $.number(timeout);
    }

    int ret = swrapMultiSelect(socks, len, t);

    free(socks); // <- sempre liberar antes de retornar

    if (ret == -1) {
        retorne $.nulo, $.string("Erro no multi select."), $.number(-1);
    } else if (ret == 0) {
        retorne $.nulo, $.string("Tempo limite atingido."), $.number(0);
    }

    retorne $.int(ret), $.string("Ok"), $.number(1);
fim




/*
--[[[
    \fn pswrap.obt_ultimo_erro
    \resumo Retorna a última mensagem de erro de socket ocorrida na thread atual.
    \obs Útil para depurar falhas em funções que retornam `nulo` sem uma mensagem de erro explícita.
    \retorno err_msg {string} - A descrição do último erro de socket.
    
\codigo ex_obt_ultimo_erro.prisma
local sucesso, err = pswrap.escute(sock_servidor, 128)
se nao sucesso entao
    -- 'err' aqui pode ser generico, pegamos o erro especifico:
    local erro_real = pswrap.obt_ultimo_erro()
    erro("Falha ao escutar: " .. erro_real)
fim
\codigo--

funcao pswrap.obt_ultimo_erro()

]]
*/

funcao swrapGetLastSocketError() #[export obt_ultimo_erro]
    char str_err[256] = {0};
    swrapGetLastSocketError(str_err, sizeof(str_err));
    //printf("Último erro de socket: %s\n", err);
    retorne $.string(str_err);
fim

/*
--[[[
    \var swrap.TCP
    \resumo Valor (0) que define o protocolo do socket como TCP (orientado à conexão).
    \obs Garante entrega confiável e ordenada de dados. É o padrão para HTTP. Usado no parâmetro 'protocolo' de `pswrap.socket`.
]]
swrap.TCP = SWRAP_TCP

--[[[
    \var swrap.UDP
    \resumo Valor (1) que define o protocolo do socket como UDP (datagramas).
    \obs Envio rápido, mas não-confiável. Não há garantia de entrega ou ordem. Usado no parâmetro 'protocolo' de `pswrap.socket`.
]]
swrap.UDP = SWRAP_UDP

--[[[
    \var swrap.SERVIDOR
    \resumo Valor (0) que define o modo do socket para 'BIND' (escuta/servidor).
    \obs Prepara o socket para escutar em um host e porta, pronto para 'pswrap.escute'. Usado no parâmetro 'modo' de `pswrap.socket`.
]]
swrap.SERVIDOR = SWRAP_BIND

--[[[
    \var swrap.CLIENTE
    \resumo Valor (1) que define o modo do socket para 'CONNECT' (cliente).
    \obs Faz com que o socket tente se conectar a um host e porta remotos. Usado no parâmetro 'modo' de `pswrap.socket`.
]]
swrap.CLIENTE = SWRAP_CONNECT
--[[[
    \var swrap.PADRAO
    \resumo Valor (0) para o parâmetro 'flags' de `pswrap.socket`.
    \obs Nenhuma flag especial é ativada. O socket operará em modo padrão (bloqueante, com Nagle).
]]
swrap.PADRAO = SWRAP_DEFAULT

--[[[
    \var swrap.NAO_BLOQUEANTE
    \resumo Flag (1) que define o socket para o modo 'não-bloqueante' (non-blocking).
    \obs Faz com que chamadas como 'aceitar' ou 'receba' retornem imediatamente, mesmo sem dados. Não é necessário se você usa `pswrap.multi_seletor`, pois ele já gerencia o bloqueio.
]]
swrap.NAO_BLOQUEANTE = SWRAP_NOBLOCK

--[[[
    \var swrap.SEM_ESPERA
    \resumo Flag (2) que desativa o Algoritmo de Nagle (TCP_NODELAY).
    \obs Envia pacotes pequenos imediatamente. Útil para apps de baixa latência (ex: jogos). Pode ter um pequeno custo de performance em troca de responsividade.
]]
swrap.SEM_ESPERA = SWRAP_NODELAY

*/

$.const_int{
SWRAP_TCP #[export TCP]
SWRAP_UDP #[export UDP]
SWRAP_BIND #[export SERVIDOR]
SWRAP_CONNECT #[export CLIENTE]
SWRAP_DEFAULT #[export PADRAO]
SWRAP_NOBLOCK #[export NAO_BLOQUEANTE]
SWRAP_NODELAY #[export SEM_ESPERA]
}

    
