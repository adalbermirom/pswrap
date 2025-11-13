#!/bin/bash
# Este e o script de build principal.
# Ele apenas executa o 'plibc', que faz todo o trabalho.

echo "-> Executando o 'plibc' (transpilador + compilador)..."

# --- Escolha a opcao que funciona para voce ---

#gerando documentação:
./minidoc pswrap.plib.c
# Opcao 1: Se 'plibc' e um executavel
./plibc pswrap.plib.c

# -----------------------------------------------

# Verifica se o plibc falhou
if [ $? -ne 0 ]; then
    echo "Erro: O 'plibc' falhou."
    exit 1
fi

echo "-> Processo concluido!"
