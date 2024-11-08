#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <WinSock.h>
#pragma comment(lib, "Ws2_32.lib")

void print_MACADDR(FILE* out, char* MAC) {
    for (int i = 0; i < 5; i++) {
        fprintf(out, "%02X:", (unsigned char)MAC[i]);
    }
    fprintf(out, "%02X\n", (unsigned char)MAC[5]);
}

void print_IPADDR(FILE* out, char* IP) {
    for (int i = 0; i < 3; i++) {
        fprintf(out, "%d.", (unsigned char)IP[i]);
    }
    fprintf(out, "%d\n", (unsigned char)IP[3]);
}

int main() {
    setlocale(LC_ALL, "Rus");
    FILE* in = nullptr;
    FILE* out = nullptr;

    char fname[15];
    int fsize = 0;
    bool file_opened = false;

    // Чтение имени файла с проверкой открытия
    while (!file_opened) {
        printf("Введите имя файла: ");
        scanf("%s", fname);
        in = fopen(fname, "rb");
        if (in != nullptr)
            file_opened = true;
        else
            printf("Ошибка открытия файла\n");
    }

    out = fopen("out.txt", "w");

    // Определяем размер файла
    fseek(in, 0, SEEK_END);
    fsize = ftell(in);
    fseek(in, 0, SEEK_SET);
    fprintf(out, "Размер файла: %d байт\n\n", fsize);

    // Чтение данных из файла
    char* DATA = new char[fsize];
    fread(DATA, fsize, 1, in);
    fclose(in);

    char* d = DATA;
    int frames = 1;
    size_t type_count[5] = { 0 };

    // Цикл обработки каждого фрейма
    while (d < DATA + fsize) {
        fprintf(out, "Фрейм: %d\n", frames);
        fprintf(out, "MAC-адрес получателя: ");
        print_MACADDR(out, d); // первые 6 байтов - адрес назначения
        fprintf(out, "MAC-адрес отправителя: ");
        print_MACADDR(out, d + 6); // следующие 6 байтов - адрес отправителя

        unsigned short type = ntohs(*(unsigned short*)(d + 12)); // определяем тип фрейма

        // Отладочный вывод типа фрейма
        fprintf(out, "Тип (raw): 0x%04X\n", type);

        if (type == 0x0800) { // Если фрейм - IPv4
            fprintf(out, "Тип фрейма: IPv4\n");
            fprintf(out, "IP-адрес отправителя: ");
            print_IPADDR(out, d + 26);
            fprintf(out, "IP-адрес получателя: ");
            print_IPADDR(out, d + 30);

            int ip_total_length = ntohs(*(unsigned short*)(d + 16)); // длина IP пакета
            d += ip_total_length + 14; // смещаем указатель для перехода к следующему фрейму
            type_count[0]++;
        }
        else if (type > 0x05DC) { // Если фрейм - Ethernet DIX (II)
            fprintf(out, "Тип фрейма: Ethernet DIX (II)\n");
            d += 1500 + 14; // фиксированный переход для Ethernet DIX (II)
            type_count[1]++;
        }
        else { // Если фрейм - IEEE 802.3
            unsigned short F = ntohs(*(unsigned short*)(d + 14)); // первые 2 байта данных

            // Отладочный вывод F
            fprintf(out, "F (raw): 0x%04X\n", F);

            if (F == 0xFFFF) {
                fprintf(out, "Тип фрейма: Novell 802.3\n");
                type_count[2]++;
            }
            else if (F == 0xAAAA) {
                fprintf(out, "Тип фрейма: Ethernet SNAP\n");
                type_count[3]++;
            }
            else {
                fprintf(out, "Тип фрейма: 802.3/LLC (Ethernet 802.2)\n");
                type_count[4]++;
            }
            d += 1500 + 14; // переход для других типов фреймов
        }
        fprintf(out, "\n-------------------------------\n");
        frames++;
    }

    // Итоговая статистика
    fprintf(out, "Общее число фреймов: %d\n", frames - 1);
    fprintf(out, "IPv4: %d\n", type_count[0]);
    fprintf(out, "Ethernet DIX (II): %d\n", type_count[1]);
    fprintf(out, "Novell 802.3: %d\n", type_count[2]);
    fprintf(out, "Ethernet SNAP: %d\n", type_count[3]);
    fprintf(out, "802.3/LLC: %d\n", type_count[4]);

    fclose(out);
    delete[] DATA;
    system("pause");
    return 0;
}
