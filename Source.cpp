#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <WinSock.h>
#pragma comment(lib, "Ws2_32.lib")

// выводит MAC-адрес (6 байт) в читаемом формате XX:XX:XX:XX:XX:XX
void print_MACADDR(FILE* out, char* MAC) {
    for (int i = 0; i < 5; i++) {
        fprintf(out, "%02X:", (unsigned char)MAC[i]);
    }
    fprintf(out, "%02X\n", (unsigned char)MAC[5]);
}

// выводит IP-адрес (4 байта) в формате X.X.X.X.
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
    size_t packet_count[3] = { 0 }; // IPv4, ARP, IPX

    // Цикл обработки каждого кадра
    while (d < DATA + fsize) {
        fprintf(out, "Кадр: %d\n", frames);
        fprintf(out, "MAC-адрес получателя: ");
        print_MACADDR(out, d); // первые 6 байтов - адрес назначения
        fprintf(out, "MAC-адрес отправителя: ");
        print_MACADDR(out, d + 6); // следующие 6 байтов - адрес отправителя

        unsigned short type = ntohs(*(unsigned short*)(d + 12)); // определяем тип/длину кадра
        int frame_size = 14; // Инициализируем размер заголовком Ethernet (14 байт = длина мак адресов (6 + 6) + длина поля type/lenght)

        if (type > 0x05DC) { // если значение поля type/lenght > 0x05DC, то это Ethernet DIX (II)
            fprintf(out, "Тип кадра: Ethernet DIX (II)\n");

            if (type == 0x0800) { // проверка, принадлежит ли вложенный пакет типу IPv4
                fprintf(out, "Type: IPv4\n");
                packet_count[0]++; // Увеличиваем счетчик IPv4 пакетов
                int ip_total_length = ntohs(*(unsigned short*)(d + 16)); // длина IP пакета 
                frame_size += ip_total_length; // полный размер фрейма = длина Ethernet заголовка + длина вложенного IP пакета
                fprintf(out, "Длина IPv4 пакета: %d байт\n", ip_total_length);
                // Вывод IP-адресов
                fprintf(out, "IP-адрес отправителя: ");
                print_IPADDR(out, d + 26); // IP отправителя на 27-30 байтах кадра
                fprintf(out, "IP-адрес получателя: ");
                print_IPADDR(out, d + 30); // IP получателя на 31-34 байтах кадра
            }
            else if (type == 0x0806) { // проверка, принадлежит ли вложенный пакет типу ARP
                fprintf(out, "Type: ARP\n");
                packet_count[1]++; // Увеличиваем счетчик ARP пакетов
                fprintf(out, "Длина ARP пакета: 28 байт\n");
                int arp_packet_length = 28; // фиксированный размер ARP пакета в байтах
                frame_size += arp_packet_length; // полный размер фрейма = длина Ethernet заголовка + длина ARP пакета

                // Вывод IP-адресов
                fprintf(out, "IP-адрес отправителя: ");
                print_IPADDR(out, d + 28); // IP отправителя на 15-18 байтах пакета
                fprintf(out, "IP-адрес получателя: ");
                print_IPADDR(out, d + 38); // IP получателя на 25-28 байтах пакета

            }
            else if (type == 0x8137 || type == 0x8138) { // проверка, принадлежит ли вложенный пакет типу Novell IPX
                fprintf(out, "Type: Novell IPX\n");
                packet_count[2]++; // Увеличиваем счетчик IPX пакетов
                int ipx_packet_length = ntohs(*(unsigned short*)(d + 16)); // размер IPX пакета (в байтах) из 3-4 байтов пакета
                frame_size += ipx_packet_length; // полный размер фрейма = длина Ethernet заголовка + длина IPX пакета

                // Дополнительная обработка IPX-пакета 
                fprintf(out, "Длина IPX пакета: %d байт\n", ipx_packet_length);
            }
            else {
                // Обработка ошибки для неизвестного типа
                fprintf(out, "Ошибка: Сетевой протокол неизвестного типа. Невозможно определить границы следующего кадра.\n");
                fprintf(out, "\n-------------------------------\n");
                break; // Выход из цикла обработки фреймов
            }

            d += frame_size; // смещаем указатель для перехода к следующему фрейму
            type_count[1]++;
        }

        else {
            frame_size += type; // для всех остальных типов длина равна значению поля length + длина Ethernet заголовка

            unsigned short F = ntohs(*(unsigned short*)(d + 14)); // следующие 2 байта после поля length

            // Определение типа кадра по 15-16 байтам 
            if (F == 0xFFFF) { // поле данных кадра Raw 802.3 всегда начинается с двух байтов, содержащих 0хFFFF
                fprintf(out, "Тип кадра: Raw 802.3/Novell 802.3\n");
                type_count[2]++;
            }
            else if (F == 0xAAAA) { // поля DSAP и SSAP заголовка LLC оба имеют код 0хАА, отведенный для протокола SNAP
                fprintf(out, "Тип кадра: Ethernet SNAP\n");

                // проверка, принадлежит ли пакет, вложенный в кадр  Ethernet SNAP, типу IPv4
                if (ntohs(*(unsigned short*)(d + 20)) == 0x0800) { // 21-22 байты
                    fprintf(out, "Type: IPv4\n");
                    packet_count[0]++; // Увеличиваем счетчик IPv4 пакетов
                    fprintf(out, "Длина IPv4 пакета: %d байт\n", frame_size - 14);
                    // Вывод IP-адресов
                    fprintf(out, "IP-адрес отправителя: ");
                    print_IPADDR(out, d + 34); // IP отправителя на 35-38 байтах
                    fprintf(out, "IP-адрес получателя: ");
                    print_IPADDR(out, d + 38); // IP получателя на 39-42 байтах
                }

                type_count[3]++;
            }
            else {
                fprintf(out, "Тип кадра: 802.3/LLC\n");
                type_count[4]++;
            }
            d += frame_size; // переход к следующему фрейму, используя длину
        }

        fprintf(out, "Размер кадра: %d байт\n", frame_size);
        fprintf(out, "\n-------------------------------\n");
        frames++;
    }

    // Итоговая статистика
    fprintf(out, "Общее число обработанных кадров: %d\n", frames - 1);
    fprintf(out, "Ethernet DIX (II): %d\n", type_count[1]);
    fprintf(out, "Raw 802.3/Novell 802.3: %d\n", type_count[2]);
    fprintf(out, "Ethernet SNAP: %d\n", type_count[3]);
    fprintf(out, "802.3/LLC: %d\n", type_count[4]);
    fprintf(out, "Из них:\n");
    fprintf(out, "IPv4 пакеты: %d\n", packet_count[0]);
    fprintf(out, "ARP пакеты: %d\n", packet_count[1]);
    fprintf(out, "IPX пакеты: %d\n", packet_count[2]);

    // Освобождение выделенной памяти
    delete[] DATA;
    fclose(out);
    printf("Работа завершена. Результаты сохранены в out.txt\n");
    return 0;
}
