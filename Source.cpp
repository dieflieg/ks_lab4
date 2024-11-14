#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <WinSock.h>
#pragma comment(lib, "Ws2_32.lib")

// ������� MAC-����� (6 ����) � �������� ������� XX:XX:XX:XX:XX:XX
void print_MACADDR(FILE* out, char* MAC) {
    for (int i = 0; i < 5; i++) {
        fprintf(out, "%02X:", (unsigned char)MAC[i]);
    }
    fprintf(out, "%02X\n", (unsigned char)MAC[5]);
}

// ������� IP-����� (4 �����) � ������� X.X.X.X.
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

    // ������ ����� ����� � ��������� ��������
    while (!file_opened) {
        printf("������� ��� �����: ");
        scanf("%s", fname);
        in = fopen(fname, "rb");
        if (in != nullptr)
            file_opened = true;
        else
            printf("������ �������� �����\n");
    }

    out = fopen("out.txt", "w");

    // ���������� ������ �����
    fseek(in, 0, SEEK_END);
    fsize = ftell(in);
    fseek(in, 0, SEEK_SET);
    fprintf(out, "������ �����: %d ����\n\n", fsize);

    // ������ ������ �� �����
    char* DATA = new char[fsize];
    fread(DATA, fsize, 1, in);
    fclose(in);

    char* d = DATA;
    int frames = 1;
    size_t type_count[5] = { 0 };
    size_t packet_count[3] = { 0 }; // IPv4, ARP, IPX

    // ���� ��������� ������� �����
    while (d < DATA + fsize) {
        fprintf(out, "����: %d\n", frames);
        fprintf(out, "MAC-����� ����������: ");
        print_MACADDR(out, d); // ������ 6 ������ - ����� ����������
        fprintf(out, "MAC-����� �����������: ");
        print_MACADDR(out, d + 6); // ��������� 6 ������ - ����� �����������

        unsigned short type = ntohs(*(unsigned short*)(d + 12)); // ���������� ���/����� �����
        int frame_size = 14; // �������������� ������ ���������� Ethernet (14 ���� = ����� ��� ������� (6 + 6) + ����� ���� type/lenght)

        if (type > 0x05DC) { // ���� �������� ���� type/lenght > 0x05DC, �� ��� Ethernet DIX (II)
            fprintf(out, "��� �����: Ethernet DIX (II)\n");

            if (type == 0x0800) { // ��������, ����������� �� ��������� ����� ���� IPv4
                fprintf(out, "Type: IPv4\n");
                packet_count[0]++; // ����������� ������� IPv4 �������
                int ip_total_length = ntohs(*(unsigned short*)(d + 16)); // ����� IP ������ 
                frame_size += ip_total_length; // ������ ������ ������ = ����� Ethernet ��������� + ����� ���������� IP ������
                fprintf(out, "����� IPv4 ������: %d ����\n", ip_total_length);
                // ����� IP-�������
                fprintf(out, "IP-����� �����������: ");
                print_IPADDR(out, d + 26); // IP ����������� �� 27-30 ������ �����
                fprintf(out, "IP-����� ����������: ");
                print_IPADDR(out, d + 30); // IP ���������� �� 31-34 ������ �����
            }
            else if (type == 0x0806) { // ��������, ����������� �� ��������� ����� ���� ARP
                fprintf(out, "Type: ARP\n");
                packet_count[1]++; // ����������� ������� ARP �������
                fprintf(out, "����� ARP ������: 28 ����\n");
                int arp_packet_length = 28; // ������������� ������ ARP ������ � ������
                frame_size += arp_packet_length; // ������ ������ ������ = ����� Ethernet ��������� + ����� ARP ������

                // ����� IP-�������
                fprintf(out, "IP-����� �����������: ");
                print_IPADDR(out, d + 28); // IP ����������� �� 15-18 ������ ������
                fprintf(out, "IP-����� ����������: ");
                print_IPADDR(out, d + 38); // IP ���������� �� 25-28 ������ ������

            }
            else if (type == 0x8137 || type == 0x8138) { // ��������, ����������� �� ��������� ����� ���� Novell IPX
                fprintf(out, "Type: Novell IPX\n");
                packet_count[2]++; // ����������� ������� IPX �������
                int ipx_packet_length = ntohs(*(unsigned short*)(d + 16)); // ������ IPX ������ (� ������) �� 3-4 ������ ������
                frame_size += ipx_packet_length; // ������ ������ ������ = ����� Ethernet ��������� + ����� IPX ������

                // �������������� ��������� IPX-������ 
                fprintf(out, "����� IPX ������: %d ����\n", ipx_packet_length);
            }
            else {
                // ��������� ������ ��� ������������ ����
                fprintf(out, "������: ������� �������� ������������ ����. ���������� ���������� ������� ���������� �����.\n");
                fprintf(out, "\n-------------------------------\n");
                break; // ����� �� ����� ��������� �������
            }

            d += frame_size; // ������� ��������� ��� �������� � ���������� ������
            type_count[1]++;
        }

        else {
            frame_size += type; // ��� ���� ��������� ����� ����� ����� �������� ���� length + ����� Ethernet ���������

            unsigned short F = ntohs(*(unsigned short*)(d + 14)); // ��������� 2 ����� ����� ���� length

            // ����������� ���� ����� �� 15-16 ������ 
            if (F == 0xFFFF) { // ���� ������ ����� Raw 802.3 ������ ���������� � ���� ������, ���������� 0�FFFF
                fprintf(out, "��� �����: Raw 802.3/Novell 802.3\n");
                type_count[2]++;
            }
            else if (F == 0xAAAA) { // ���� DSAP � SSAP ��������� LLC ��� ����� ��� 0���, ���������� ��� ��������� SNAP
                fprintf(out, "��� �����: Ethernet SNAP\n");

                // ��������, ����������� �� �����, ��������� � ����  Ethernet SNAP, ���� IPv4
                if (ntohs(*(unsigned short*)(d + 20)) == 0x0800) { // 21-22 �����
                    fprintf(out, "Type: IPv4\n");
                    packet_count[0]++; // ����������� ������� IPv4 �������
                    fprintf(out, "����� IPv4 ������: %d ����\n", frame_size - 14);
                    // ����� IP-�������
                    fprintf(out, "IP-����� �����������: ");
                    print_IPADDR(out, d + 34); // IP ����������� �� 35-38 ������
                    fprintf(out, "IP-����� ����������: ");
                    print_IPADDR(out, d + 38); // IP ���������� �� 39-42 ������
                }

                type_count[3]++;
            }
            else {
                fprintf(out, "��� �����: 802.3/LLC\n");
                type_count[4]++;
            }
            d += frame_size; // ������� � ���������� ������, ��������� �����
        }

        fprintf(out, "������ �����: %d ����\n", frame_size);
        fprintf(out, "\n-------------------------------\n");
        frames++;
    }

    // �������� ����������
    fprintf(out, "����� ����� ������������ ������: %d\n", frames - 1);
    fprintf(out, "Ethernet DIX (II): %d\n", type_count[1]);
    fprintf(out, "Raw 802.3/Novell 802.3: %d\n", type_count[2]);
    fprintf(out, "Ethernet SNAP: %d\n", type_count[3]);
    fprintf(out, "802.3/LLC: %d\n", type_count[4]);
    fprintf(out, "�� ���:\n");
    fprintf(out, "IPv4 ������: %d\n", packet_count[0]);
    fprintf(out, "ARP ������: %d\n", packet_count[1]);
    fprintf(out, "IPX ������: %d\n", packet_count[2]);

    // ������������ ���������� ������
    delete[] DATA;
    fclose(out);
    printf("������ ���������. ���������� ��������� � out.txt\n");
    return 0;
}
