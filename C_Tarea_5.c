#include <stdio.h>

#define SIZE_FRAME 500
#define AMMOUNT_FRAMES 20

struct ip_frame{
	char *version;
	char *heder_size;
	short *total_length;
	char *protocol;				// Al ser requerido se le debe sumar 1 al apuntador para tener todo el dato
	short *checksum;
	int *ip_destiny;
	int *ip_origin;
	
	char *frame;
	struct *tcp_frame=NULL;
	struct *udp_frame=NULL;
};

struct tcp_frame{
	short *port_origin;
	short *port_destiny;
	int *sequence_number;
	char *ack_number;			// Solo se usa un bit (de ixquierda a derecha en cuarto elemento, doceava posición)
	char *heder_length;
	char *control;				// Son 6 bits (se accederá primero a cuatro y luego a dos de otros 4)
	short *checksum;
	char *data;					// Dependiend del tamaño de datos hay que ingrementar este puntero para realizar la lectura
};

struct udp_frame{
	short *port_origin;
	short *port_destiny;
	short *mesage_length;
	short *checksum;
	char *data;
};

char fill_ip_frame(char *frame, struct ip_frame *ip);
void fill_tcp_frame(char *frame, struct tcp_frame *tcp);
void fill_udp_frame(char *frame, struct udp_frame *udp);
void print_tcp_results(struct ip_frame *ip, int frame_number);
void print_udp_results(struct ip_frame *ip, int frame_number);

int int main(char const *argv[]){
	char frames[AMMOUNT_FRAMES][SIZE_FRAME];
	struct ip_frame *ip_frames[AMMOUNT_FRAMES];
	struct tcp_frame *tcp_frames[AMMOUNT_FRAMES];
	struct udp_frame *udp_frames[AMMOUNT_FRAMES];
	int ip_counter=0, udp_counter=0, tcp_counter=0;

	// Leer archivo
    
    // for para copiar todos los frames a memoria
		// Llenar elemento del array de frames
	// fin del for

	// Cerrar el archivo

	// for que cicla entre los elementos del buffer (frames)
		// Lenar la estructura IP

		//Checar tipo de protocolo
		//Si es TCP llenar estructura TCP
			//Usar un espacio del array TCP que coincida con IP e incrementar el contador de TCP
		//Si es UDP llenar estructura UDP
			//Usar un espacio del array UDP que coincida con IP e incrementar el contador de UDP


		// Imprimir en consola
	//fin del for

	// Imprimir datos generales de la ejecuciós

	return 0;
}

char fill_ip_frame(char *frame, struct ip_frame *ip){
	// Faltante de definir
}

void fill_tcp_frame(char *frame, struct tcp_frame *tcp){
	// Faltante de definir
}

void fill_udp_frame(char *frame, struct udp_frame *udp){
	// Faltante de definir
}

void print_tcp_results(struct ip_frame *ip, int frame_number){
	// Faltante de definir
}

void print_udp_results(struct ip_frame *ip, int frame_number){
	// Faltante de definir
}
