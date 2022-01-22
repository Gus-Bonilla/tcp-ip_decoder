#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SIZE_FRAME 1564
#define AMMOUNT_FRAMES 20
#define TCP_PROTOCOL 6
#define EROR_NO_FILE 1
#define EROR_FILE_NOT_FOUND 2
#define ANTIMASK_4B 0xf0
#define MASK_6B 0xfc
#define MASK_4B 0x0f
#define NETWORK_FRAME_BYTES 14

struct ip_frame{
	unsigned char version;
	unsigned char heder_size;
	unsigned short *total_length;
	unsigned char *protocol;				// Al ser requerido se le debe sumar 1 al apuntador para tener todo el dato
	unsigned short *checksum;
	unsigned int *ip_destiny;
	unsigned int *ip_origin;
	
	unsigned char *frame;
	unsigned char *heder_ip_end;
	struct tcp_frame *tcp;
	struct udp_frame *udp;
};

struct tcp_frame{
	unsigned short *port_origin;
	unsigned short *port_destiny;
	unsigned int *sequence_number;
	unsigned int *ack_number;			// Solo se usa un bit (de ixquierda a derecha en cuarto elemento, doceava posición)
	unsigned char heder_length;
	unsigned char control;				// Son 6 bits (se accederá primero a cuatro y luego a dos de otros 4)
	unsigned short *checksum;
	unsigned char *data_beg;					// Dependiend del tamaño de datos hay que ingrementar este puntero para realizar la lectura
};

struct udp_frame{
	unsigned short *port_origin;		// size = 16 bits
	unsigned short *port_destiny;		// size = 16 bits
	unsigned short *mesage_length;		// size = 16 bits
	unsigned short *checksum;			// size = 16 bits
	unsigned char  *data_beg;			// size = 8 bits - The frame has an undefined ammount of elements as data, here it begins
	unsigned char  *data_end;			// size = 8 bits - The frame has an undefined ammount of elements as data, here it ends
};

int fill_ip_frame(unsigned char *frame, struct ip_frame *ip, int frame_bytes);
void fill_tcp_frame(unsigned char *frame, struct tcp_frame *tcp, unsigned char *base_frame_beg, int frame_bytes);
void fill_udp_frame(unsigned char *frame, struct udp_frame *udp, unsigned char *base_frame_beg, int frame_bytes);
int swap_Endians_32(int value);
short swap_Endians_16(short value);


int main(int argc, char const *argv[]){
	// Para Gus

	unsigned char frames[AMMOUNT_FRAMES][SIZE_FRAME];
	struct ip_frame ip_frames[AMMOUNT_FRAMES];
	struct tcp_frame tcp_frames[AMMOUNT_FRAMES];
	struct udp_frame udp_frames[AMMOUNT_FRAMES];
	int ip_counter=0, udp_counter=0, flag_udp=0;
	int frames_counter=0, tcp_counter=0;
	FILE *input_file;
    int frame_bytes=0;

    if(argc < 1){
    	printf("\nIntroduzca el nombre del archivo a abrir :( \n\n");
    	return EROR_NO_FILE;
    }else{
    	input_file = fopen(argv[1],"rb");
    	printf("\nArchivo a buscar: %s \n", argv[1]);

	    if(input_file == NULL){
	    	printf("\nArchivo no encontrado :( \n\n");
	    	return EROR_FILE_NOT_FOUND;
	    }else{
	    	frame_bytes = fread(frames[0], 1, SIZE_FRAME, input_file);
	    }

	    fclose(input_file);
	    //frames[0][frame_bytes] = '\0';
	    frames_counter += 1;
    }

    printf("\nRAW FRAME:\n");
    for(int idx=0; idx<frame_bytes; idx++){
    	printf("%02x", frames[0][idx]);
    }

    printf("\n\nTotal de bytes en RAW FRAME: %d\n", frame_bytes);

    printf("\nRAW FRAME sin la cabecera de red:\n");
    for(int idx=0; idx<(frame_bytes-NETWORK_FRAME_BYTES); idx++){
    	frames[0][idx] = frames[0][idx+NETWORK_FRAME_BYTES];
    	//printf("\nRAW FRAME without the network frame:\n");
    	printf("%02x", frames[0][idx]);
    	//printf("\nRAW FRAME without the network frame:\n");
    }
    
    frame_bytes = frame_bytes-NETWORK_FRAME_BYTES;
    printf("\n\nTotal de bytes en RAW FRAME sin la cabecera de red: %d\n", frame_bytes);

	for(int idx=0; idx<frames_counter; idx++){
		flag_udp = fill_ip_frame(frames[idx], &ip_frames[idx], frame_bytes);
		
		//printf("\nEntró al for xD\n");

		if(flag_udp){
			//printf("\nEntró al UDP\n");
			ip_frames[idx].udp = &udp_frames[idx];
			fill_udp_frame(ip_frames[idx].heder_ip_end+1, &udp_frames[idx], frames[idx], frame_bytes);
			//printf("\nTerminó fill UDP\n");
			//print_udp_results(&ip_frames[idx], idx);
			udp_counter += 1;
		}else{
			//printf("\nEntró al TCP\n");
			ip_frames[idx].tcp = &tcp_frames[idx];
			fill_tcp_frame(ip_frames[idx].heder_ip_end+1, &tcp_frames[idx], frames[idx], frame_bytes);
			//printf("\nTerminó fill TCP\n");
			//print_tcp_results(&ip_frames[idx], idx);
			tcp_counter += 1;
		}

		ip_counter += 1;
	}
	
	return 0;
}

int fill_ip_frame(unsigned char *frame, struct ip_frame *ip, int frame_bytes){
	// Para Cardona (Pepe)

	int flag_udp = 1;
	
	ip->version 	  = *frame;   						//son 4 bits
	//ip->version 	  = ip->version&ANTIMASK_4B;
	ip->version 	  = ip->version>>4;
	ip->heder_size 	  = *frame; 						//sig 4 bits
	ip->heder_size    = ip->heder_size & MASK_4B;
	ip->total_length  = (short*)frame+1;
	ip->protocol 	  = frame+9;
	ip->checksum 	  = (short*)frame+5;
	ip->ip_origin	  = (int*)frame+3;
	ip->ip_destiny 	  = (int*)frame+4;

	ip->frame 		  = frame;
	ip->heder_ip_end  = frame + (((ip->heder_size)*4)-1);
	
	//printf("\nwwww %x wwww\n", *(ip->heder_ip_end+1));
	//printf("\nwwww %x wwww\n", *(ip->heder_ip_end+2));

	if(*(ip->protocol) == TCP_PROTOCOL)
		flag_udp = 0;


	///// PRINT RESULTS /////
	unsigned short aux;
	int aux_2;

	printf("\n\nIP - Versión: 0x%02x\n", ip->version);
	printf("IP - Tamaño Cabacera: 0x%02x\n", ip->heder_size);
	aux = *(ip->total_length);
	aux = swap_Endians_16(aux);
	printf("IP - Longitud Total: 0x%04x\n", aux);
	printf("IP - Protocolo: 0x%02x\n", *(ip->protocol));
	aux = *(ip->checksum);
	aux = swap_Endians_16(aux);
	printf("IP - Suma de Control de Cabacera: 0x%02x\n", aux);
	aux_2 = *(ip->ip_origin);
	aux_2 = swap_Endians_32(aux_2);
	printf("IP - Dirección IP de origen: 0x%04x\n", aux_2);
	aux_2 = *(ip->ip_destiny);
	aux_2 = swap_Endians_32(aux_2);
	printf("IP - Dirección IP de destino: 0x%04x\n\n", aux_2);

	return flag_udp;
}

void fill_tcp_frame(unsigned char *frame, struct tcp_frame *tcp, unsigned char *base_frame_beg, int frame_bytes){
	// Para Cardona (Pepe)

	tcp->port_origin	 = (short*)frame;
	tcp->port_destiny	 = (short*)frame+1;
	tcp->sequence_number = (int*)frame+1;
	tcp->ack_number		 = (int*)frame+2;
	tcp->heder_length	 = *(frame+12);				// Son 4 bits
	tcp->heder_length 	 = (tcp->heder_length)>>4;
	tcp->control		 = *(frame+13);				// Son 6 bits
	tcp->control 	 	 = (tcp->control)&MASK_6B;
	tcp->checksum		 = (short*)frame+8;
	tcp->data_beg		 = frame+(tcp->heder_length*4);

	///// PRINT RESULTS /////
	unsigned short aux;
	unsigned int aux_2;

	aux = *(tcp->port_origin);
	aux = swap_Endians_16(aux);
	printf("TCP - Puerto origen: 0x%02x\n", aux);
	aux = *(tcp->port_destiny);
	aux = swap_Endians_16(aux);
	printf("TCP - Puerto destino: 0x%02x\n", aux);
	aux_2 = *(tcp->sequence_number);
	aux_2 = swap_Endians_32(aux_2);
	printf("TCP - Número de secuencia: 0x%04x\n", aux_2);
	aux_2 = *(tcp->ack_number);
	aux_2 = swap_Endians_32(aux_2);
	printf("TCP - Número ACK: 0x%04x\n", aux_2);
	printf("TCP - Longitud de la cabecera: 0x%02x\n", tcp->heder_length);
	printf("TCP - Control: 0x%x\n", tcp->control);
	aux = *(tcp->checksum);
	aux = swap_Endians_16(aux);
	printf("TCP - Checksum: 0x%02x\n", aux);

	printf("TCP - Datos: ");
	aux_2 = (tcp->data_beg) - base_frame_beg;
	aux_2 = frame_bytes - aux_2;
	
	for(int idx=0; idx<aux_2; idx++){
		printf("0x%x ", *((tcp->data_beg)+idx));
	}

	printf("\n\nTCP - Datos: \n");
	for(int idx=0; idx<aux_2; idx++){
		printf("%c", *((tcp->data_beg)+idx));
	}
	printf("\n\n");
}

void fill_udp_frame(unsigned char *frame, struct udp_frame *udp, unsigned char *base_frame_beg, int frame_bytes){
	// To Gus

	udp->port_origin   = (short*)frame;
	udp->port_destiny  = (short*)frame+1;
	udp->mesage_length = (short*)frame+2;
	udp->checksum 	   = (short*)frame+3;
	udp->data_beg 	   = frame+8;
	//udp->data_end	   = frame + *(udp->mesage_length);


	///// PRINT RESULTS /////
	unsigned short aux;
	unsigned int aux_2;

	aux = *(udp->port_origin);
	aux = swap_Endians_16(aux);
	printf("UDP - Puerto Origen: 0x%02x\n", aux);
	aux = *(udp->port_destiny);
	aux = swap_Endians_16(aux);
	printf("UDP - Puerto Destino: 0x%02x\n", aux);
	aux = *(udp->mesage_length);
	aux = swap_Endians_16(aux);
	printf("UDP - Longitud del Mensaje: 0x%02x\n", aux);
	aux = *(udp->checksum);
	aux = swap_Endians_16(aux);
	printf("UDP - Suma de verificación: 0x%02x\n", aux);

	printf("UDP - Datos: ");
	aux_2 = (udp->data_beg) - base_frame_beg;
	aux_2 = frame_bytes - aux_2;
	
	for(int idx=0; idx<aux_2; idx++){
		printf("0x%x ", *((udp->data_beg)+idx));
	}

	printf("\n\nUDP - Datos: \n");
	for(int idx=0; idx<aux_2; idx++){
		printf("%c", *((udp->data_beg)+idx));
	}
	printf("\n\n");
}

int swap_Endians_32(int value){
	int leftmost_byte;
	int left_middle_byle;
	int right_middle_byte;
	int rightmost_byte;
	int result;
	
	leftmost_byte = (value & 0x000000FF) >> 0;
	left_middle_byle = (value & 0x0000FF00) >> 8;
	right_middle_byte = (value & 0x00FF0000) >> 16;
	rightmost_byte = (value & 0xFF000000) >> 24;
	leftmost_byte <<= 24;
	left_middle_byle <<= 16;
	right_middle_byte <<= 8;
	rightmost_byte <<= 0;
	result = (leftmost_byte | left_middle_byle
			| right_middle_byte | rightmost_byte);

	return result;
}

short swap_Endians_16(short value){
	short leftmost_byte;
	short rightmost_byte;
	short result;
	
	leftmost_byte = (value & 0x00FF) >> 0;
	rightmost_byte = (value & 0xFF00) >> 8;
	leftmost_byte <<= 8;
	rightmost_byte <<= 0;
	result = (rightmost_byte | leftmost_byte);

	return result;
}
