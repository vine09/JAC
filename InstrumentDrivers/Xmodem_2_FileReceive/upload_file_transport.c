#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"
#include "xmodem_file_transport.h"
#include "upload_dload.h"


#define MIN_UPLOAD_FIRST_DATA_LEN  (PACKAGE_DATA_LEN_128 - 4 - 16)


/*====================== globle datas define =============================*/
typedef struct{
	unsigned char package_head;
	unsigned char package_num;
	unsigned char package_num_flag;
	int upload_data_len;
}last_upload_fileinfo;

typedef struct{
	int file_fd;
	int file_len;
	unsigned char file_md5[FILE_MD5_NUMS];
}upload_file_info;

upload_file_info m_upload_file_info = {0};
last_upload_fileinfo m_last_upload_fileinfo = {0};
xmodem_timer m_upload_timer = {0};
static int m_send_file_len = -1; 

/*===================  upload file functions begin  ======================*/
inline void judge_last_package_num()
{
	if(ACK_ACK == m_upload_timer.ack_flag){
		if(0xFF == m_last_upload_fileinfo.package_num){
			m_last_upload_fileinfo.package_num_flag ++;
			m_last_upload_fileinfo.package_num = 1;
		}else{
			m_last_upload_fileinfo.package_num ++;
		}
	}

}

int get_upload_file_size()
{
	struct stat upload_file_stat = {0};
	if(m_upload_file_info.file_fd > 0){
		if(!fstat(m_upload_file_info.file_fd, &upload_file_stat)){
			return upload_file_stat.st_size;
		}
	}
	return -1;
}

void close_upload_file()
{
	if(m_upload_file_info.file_fd > 0)
		close(m_upload_file_info.file_fd);
	
	m_upload_file_info.file_fd = -1;
	m_upload_file_info.file_len = -1;
	memset(m_upload_file_info.file_md5,0,FILE_MD5_NUMS);

	memset(&m_last_upload_fileinfo, 0, sizeof(m_last_upload_fileinfo));
	stop_xmodem_timer(&m_upload_timer);
	set_upload_status(NON_UPLOAD_STATUS);
}

int open_upload_file(unsigned char *upload_file_path)
{
	m_upload_file_info.file_fd = open(upload_file_path,O_RDONLY);
	if(m_upload_file_info.file_fd < 0)
		return LOCAL_DATA_FAILURE;

	return LOCAL_DATA_SUCCESS;
}

void upload_timer_out_deal()
{
	m_upload_timer.resend_times ++;
	if(MAX_RESEND_TIMES < m_upload_timer.resend_times){
		close_upload_file();
		local_data_output("upload$Fail");
	}
}

void upload_data_output(char *buf)
{
	char out_buf[MAX_TRANS_STDSTR_NUM] = {0};
	setbuffer(stdout,out_buf,MAX_TRANS_STDSTR_NUM);

	fprintf(stdout,"%s\n",buf);
	fflush(stdout);
}

void fill_upload_char(int long_len,int short_len, char *deal_str)
{
	int len;
	if(long_len > short_len){
		deal_str += short_len;
		len = long_len - short_len;
		while(len){
			deal_str[len -1] = 0x1A;
			len --;
		}
	}
}

unsigned char get_upload_package_crc8(unsigned char *data, int data_len)
{
	unsigned char crc_8 = 0;
	unsigned char index;
	char *deal_data;
	
	deal_data = data;
	deal_data += 3;
	for(index = 0; index < data_len - 3; index ++){
		crc_8 ^= deal_data[index]; 
	}

	return crc_8;
}

int deal_upload_trans_package_abort(unsigned char *package)
{
	unsigned char abort_buf[3] = {0};
	snprintf(abort_buf,3,"%02x",XMODEM_CAN);
	close_upload_file();
	local_data_output(abort_buf);
	local_data_output("upload$Fail");

	return LOCAL_DATA_FAILURE;
}

int upload_file_last_package(int file_data_len)
{
	int package_data_len = 1 + 1 + 1 + PACKAGE_DATA_LEN_128 + 1;
	char package_data[package_data_len];
	int read_len = -1;
	char file_data[file_data_len];
	char package_data_str[package_data_len * 2];
	char *deal_str = package_data;

	judge_last_package_num();
	
	deal_str[0] = XMODEM_SOH;
	deal_str[1] = m_last_upload_fileinfo.package_num;
	deal_str[2] = ~m_last_upload_fileinfo.package_num;

	deal_str += 3;
	read_len = read(m_upload_file_info.file_fd,file_data,file_data_len);
	if(read_len <= 0){
		return deal_upload_trans_package_abort(NULL);
	}

	if(file_data_len == read_len){
		memcpy(deal_str,file_data,file_data_len);
		fill_upload_char(PACKAGE_DATA_LEN_128, file_data_len, deal_str);
		deal_str += PACKAGE_DATA_LEN_128;
	
		deal_str[0] = get_upload_package_crc8(package_data, package_data_len - 1);
		
		hexarr_convert_2hex_string(package_data, package_data_len, package_data_str);
		upload_data_output(package_data_str);

		m_send_file_len += file_data_len;
		m_last_upload_fileinfo.upload_data_len = file_data_len;
	}
	
	start_timer(m_upload_timer.ack_timer);
	upload_timer_out_deal();

	return LOCAL_DATA_SUCCESS;
}

int upload_file_first_package(int upload_data_len)
{
	int package_len;
	int file_head_data_len = -1;
	int read_len = -1;
	int ret = -1;
	unsigned char file_len_arr[4] = {0};

	/**first_package: 																	  *
	 *	SOH | Package_num | ~Package_num | FIle_len(4) | FILE_MD5(16) | File_Data | CRC8  *
	**/
	if(upload_data_len < MIN_UPLOAD_FIRST_DATA_LEN){
		file_head_data_len = m_upload_file_info.file_len;
		package_len = 1 + 1 + 1 + 4 + FILE_MD5_NUMS + PACKAGE_DATA_LEN_128 + 1;
	}else{
		file_head_data_len = upload_data_len - 4 - FILE_MD5_NUMS;
		package_len = 1 + 1 + 1 + 4 + FILE_MD5_NUMS + upload_data_len + 1;
	}

	unsigned char upload_package[package_len] ;
	unsigned char upload_file_head_data[file_head_data_len] ;
	char upload_package_str[package_len * 2] ;
	
	char *deal_str = upload_package;

	deal_str[0] = m_last_upload_fileinfo.package_head;
	deal_str[1] = m_last_upload_fileinfo.package_num;
	deal_str[2] = ~m_last_upload_fileinfo.package_num;

	deal_str += 3;
	data_to_hex_arry(file_len_arr, m_upload_file_info.file_len, SYS32_INT32_BYTE);
	memcpy(deal_str,file_len_arr,4);

	deal_str += 4;
	ret = get_xmodem_file_md5(m_upload_file_info.file_fd,	\
							m_upload_file_info.file_md5, 	\
							m_upload_file_info.file_len);
	if(ret < 0)
		return LOCAL_DATA_FAILURE;
	
	memcpy(deal_str,m_upload_file_info.file_md5,FILE_MD5_NUMS);

	deal_str += FILE_MD5_NUMS;
	read_len = read(m_upload_file_info.file_fd, upload_file_head_data, file_head_data_len);
	if(read_len <= 0){
		return deal_upload_trans_package_abort(NULL);
	}

	if(read_len == file_head_data_len){
		memcpy(deal_str, upload_file_head_data, file_head_data_len);
		if(file_head_data_len == m_upload_file_info.file_len){
			fill_upload_char(MIN_UPLOAD_FIRST_DATA_LEN, file_head_data_len, deal_str);
			deal_str += MIN_UPLOAD_FIRST_DATA_LEN;
		}else{
			deal_str += file_head_data_len;
		}
		
		deal_str[0] = get_upload_package_crc8(upload_package,package_len - 1);
		
		hexarr_convert_2hex_string(upload_package,package_len,upload_package_str);
		upload_data_output(upload_package_str);

		m_send_file_len = file_head_data_len;
		m_last_upload_fileinfo.upload_data_len = file_head_data_len;
	}

	start_timer(m_upload_timer.ack_timer);
	upload_timer_out_deal();
	
	return LOCAL_DATA_SUCCESS;
}

int deal_upload_trans_package_encode(int upload_data_len)
{
	int package_data_len = 1 + 1 + 1 + upload_data_len + 1;
	char package_data[package_data_len] ;
	int read_len = -1;
	char file_data[upload_data_len] ;
	char package_data_str[package_data_len * 2] ;

	char *deal_str = package_data;

	if(PACKAGE_DATA_LEN_128 == upload_data_len){
		deal_str[0] = XMODEM_SOH;
	}else if(PACKAGE_DATA_LEN_1024 == upload_data_len){
		deal_str[0] = XMODEM_STX;
	}else{
		return LOCAL_DATA_FAILURE;
	}
	
	
	judge_last_package_num();

	deal_str ++;
	deal_str[0] = m_last_upload_fileinfo.package_num;
	deal_str[1] = ~ m_last_upload_fileinfo.package_num;

	deal_str += 2;
	read_len = read(m_upload_file_info.file_fd, file_data, upload_data_len);
	if(read_len <= 0){
		return deal_upload_trans_package_abort(NULL);
	}

	if(upload_data_len == read_len){
		
		memcpy(deal_str,file_data,upload_data_len);
		deal_str += upload_data_len;

		deal_str[0] = get_upload_package_crc8(package_data, package_data_len - 1);

		hexarr_convert_2hex_string(package_data,package_data_len,package_data_str);
		upload_data_output(package_data_str);

		m_send_file_len += upload_data_len;
		m_last_upload_fileinfo.upload_data_len = upload_data_len;
	}
	
	start_timer(m_upload_timer.ack_timer);
	upload_timer_out_deal();
	
	return LOCAL_DATA_SUCCESS;

}

int deal_upload_trans_package_128bytes(unsigned char *package)
{
	return deal_upload_trans_package_encode(PACKAGE_DATA_LEN_128);
}

int deal_upload_trans_package_1024bytes(unsigned char *package)
{
	return deal_upload_trans_package_encode(PACKAGE_DATA_LEN_1024);
}

int deal_upload_trans_package_finish(unsigned char *package)
{
	unsigned char eot_buf[3] = {0};
	snprintf(eot_buf,3,"%02x",XMODEM_EOT);
	close_upload_file();
	local_data_output(eot_buf);
	local_data_output("upload$OK");

	return LOCAL_DATA_SUCCESS;
}

int deal_upload_trans_package()
{
	int package_data_len;
	
	if(ACK_NAK == m_upload_timer.ack_flag){
		m_send_file_len -= m_last_upload_fileinfo.upload_data_len;	
		lseek(m_upload_file_info.file_fd, - m_last_upload_fileinfo.upload_data_len, SEEK_CUR);
	}
	
	package_data_len = m_upload_file_info.file_len - m_send_file_len;
	
	if(package_data_len >= PACKAGE_DATA_LEN_1024){
		
		return deal_upload_trans_package_1024bytes(NULL);
	}else if((package_data_len > PACKAGE_DATA_LEN_128) && (package_data_len < PACKAGE_DATA_LEN_1024)){
	
		return deal_upload_trans_package_128bytes(NULL);
	}else if((package_data_len > 0) && (package_data_len < PACKAGE_DATA_LEN_128)){
		
		return upload_file_last_package(package_data_len);
	}else if(0 == package_data_len){

		return deal_upload_trans_package_finish(NULL);
	}else{
		
		return deal_upload_trans_package_abort(NULL);
	}
}

int deal_upload_trans_package_ack(unsigned char *package)
{
	stop_xmodem_timer(&m_upload_timer);
	m_upload_timer.ack_flag = ACK_ACK;
	return deal_upload_trans_package();
}

int deal_upload_trans_package_nak(unsigned char *package)
{
	stop_xmodem_timer(&m_upload_timer);
	m_upload_timer.ack_flag = ACK_NAK;
	if(1 == (m_last_upload_fileinfo.package_num_flag * 0xFF + m_last_upload_fileinfo.package_num)){

		return upload_file_first_package(m_last_upload_fileinfo.upload_data_len);
	}else{
		return deal_upload_trans_package();
	}
}

int deal_upload_trans_package_crc16(unsigned char *package)
{
	char crc16_buf[3] = {0};
	snprintf(crc16_buf,3,"%02x",XMODEM_CRC16);
	local_data_output(crc16_buf);
	close_upload_file();
}

xmodem_deal s_xmodem_deal_upload[] = {
	{PACKAGE_BYTES_128, 		 XMODEM_SOH, 	deal_upload_trans_package_128bytes},
	{PACKAGE_BYTES_1024, 		 XMODEM_STX, 	deal_upload_trans_package_1024bytes},
	{FINISH_FILE_TRANSPORT, 	 XMODEM_EOT, 	deal_upload_trans_package_finish},
	{CONTINUE_SEND_NEXT_PACKAGE, XMODEM_ACK, 	deal_upload_trans_package_ack},
	{SENDER_TRANSPORT_STYLE, 	 XMODEM_NAK, 	deal_upload_trans_package_nak},
	{ABORT_DATA_TRANSPORT, 		 XMODEM_CAN, 	deal_upload_trans_package_abort},
	{TRANS_CRC16_STYLE, 		 XMODEM_CRC16,  deal_upload_trans_package_crc16},
};


int start_upload_file()
{
	int upload_data_len = -1;
	
	m_upload_file_info.file_len = get_upload_file_size();
	if(m_upload_file_info.file_len <= 0)
		return LOCAL_DATA_FAILURE;

	if(m_upload_file_info.file_len >= PACKAGE_DATA_LEN_1024){
		
		m_last_upload_fileinfo.package_head = XMODEM_STX;
		upload_data_len = PACKAGE_DATA_LEN_1024 ;
	}else if((m_upload_file_info.file_len >= MIN_UPLOAD_FIRST_DATA_LEN)  \
					&&(m_upload_file_info.file_len < PACKAGE_DATA_LEN_1024)){
					
		m_last_upload_fileinfo.package_head = XMODEM_SOH;
		upload_data_len = PACKAGE_DATA_LEN_128;
	}else if(m_upload_file_info.file_len < MIN_UPLOAD_FIRST_DATA_LEN){
		
		m_last_upload_fileinfo.package_head = XMODEM_SOH;
		upload_data_len = m_upload_file_info.file_len;
	}
	
	m_last_upload_fileinfo.package_num = 1;
	
	return upload_file_first_package(upload_data_len);
}

void upload_file_transport_resend(void *p_data)
{
	if(ACK_ACK == m_upload_timer.ack_flag){
		s_xmodem_deal_upload[CONTINUE_SEND_NEXT_PACKAGE].deal_xmodem_package_func(NULL);
	}else if(ACK_NAK == m_upload_timer.ack_flag){
		s_xmodem_deal_upload[SENDER_TRANSPORT_STYLE].deal_xmodem_package_func(NULL);
	}else{
		s_xmodem_deal_upload[ABORT_DATA_TRANSPORT].deal_xmodem_package_func(NULL);
	}
}


int upload_file_transport_init(unsigned char *upload_file_path, int file_path_len)
{
	int ret = LOCAL_DATA_FAILURE;
	
	m_upload_file_info.file_fd = -1;
	m_upload_file_info.file_len = -1;
	memset(m_upload_file_info.file_md5,0,FILE_MD5_NUMS);

	memset(&m_last_upload_fileinfo, 0, sizeof(m_last_upload_fileinfo));
	
	m_send_file_len = 0;
	s_xmodem_deal_upload[SENDER_TRANSPORT_STYLE].deal_xmodem_package_func(NULL);
	
	xmodem_timer_init(&m_upload_timer, ACK_ACK, upload_file_transport_resend);
	
	DEAL_LAST_CHAR(upload_file_path, file_path_len);
	ret = open_upload_file(upload_file_path);
	if(LOCAL_DATA_FAILURE == ret){
		return s_xmodem_deal_upload[ABORT_DATA_TRANSPORT].deal_xmodem_package_func(NULL);
	}

	return start_upload_file();
}


int upload_file_transport_ack_deal(unsigned char *upload_recv_buf)
{
	if(XMODEM_ACK == upload_recv_buf[0]){
		return s_xmodem_deal_upload[CONTINUE_SEND_NEXT_PACKAGE].deal_xmodem_package_func(NULL);
	}else if(XMODEM_NAK == upload_recv_buf[0]){
		return s_xmodem_deal_upload[SENDER_TRANSPORT_STYLE].deal_xmodem_package_func(NULL);
	}else{
		upload_timer_out_deal();
	}

}


TRANSPORT].deal_xmodem_package_func(NULL);
	}

	return start_upload_file();
}


int upload_file_transport_ack_deal(unsigned char *upload_recv_buf)
{
	if(XMODEM_ACK == upload_recv_buf[0]){
		return s_xmodem_deal_upload[CONTINUE_SEND_NEXT_PACKAGE].deal_xmodem_package_func(NULL);
	}else if(XMODEM_NAK == upload_recv_buf[0]){
		return s_xmodem_deal_upload[SENDER_TRANSPORT_STYLE].deal_xmodem_package_func(NULL);
	}else{
		upload_timer_out_deal();
	}

}


