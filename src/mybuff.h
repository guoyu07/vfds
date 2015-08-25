#ifndef _MYBUFF_H_
#define _MYBUFF_H_
#include <stdint.h>

//���ݻ�����
struct mybuff {
	char* data;			//bufferָ��
	size_t size;		//buffer��С
	size_t len;		//������Ч����
	int fd;
	off_t foffset;
	size_t flen;
};

//��ʼ��������С
extern int init_buff_size;
/*
 * ��ʼ��
 * mybuff		����ʼ����buff
 */
extern void mybuff_init(struct mybuff* mybuff);
/*
 * д������
 * mybuff		Ŀ��buff
 * data			����ָ��
 * len			���ݳ���
 * return		0-�ɹ�������ʧ��
 */
extern int mybuff_setdata(struct mybuff* mybuff, const char* data, size_t len);
/* 
 * д���ļ���Ϣ
 * mybuff		Ŀ��buff
 * fd			�ļ�fd
 * offset		ƫ����
 * len			���ͳ���
 * return		0-�ɹ�������ʧ��
 */
extern int mybuff_setfile(struct mybuff* mybuff, int fd, off_t offset, size_t len);
/*
 * ȡ����
 * mybuff		Դbuff
 * data			������ָ��
 * len			���ݳ���ָ��
 * return		0-�ɹ�������û������
 */
extern int mybuff_getdata(struct mybuff* mybuff, char** data, size_t* len);
/*
 * ����ʹ��������
 * mybuff		Դbuff
 * len			ʹ�ó���
 */
extern void mybuff_skipdata(struct mybuff* mybuff, size_t en);
/*
 * ȡ�ļ���Ϣ
 * mybuff		Դbuff
 * fd			�ļ�fd
 * offset		ƫ����
 * len			���ͳ���
 * return		0-�ɹ�������û������
 */
extern int mybuff_getfile(struct mybuff* mybuff, int* fd, off_t* offset, size_t * len);
/*
 * ����ʹ���ļ�������
 * mybuff		Դbuff
 * len			���ݳ���
 */
extern void mybuff_skipfile(struct mybuff* mybuff, size_t len);
/*
 * ���³�ʼ��
 * mybuff		Ŀ��buff
 */
extern void mybuff_reinit(struct mybuff* mybuff);
/*
 * �ͷ���Դ
 * mybuff		Ŀ��buff
 */
extern void mybuff_fini(struct mybuff* mybuff);

#endif
