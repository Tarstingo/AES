#include <stdio.h>
#include<string.h>
#include<fcntl.h>
#include<stdlib.h>
#include<unistd.h>

#include"aes.h"

int main(int argc,char *argv[])
{
/*
    plaintext text={{0x01,0x23,0x45,0x67},
                    {0x89,0xab,0xcd,0xef},
                    {0xfe,0xdc,0xba,0x98},
                    {0x76,0x54,0x32,0x10}};
    plaintext key={{0x0f,0x15,0x71,0xc9},
                   {0x47,0xd9,0xe8,0x59},
                   {0x0c,0xb7,0xad,0xd6},
                   {0xaf,0x7f,0x67,0x98}};
*/
    if(argc!=5)
    {
        printf("使用方法：%s 加密方式（1表示加密，0表示解密） 要加密/解密的文件名 密钥文件名 保存文件名字\n",argv[0]);
        return 1;
    }
    int fptex,fkey,fsave;
    fptex=open(argv[2],O_RDONLY);//要加密的文件
    fkey=open(argv[3],O_RDONLY);//密钥文件
    fsave=open(argv[4],O_RDWR|O_CREAT);//保存加密文件

    plaintext text,key;
    read(fkey,&key,sizeof(plaintext));
    printf("密钥为\n");
    prtptx(key);//打印出加密密钥
    plaintext allkey[11];
    KeyExpansion(key,allkey);//扩展密钥
    int len;
    if((argv[1][0]=='0')&&(strlen(argv[1])==1))//解密文件
    {
        plaintext tmptext;
        memset(&text,'\0',sizeof(plaintext));
        len=read(fptex,&text,sizeof(plaintext));
        while(1)
        {
            memset(&tmptext,'\0',sizeof(plaintext));
            decryptAes128(text,allkey,&tmptext);
            len=read(fptex,&text,sizeof(plaintext));
            if(len<(int)sizeof(plaintext))
                break;
            write(fsave,&tmptext,sizeof(plaintext));
        }
        int i;
        i=(unsigned int)tmptext[3][3];
        write(fsave,&tmptext,16-i);
    }
    else if((argv[1][0]=='1')&&(strlen(argv[1])==1))//加密文件
    {
        plaintext tmptext;
        while(1)
        {
            memset(&text,'\0',sizeof(plaintext));
            len=read(fptex,&text,sizeof(plaintext));

            memset(&tmptext,'\0',sizeof(plaintext));
            if(len<(int)sizeof(plaintext))
                break;
            encryptAes128(text,allkey,&tmptext);
            write(fsave,&tmptext,sizeof(plaintext));
        }
        int i;                  //处理最后一组读取的数据不足16个字节，若还差i个字节，则在后面补i个i的16进制unsigned char
        for(i=len;i<16;i++)
            text[i/4][i%4]=(unsigned char)(16-len);
        encryptAes128(text,allkey,&tmptext);
        write(fsave,&tmptext,sizeof(plaintext));
    }
    else
    {
        printf("参数错误\n");
        return 1;
    }


    close(fptex);close(fkey);close(fsave);
    return 0;
}
