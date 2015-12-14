#include<stdio.h>
#include<string.h>
#include"aes.h"
void SubByte(byte *a)
{
    byte s=*a;
    *a=s_box[(int)s];
}

void InverseSubByte(byte *a)
{
    byte s=*a;
    *a=inv_s_box[(int)s];
}

void AddRoundKey(plaintext *status,plaintext roundkey)
{
    int i,j;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            (*status)[i][j]^=roundkey[i][j];
}

void ShiftRows(plaintext *status)
{
    int i,j;
    for(i=0;i<4;i++)
    {
        byte tmp[4];
        for(j=0;j<4;j++)
        {
            tmp[j]=(*status)[i][j];
        }
        for(j=0;j<4;j++)
        {
            (*status)[i][j]=tmp[(j+i)%4];
        }
    }
}
void InvShiftRows(plaintext *status)
{
    int i,j;
    for(i=0;i<4;i++)
    {
        byte tmp[4];
        for(j=0;j<4;j++)
        {
            tmp[j]=(*status)[i][j];
        }
        for(j=0;j<4;j++)
        {
            (*status)[i][j]=tmp[(j+4-i)%4];
        }
    }
}

void RotWord(word *wd)
{
    int i;
    char tmp=(*wd)[0];
    for(i=0;i<3;i++)
    {
        (*wd)[i]=(*wd)[(i+1)%4];
    }
    (*wd)[3]=tmp;
}



void KeyExpansion(plaintext key,plaintext *allroundkey)
{
    word temp;
    memset(&temp,'\0',sizeof(word));
    int i,j;
    //allroundkey[0]
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            allroundkey[0][i][j]=key[i][j];
        }
    }
    int k;
    for(k=1;k<11;k++)
    {
        int i;
        for(i=0;i<4;i++)
        {
            for(j=0;j<4;j++)
            {
                temp[j]=allroundkey[(4*k+i-1)/4][(4*k+i-1)%4][j];
            }
            if(i==0)
            {
                RotWord(&temp);
                for(j=0;j<4;j++)
                {
                    SubByte(&temp[j]);

                }
                temp[0]=temp[0]^Rcon[k-1];
            }
            for(j=0;j<4;j++)
            {
                allroundkey[k][i][j]=allroundkey[k-1][i][j]^temp[j];
            }
        }
    }
}


byte multi2(byte b)
{
    if((b&0x80)==0)
        return ((b&0x7f)<<1);
    else
    {
        return ((b&0x7f)<<1)^0x1b;
    }
}

byte multi3(byte b)
{
    if((b&0x80)==0)
        return ((b&0x7f)<<1)^b;
    else
        return ((b&0x7f)<<1)^b^0x1b;
}

byte MultiField(byte a,byte b)
{
    byte p = 0, i = 0, hbs = 0;

    for (i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }

        hbs = a & 0x80;
        a <<= 1;
        if (hbs) a ^= 0x1b; // 0000 0001 0001 1011
        b >>= 1;
    }

    return (byte)p;
}


void Mixcolumn(plaintext *status)
{
//printf("in mixcolumn\n");
    plaintext *p=status;
    plaintext tmp;
    int i,j;
/*    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            printf("\033[31m%02x \033[0m",(*p)[i][j]);
        }
        printf("\n");
    }
*/
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            tmp[i][j]=(*p)[i][j];
    for(j=0;j<4;j++)
    {
        (*p)[0][j]=multi2(tmp[0][j])^multi3(tmp[1][j])^tmp[2][j]^tmp[3][j];
        (*p)[1][j]=tmp[0][j]^multi2(tmp[1][j])^multi3(tmp[2][j])^tmp[3][j];
        (*p)[2][j]=tmp[0][j]^tmp[1][j]^multi2(tmp[2][j])^multi3(tmp[3][j]);
        (*p)[3][j]=multi3(tmp[0][j])^tmp[1][j]^tmp[2][j]^multi2(tmp[3][j]);
    }
}

//解密时用的InvMixcolumn操作
void InvMixColumn(plaintext *status)
{
    byte cnst[]={0x0e,0x0b,0x0d,0x09};
    plaintext tmp;
    int i,j,k;
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
        {
            tmp[i][j]=(byte)0x00;
            for(k=0;k<4;k++)
            {
                tmp[i][j]^=MultiField(cnst[(k+i*3)%4],(*status)[k][j]);
            }
        }
    }
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            (*status)[i][j]=tmp[i][j];
}




void transpos(plaintext *p)
{
    plaintext tmp;
    int i,j;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            tmp[i][j]=(*p)[i][j];
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            (*p)[j][i]=tmp[i][j];
}




void encryptAes128(plaintext ptext,plaintext *allkey,plaintext *dest)
{
    int i,j,k;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            (*dest)[i][j]=ptext[i][j];

    plaintext tmpallkey[11];
    for(k=0;k<11;k++)
    {
        for(i=0;i<4;i++)
            for(j=0;j<4;j++)
                tmpallkey[k][i][j]=allkey[k][i][j];
        transpos(&tmpallkey[k]);
    }

    transpos(dest);
/*
    printf("转置换明文\n");
    prtptx(*dest);
    printf("初始轮密钥\n");
    prtptx(tmpallkey[0]);
*/
    AddRoundKey(dest,tmpallkey[0]);


    for(k=0;k<9;k++)
    {
//        printf("第%d轮加密开始\n",k+1);
//        prtptx(*dest);
        for(i=0;i<4;i++)
            for(j=0;j<4;j++)
                SubByte(&((*dest)[i][j]));
//        printf("第%d轮字节替换后\n",k+1);
//        prtptx(*dest);
        ShiftRows(dest);
/*
        printf("第%d轮行位移后\n",k+1);
        int u,v;
        for(u=0;u<4;u++)
        {
            for(v=0;v<4;v++)
            {
                printf("%02x ",(*dest)[u][v]);
            }
            printf("\n");
        }
        prtptx(text);
*/
        Mixcolumn(dest);
/*
        printf("\033[33m第%d轮列混合后\n",k+1);
        prtptx(*dest);
        printf("\033[0m");
        printf("\033[33m第%d轮轮密钥\n",k+1);
        prtptx(tmpallkey[k+1]);
        printf("\033[0m");
*/
        AddRoundKey(dest,tmpallkey[k+1]);
/*
        printf("第%d轮加密后\n",k+1);
        prtptx(*dest);
        printf("\n");
*/
    }
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            SubByte(&((*dest)[i][j]));
    ShiftRows(dest);
    AddRoundKey(dest,tmpallkey[10]);

//    prtptx(*dest);
    transpos(dest);
//    prtptx(*dest);
}
void decryptAes128(plaintext etext,plaintext *allkey,plaintext *dest)
{
    int i,j,k;
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            (*dest)[i][j]=etext[i][j];

    plaintext tmpallkey[11];
    for(k=0;k<11;k++)
    {
        for(i=0;i<4;i++)
            for(j=0;j<4;j++)
                tmpallkey[k][i][j]=allkey[k][i][j];
        transpos(&tmpallkey[k]);
    }
    transpos(dest);
    AddRoundKey(dest,tmpallkey[10]);
    InvShiftRows(dest);
    for(i=0;i<4;i++)
        for(j=0;j<4;j++)
            InverseSubByte(&((*dest)[i][j]));
    for(k=8;k>=0;k--)
    {
        AddRoundKey(dest,tmpallkey[k+1]);
//        prtptx(*dest);
        InvMixColumn(dest);
        InvShiftRows(dest);
        for(i=0;i<4;i++)
            for(j=0;j<4;j++)
                InverseSubByte(&((*dest)[i][j]));
    }
    AddRoundKey(dest,tmpallkey[0]);
    transpos(dest);
}


void prtptx(plaintext p)
{
    int i,j;
    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
            printf("%02x ",p[i][j]);
        printf("\n");
    }
    printf("\n");
}
