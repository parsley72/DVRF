#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcmnvram.h>
#include <error.h>
#include <shutils.h>

#define RANDOM_DEVICE "/dev/urandom"
#define RETRY_PIN_CODE  3

unsigned long int ComputeChecksum( unsigned long int PIN )
{
        unsigned long int accum = 0;
        PIN *= 10;
        accum += 3 * ((PIN / 10000000) % 10);
        accum += 1 * ((PIN / 1000000) % 10);
        accum += 3 * ((PIN / 100000) % 10);
        accum += 1 * ((PIN / 10000) % 10);
        accum += 3 * ((PIN / 1000) % 10);
        accum += 1 * ((PIN / 100) % 10);
        accum += 3 * ((PIN / 10) % 10);
        int digit = (accum % 10);
        return (10 - digit) % 10;
}

int wsc_generate_pin(char *wsc_pin)
{
        FILE *fp;
        unsigned int devPwd=0;
        unsigned int checksum=0;
        unsigned int mac=0;
        unsigned int move=0;
        int len = 2;
        int iloop;
        int shift_int=(sizeof(int)*4);
        int temp = 0;
        char hex[] = "XX";
        unsigned char public_key[40]={0};
        char cmd[100]={0};
        char *c_devPwd=wsc_pin;
	unsigned char *mac_str = nvram_safe_get("lan_hwaddr");

	sprintf(cmd,"echo %s > %s",mac_str,RANDOM_DEVICE);
	system(cmd);
	if((fp = fopen(RANDOM_DEVICE,"rb")))
        {
                fread(&move,sizeof(unsigned int),1,fp);
                fclose(fp);
        }
        srand((unsigned)move);
        move = rand();
        sprintf(public_key,"%u%s",move,mac_str);
	sprintf(cmd,"echo %s > %s",public_key,RANDOM_DEVICE);
	system(cmd);

        for(iloop=0;iloop<6;iloop++)
        {
                /*check mac format*/
                if((*mac_str == ':') && (*(mac_str+2) == ':'))
                        sprintf(hex,"0%c",*(mac_str+1));
                else
                {
                        if(iloop>0) mac_str++;
                        strncpy(hex,mac_str,2);
                }

                public_key[iloop]=(unsigned char)strtol(hex,NULL,16);
                if(iloop >=3)
                {
                        if(shift_int<=0)
                                mac|=(public_key[iloop]);
                        else
                                mac|=(public_key[iloop]<<shift_int);
                        shift_int-=(sizeof(int)*2);
                }
                mac_str+=2;
        }

        move = 0;
        if((fp = fopen(RANDOM_DEVICE,"rb")))
        {
                for(iloop=0;iloop<len;iloop++)
                {
                        temp=(unsigned char)fgetc(fp);
                        move |= (temp << (iloop*2*(sizeof(int))));
                }
                move+=mac;
                fclose(fp);
        }
        srand(move);
        devPwd = rand();
        devPwd %= 10000000;
        if(devPwd == 0)
                return 0;
        checksum = ComputeChecksum(devPwd);
        devPwd = devPwd*10 + checksum;
        sprintf( c_devPwd, "%08d", devPwd );
        c_devPwd[8] = '\0';
        return 1;
}

int main(void)
{
	char wsc_pin[13]={0};
	int  count = 0;

	while((wsc_generate_pin(wsc_pin)) && (count < RETRY_PIN_CODE))
		count++;	
	
	printf("%s",wsc_pin);
	return 1;
}

