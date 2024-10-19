extern int mac_init(struct mac *data);
extern int set_mac(char *string);
//extern int eou_key_init(void);

struct mac {
	int index;
	unsigned char maclist[8][18];
};

