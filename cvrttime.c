#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define BEIJINGTIME	8
#define DAY		(60 * 60 * 24)
#define YEARFIRST	2001
#define YEARSTART	(365 * (YEARFIRST-1970) + 8)
#define YEAR400		(365 * 4 * 100 + (4 * (100 / 4 - 1) + 1))
#define YEAR100		(365 * 100 + (100 / 4 - 1))
#define YEAR004		(365 * 4 + 1)
#define YEAR001		365

char* timeval_to_ascii(const struct timeval *tv, char *buf, unsigned int size)
{
	long sec = 0, usec = 0;
	int yy = 0, mm = 0, dd = 0, hh = 0, mi = 0, ss = 0, ms = 0;
	int ad = 0;
	int y400 = 0, y100 = 0, y004 = 0, y001 = 0;
	int m[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	int i;

	sec = tv->tv_sec;
	usec = tv->tv_usec;
	sec = sec + (60 * 60) * BEIJINGTIME;

	ad = sec / DAY;
	ad = ad - YEARSTART;
	y400 = ad / YEAR400;

	y100 = (ad - y400 * YEAR400) / YEAR100;
	y004 = (ad - y400 * YEAR400 - y100 * YEAR100) / YEAR004;
	y001 = (ad - y400 * YEAR400 - y100 * YEAR100 - y004 * YEAR004) / YEAR001;

	yy = y400 * 4 * 100 + y100 * 100 + y004 * 4 + y001 * 1 + YEARFIRST;
	dd = (ad - y400 * YEAR400 - y100 * YEAR100 - y004 * YEAR004)%YEAR001;

	// 月 日
	if(0 == yy%1000) {
		if(0 == (yy / 1000)%4) {
			m[1] = 29;
		}
	} else {
		if(0 == yy%4) {
			m[1] = 29;
		}
	}

	for(i = 1; i <= 12; i++) {
		if(dd - m[i] < 0) {
			break;
		} else {
			dd = dd -m[i];
		}
	}

	mm = i;
	// 小时
	hh = sec / (60 * 60)%24;
	// 分
	mi = sec / 60 - sec / (60 * 60) * 60;
	// 秒
	ss = sec - sec / 60 * 60;
	ms = usec;
	snprintf(buf, size, "%02d:%02d:%02d.%06d", hh, mi, ss, ms);

	return buf;
}
