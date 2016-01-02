#ifndef _TIME_UTIL_H_
#define _TIME_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <string>
#include <iostream>

#define TIME_MAXSIZE 100
using namespace std;

class TIME {
public:
	TIME() {}
	~TIME() {}

	TIME(int sec, int usec) {
		d_time.tv_sec = sec;
		d_time.tv_usec = usec;
	}

	TIME(const TIME &other) {
		d_time = other.d_time;
		strncpy(d_timestamp, other.d_timestamp, TIME_MAXSIZE);
	}

	void GetCurrTime() {
		gettimeofday(&d_time, NULL);
	}

	double CvtFloatTime() {
		return (d_time.tv_sec + d_time.tv_usec/1000000.);
	} 

	char* CvtCurrTime(); //Return the readable time format in string

	/*Calculate time duration in us*/
	friend double operator-(TIME end, TIME start) {
		double interval = ((end.d_time.tv_sec - start.d_time.tv_sec)*1000000.0 + (end.d_time.tv_usec - start.d_time.tv_usec));
		return interval;
	}

	TIME& operator=(const TIME &other) {
		d_time = other.d_time;
		return *this;
	}

	static void GetCurrTime(struct timeval* time) {
		gettimeofday(time, NULL);
	}

	static double CvtCurrTime(struct timeval* time) {
		double raw_time = time->tv_sec + time->tv_usec/1000000.0;
		return raw_time;
	}   

//private:
	struct timeval d_time; /*Current time*/
	char d_timestamp[TIME_MAXSIZE];
};

/**
 * Purpose: Convert the formatted string time to its raw form
 * @return: time from epoch or 0.0 if fail
*/
inline double CvtRawTime(const string &format, const string &time_str) {
	size_t found=0;
	found = time_str.find_first_of(".");
	double time=0.0;
	struct tm time_tuple;
	bzero((void*)&time_tuple, sizeof(struct tm));
	strptime(time_str.substr(0, found).c_str(), format.c_str(), &time_tuple);
	time = (double)mktime(&time_tuple) + double(atoi(time_str.substr(found+1).c_str()))/1000000.;
	return time;
}

#endif

