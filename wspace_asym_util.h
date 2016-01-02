#ifndef WSPACE_ASYM_UTIL_H_
#define WSPACE_ASYM_UTIL_H_ 

#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "pthread_wrapper.h"
#include "time_util.h"
#include "rate.h"

/* Parameter to be tuned */
#define BUF_SIZE 5000
#define PKT_SIZE 1472
#define ACK_WINDOW 720
#define NUM_RETRANS 1
//#define ACK_PKT_INTERVAL 5
//#define ACK_TIME_OUT     15  //in sec
#define ACK_LAG_TIME	 0
#define RTT 200 		 	   // in msec
#define TX_INTERVAL 0		   // in usec
/* end parameter to be tuned*/

#define ATH_DATA 1
#define CELL_DATA 2
#define ACK 3

#define ATH_DATA_HEADER_SIZE   (uint16) sizeof(AthDataHeader)
#define CELL_DATA_HEADER_SIZE  (uint16) sizeof(CellDataHeader)
#define ACK_HEADER_SIZE 	   (uint16) sizeof(AckHeader)
#define ACK_PKT_SIZE 	   	   (uint16) sizeof(AckPkt)

//#define DEBUG_BASIC_BUF
//#define TEST
#define CRC
//#define LOG_PKT
#define RAND_DROP
#define INSERT_TIMER

const double kDropProb=0.;

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

enum Status {
	kEmpty = 1,                // The slot is empty for storing packets
	// tx_send_buf             // The slot stores a new packet
	kOccupiedNew = 2,
	kOccupiedRetrans = 3,   // stores a packet should be retransmited
	kOccupiedOutbound = 4,     // a packet transmitted but does not got ack
	// rx_rcv_buf
	kBlock = 5,                // rx_write_tun() is block waiting for this packet - for signal purpose later
	kDrop = 6,
	kRead = 7,                 // Indicate the entry has been read
};
	
typedef struct {
	uint32 seq_num;
	Status status;
	uint16 len;    // Length of shim layer header + data
	uint8  num_retrans;
	TIME timestamp;
} BookKeeping;

void Perror(char *msg, ...);

class BasicBuf {
public:
	BasicBuf(): kSize(BUF_SIZE), 
			    head_pt_(0),
				tail_pt_(0)
	{
		cout << kSize << endl;
		// Clear bookkeeping
		for (int i = 0; i < kSize; i++) {
			book_keep_arr_[i].seq_num = 0;
			book_keep_arr_[i].status = kEmpty;
			book_keep_arr_[i].len = 0;
			book_keep_arr_[i].num_retrans = 0;
			book_keep_arr_[i].timestamp.GetCurrTime();
		}
		// clear packet buffer
		bzero(pkt_buf_, sizeof(pkt_buf_));
		// initialize queue lock 
		Pthread_mutex_init(&qlock_, NULL);
		// initialize lock array
		for (int i = 0; i < kSize; i++) {
			Pthread_mutex_init(&(lock_arr_[i]), NULL);
		}
		// initialize cond variables
		Pthread_cond_init(&empty_cond_, NULL);
		Pthread_cond_init(&fill_cond_, NULL);
	}	

	~BasicBuf() {
		// Reset pointer
		head_pt_ = 0;
		tail_pt_ = 0;
		// Destroy lock
		Pthread_mutex_destroy(&qlock_);
		for (int i = 0; i < kSize; i++) {
			Pthread_mutex_destroy(&(lock_arr_[i]));
		}
		// Destroy conditional variable
		Pthread_cond_destroy(&empty_cond_);
		Pthread_cond_destroy(&fill_cond_);
	}

	void LockQueue() {
		Pthread_mutex_lock(&qlock_);
	}

	void UnLockQueue() {
		Pthread_mutex_unlock(&qlock_);
	}

	void LockElement(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("LockElement invalid index: %d\n", index);
		}
		Pthread_mutex_lock(&lock_arr_[index]);
	}

	void UnLockElement(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("UnLockElement invalid index: %d\n", index);
		}
		Pthread_mutex_unlock(&lock_arr_[index]);
	}

	void WaitFill() {
		Pthread_cond_wait(&fill_cond_, &qlock_);
	}	

	void WaitEmpty() {
		Pthread_cond_wait(&empty_cond_, &qlock_);
	}

	void SignalFill() {
		Pthread_cond_signal(&fill_cond_);
	}

	void SignalEmpty() {
		Pthread_cond_signal(&empty_cond_);
	}

	bool IsFull() {
		return ((head_pt_ + BUF_SIZE) == tail_pt_);
	}

	bool IsEmpty() {
		return (tail_pt_ == head_pt_);
	}

	uint32 head_pt() const { return head_pt_; }

	uint32 head_pt_mod() const { return (head_pt_%kSize); }

	void set_head_pt(uint32 head_pt) { head_pt_ = head_pt; }

	uint32 tail_pt() const { return tail_pt_; }

	uint32 tail_pt_mod() const { return (tail_pt_%kSize); }

	void set_tail_pt(uint32 tail_pt) { tail_pt_ = tail_pt; }

	void IncrementHeadPt() {
		head_pt_++;
	}

	void IncrementTailPt() {
		tail_pt_++;
	}
	
	void GetPktBufAddr(uint32 index, char **pt) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetPktBufAddr invalid index: %d\n", index);
		}
		*pt = (char*)pkt_buf_[index];
	}

	void StorePkt(uint32 index, uint16 len, const char* pkt) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("StorePkt invalid index: %d\n", index);
		}
		memcpy((void*)pkt_buf_[index], pkt, (size_t)len);
	}

	void GetPkt(uint32 index, uint16 len, char* pkt) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetPkt invalid index: %d\n", index);
		}
		memcpy(pkt, (void*)pkt_buf_[index], (size_t)len);
	}
		
	void AcquireHeadLock(uint32 *index);    // Function acquires and releases qlock_ inside

	void AcquireTailLock(uint32 *index);    // Function acquires and releases qlock_ inside

	void UpdateBookKeeping(uint32 index, uint32 seq_num, Status status, uint16 len);

	void GetBookKeeping(uint32 index, uint32 *seq_num, Status *status, uint16 *len) const;

	void UpdateBookKeeping(uint32 index, uint32 seq_num, Status status, uint16 len, uint8 num_retrans, bool update_timestamp);

	void GetBookKeeping(uint32 index, uint32 *seq_num, Status *status, uint16 *len, uint8 *num_retrans,
						TIME *timestamp) const;


	Status& GetElementStatus(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetElementStatus invalid index: %d\n", index);
		}
		return book_keep_arr_[index].status;
	}

	uint32& GetElementSeqNum(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetElementSeqNm invalid index: %d\n", index);
		}
		return book_keep_arr_[index].seq_num;
	}

	uint16& GetElementLen(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetElementLen invalid index: %d\n", index);
		}
		return book_keep_arr_[index].len;
	}

	uint8& GetElementNumRetrans(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetElementRetrans invalid index: %d\n", index);
		}
		return book_keep_arr_[index].num_retrans;
	}

	TIME& GetElementTimeStamp(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("GetElementTimeStamp invalid index: %d\n", index);
		}
		return book_keep_arr_[index].timestamp;
	}

// Data member
	const uint32 kSize;
	uint32 head_pt_;
	uint32 tail_pt_;	
	BookKeeping book_keep_arr_[BUF_SIZE];
	char pkt_buf_[BUF_SIZE][PKT_SIZE];
	pthread_mutex_t qlock_;
	pthread_mutex_t lock_arr_[BUF_SIZE];
	pthread_cond_t empty_cond_, fill_cond_;
};

class TxSendBuf: public BasicBuf {
public:
	TxSendBuf(): curr_pt_(0) {
	}	

	~TxSendBuf() {
		curr_pt_ = 0;
	}

	void AcquireCurrLock(uint32 *index);

	uint32 curr_pt() const { return curr_pt_; }

	uint32 curr_pt_mod() const { return (curr_pt_%kSize); }

	void set_curr_pt(uint32 curr_pt) { curr_pt_ = curr_pt; }

	void IncrementCurrPt() {
		curr_pt_++;
	}

	bool IsEmpty() {
		return (tail_pt_ == curr_pt_);
	}

// Data member
	uint32 curr_pt_;
};

class RxRcvBuf: public BasicBuf {
public:
	RxRcvBuf() {
		Pthread_cond_init(&element_avail_cond_, NULL);
		Pthread_cond_init(&wake_ack_cond_, NULL);
	}

	~RxRcvBuf() {
		Pthread_cond_destroy(&element_avail_cond_);
		Pthread_cond_destroy(&wake_ack_cond_);
	}

	void SignalElementAvail() {
		Pthread_cond_signal(&element_avail_cond_);
	}

	void WaitElementAvail(uint32 index) {
		if (index < 0 || index > BUF_SIZE-1) {
			Perror("WaitElementAvail invalid index: %d\n", index);
		}
		Pthread_cond_wait(&element_avail_cond_, &lock_arr_[index]); 
	}

	void SignalWakeAck() {
		Pthread_cond_signal(&wake_ack_cond_);
	}

	int WaitWakeAck(int wait_s) {
		static struct timespec time_to_wait = {0, 0};
		struct timeval now;
		gettimeofday(&now, NULL);
		time_to_wait.tv_sec = now.tv_sec+wait_s;
		//time_to_wait.tv_nsec = (now.tv_usec + wait_ms * 1000) * 1000;
		int err = pthread_cond_timedwait(&wake_ack_cond_, &qlock_, &time_to_wait);
		return err;
	}

	void AcquireHeadLock(uint32 *index, uint32 *head);

// Data member
	pthread_cond_t element_avail_cond_;  // Associate with element locks
	pthread_cond_t wake_ack_cond_;       // Associate with qlock
};

// Three packet headers
class AthDataHeader {
public:
	AthDataHeader()
	{
		bzero(&type_, ATH_DATA_HEADER_SIZE);
		type_ = ATH_DATA;
		rate_ = ATH5K_RATE_CODE_6M;
	}
	~AthDataHeader() {}

	void SetAthHdr(uint32 seq_num, uint16 len, char rate, char code);
	void ParseAthHdr(uint32 *seq_num, uint16 *len, char *rate, char *code);
	uint16 GetRate();
	void SetRate(uint16 rate);

// Data
	char type_;
	uint32 seq_num_;
	uint16 rate_;
	uint16 len_;    // Length of the data
	char code_;
};

class CellDataHeader {
public:
	CellDataHeader(): type_(CELL_DATA)//, len_(0)
	{
	}
	~CellDataHeader() {}

	/*
	void SetCellHdr(uint16 len) { 
		if (len > PKT_SIZE - CELL_DATA_HEADER_SIZE) {    
			Perror("Error: SetCellHdr pkt size: %d CELL_DATA_HEADER_SIZE: %d is too large!\n", 
				   len, CELL_DATA_HEADER_SIZE);
		} else {
			len_ = len;		     
		}
	}

	void ParseCellHdr(uint16 *len) {
		if (type_ != CELL_DATA) {
			Perror("ParseCellHdr error! type_: %d != ATH_CELL\n", type_);
		}
		if (len_ > (PKT_SIZE - CELL_DATA_HEADER_SIZE)) {    
			Perror("Error: ParseCellHdr pkt size: %d ATH_DATA_HEADER_SIZE: %d is too large!\n", 
				   len_, CELL_DATA_HEADER_SIZE);
		} else {
			*len = len_;		     
		}
	}
	*/

// Data
	char type_;
	//uint16 len_;    // the size of the payload
}; 

class AckHeader {
public:
	AckHeader(): type_(ACK), ack_seq_(0), num_nacks_(0), 
				 start_nack_seq_(0), end_seq_(0)
	{
	}
	~AckHeader() {}

	void Init() {
		type_ = ACK;
		ack_seq_++;
		num_nacks_ = 0;
		start_nack_seq_ = 0;
		end_seq_ = 0;
	}

// Data
	char type_;
	uint32 ack_seq_;		  // Record the sequence number of ack 
	uint16 num_nacks_;		  // number of nacks in the packet
	uint32 start_nack_seq_;   // Starting sequence number of nack
	uint32 end_seq_;          // The end of this ack window - could be a good pkt or a bad pkt 
}; 

typedef struct {
	uint16 rel_seq_num;
} NackTuple;

class AckPkt {
public:
	AckPkt() {
		bzero(seq_arr_, sizeof(seq_arr_));
	}
	~AckPkt() {}

	void PushNack(uint32 seq);
	void GenerateNack(uint16 *len, char *buf);
	void ParseNack(const char *pkt, uint32 *ack_seq, uint16 *len, uint32 *end_seq, uint32 *seq_arr); 

// Data
	AckHeader ack_hdr_;
	NackTuple seq_arr_[ACK_WINDOW];
};

inline void AckPkt::PushNack(uint32 seq) {
	if (ack_hdr_.num_nacks_ == 0) {
		ack_hdr_.start_nack_seq_ = seq;
		seq_arr_[0].rel_seq_num = 0;  // Relative seq
	} else {
		assert(ack_hdr_.num_nacks_ < ACK_WINDOW);
		seq_arr_[ack_hdr_.num_nacks_].rel_seq_num = (uint16)(seq - ack_hdr_.start_nack_seq_);
	}
	ack_hdr_.num_nacks_++;
}

inline uint32 Seq2Ind(uint32 seq) {
	return ((seq-1) % BUF_SIZE);
}

#ifdef RAND_DROP
inline bool IsDrop(double drop_prob) {
	return (rand() % 100 < (int)(drop_prob*100));
}
#endif

#endif
