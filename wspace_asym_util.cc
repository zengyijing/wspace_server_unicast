#include "wspace_asym_util.h"
// BasicBuf *buf;
TxSendBuf *buf;

/*
void *Producer(void *arg) {
	int mul = (int)arg;
	uint32 index;
 	uint32 val = mul * 10;
	while (1) {
		val++;
		buf->AcquireTailLock(&index);
		buf->UpdateBookKeeping(index, val, kOccupiedNew, 1500, 5, NULL);
		printf("write index: %u val: %u\n", index, val);
		buf->UnLockElement(index);
	}
	return (void*)NULL;
}

void *Consumer(void *arg) {
	uint32 seq_num;
	uint16 len;
	Status status;
	uint32 index;
	uint8 num_retrans;
	int read_cnt = 0;
	while (1) {
		// buf->AcquireHeadLock(&index);
		buf->AcquireCurrLock(&index);
		buf->GetBookKeeping(index,&seq_num, &status, &len, &num_retrans, NULL);
		printf("read index: %d seq_num: %u len: %u status: %d\n", index, seq_num, len, status);
		// usleep(10000);
		buf->UnLockElement(index);
		read_cnt++;
		if (read_cnt == 2 * BUF_SIZE) {
			break;
		}
	}
	return (void*)NULL;
}
*/
/*
int main(int argc, char **argv) {
	buf = new TxSendBuf();
	pthread_t producer, consumer;
	Pthread_create(&producer, NULL, Producer, (void*)60);
	Pthread_create(&consumer, NULL, Consumer, NULL);
	Pthread_join(producer, NULL);
	Pthread_join(consumer, NULL);
	delete buf;
	return 0;
}
*/

// Member functions for BasicBuf
/*
Purpose: Dequeue an element in the head
*/
void BasicBuf::AcquireHeadLock(uint32 *index) {
	LockQueue();
	while (IsEmpty()) {
#ifdef TEST
		printf("Empty!\n");
#endif
		WaitFill();
	}		
	*index = head_pt_mod(); //current element
	LockElement(*index);
	IncrementHeadPt();
	SignalEmpty();
	UnLockQueue();
}

/*
Purpose: Enqueue an element in the tail
*/
void BasicBuf::AcquireTailLock(uint32 *index) {
	LockQueue();
	while (IsFull()) {
#ifdef TEST
		printf("Full! head_pt[%u] tail_pt[%u]\n", head_pt_, tail_pt_);
#endif
		WaitEmpty();
	}		
	*index = tail_pt_mod(); //current element
	LockElement(*index);
	IncrementTailPt();
	SignalFill();
	UnLockQueue();
}

void BasicBuf::UpdateBookKeeping(uint32 index, uint32 seq_num, Status status, uint16 len) {
	if (index < 0 || index > BUF_SIZE-1) {
		Perror("UpdateBookKeeping invalid index: %d\n", index);
	}
	book_keep_arr_[index].seq_num = seq_num;
	book_keep_arr_[index].status = status;
	book_keep_arr_[index].len = len;
}

void BasicBuf::GetBookKeeping(uint32 index, uint32 *seq_num, Status *status, uint16 *len) const {
	if (index < 0 || index > BUF_SIZE-1) {
		Perror("GetBookKeeping invalid index: %d\n", index);
	}
	*seq_num = book_keep_arr_[index].seq_num; 
	*status = book_keep_arr_[index].status;
	*len = book_keep_arr_[index].len; 
}

void BasicBuf::UpdateBookKeeping(uint32 index, uint32 seq_num, Status status, uint16 len, 
								  uint8 num_retrans, bool update_timestamp) {
	if (index < 0 || index > BUF_SIZE-1) {
		Perror("UpdateBookKeeping invalid index: %d\n", index);
	}
	book_keep_arr_[index].seq_num = seq_num;
	book_keep_arr_[index].status = status;
	book_keep_arr_[index].len = len;
	book_keep_arr_[index].num_retrans = num_retrans;
	if (update_timestamp) {
		book_keep_arr_[index].timestamp.GetCurrTime();
	}
}

void BasicBuf::GetBookKeeping(uint32 index, uint32 *seq_num, Status *status, uint16 *len, 
							   uint8 *num_retrans, TIME *timestamp) const {
	if (index < 0 || index > BUF_SIZE-1) {
		Perror("GetBookKeeping invalid index: %d\n", index);
	}
	*seq_num = book_keep_arr_[index].seq_num; 
	*status = book_keep_arr_[index].status;
	*len = book_keep_arr_[index].len; 
	*num_retrans = book_keep_arr_[index].num_retrans; 
	if (timestamp) {
		*timestamp = book_keep_arr_[index].timestamp; 
	}
}

// tx_send_buf
void TxSendBuf::AcquireCurrLock(uint32 *index) {
	LockQueue();
	while (IsEmpty()) {
#ifdef TEST
		printf("Empty! head_pt[%u] curr_pt[%u] tail_pt[%u]\n", head_pt_, curr_pt_, tail_pt_);
#endif
		WaitFill();
	}		
	*index = curr_pt_mod(); //current element
	LockElement(*index);
	IncrementCurrPt();
	UnLockQueue();
}

void RxRcvBuf::AcquireHeadLock(uint32 *index, uint32 *head) {
	LockQueue();
	while (IsEmpty()) {
#ifdef TEST
		printf("Empty!\n");
#endif
		WaitFill();
	}		
	*index = head_pt_mod(); 
	*head = head_pt();
	LockElement(*index);
	UnLockQueue();
}

void Perror(char *msg, ...) {

  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
  exit(-1);
}

// For three headers
void AthDataHeader::SetAthHdr(uint32 seq_num, uint16 len, char rate, char code) {
	if (len > PKT_SIZE - ATH_DATA_HEADER_SIZE) {    //PKT_SIZE is the MTU of tun0
		Perror("Error: SetAthHdr pkt size: %d ATH_DATA_HEADER_SIZE: %d is too large!\n", 
			   len, ATH_DATA_HEADER_SIZE);
	} else {
		len_ = len;		     
	}
	seq_num_ = seq_num;
	rate_ = rate;
	code_ = code;
}

void AthDataHeader::ParseAthHdr(uint32 *seq_num, uint16 *len, char *rate, char *code) {
	if (type_ != ATH_DATA) {
		Perror("ParseAthHdr error! type_: %d != ATH_DATA\n", type_);
	}
	if (len_ > (PKT_SIZE - ATH_DATA_HEADER_SIZE)) {    
		Perror("Error: ParseAthHdr pkt size: %d ATH_DATA_HEADER_SIZE: %d is too large!\n", 
			   len_, ATH_DATA_HEADER_SIZE);
	} else {
		*len = len_;		     
	}
	*seq_num = seq_num_;
	*rate = rate_;
	*code = code_;
}

void AthDataHeader::SetRate(uint16 rate) {
	switch(rate) {
 		case 10:
			rate_ = ATH5K_RATE_CODE_1M;
			break;
		case 20:
			rate_ = ATH5K_RATE_CODE_2M;
			break;
		case 55:
			rate_ = ATH5K_RATE_CODE_5_5M;
			break;
		case 110:
			rate_ = ATH5K_RATE_CODE_11M;
			break;
		case 60:
			rate_ = ATH5K_RATE_CODE_6M;
			break;
		case 90:
			rate_ = ATH5K_RATE_CODE_9M;
			break;
		case 120:
			rate_ = ATH5K_RATE_CODE_12M;
			break;
		case 180:
			rate_ = ATH5K_RATE_CODE_18M;
			break;
        case 240:
			rate_ = ATH5K_RATE_CODE_24M;
			break;
		case 360:
			rate_ = ATH5K_RATE_CODE_36M;
			break;
		case  480:
			rate_ = ATH5K_RATE_CODE_48M;
			break;
		case 540:
			rate_ = ATH5K_RATE_CODE_54M;
			break;
		default:
			Perror("Error: SetRate() invalid rate[%d]\n", rate);
	}
}

// Return rate * 10
uint16 AthDataHeader::GetRate() {
	switch(rate_) {
 		case ATH5K_RATE_CODE_1M:
			return 10;
		case ATH5K_RATE_CODE_2M:
			return 20;
		case ATH5K_RATE_CODE_5_5M:
			return 55;
		case ATH5K_RATE_CODE_11M:
			return 110;
		case ATH5K_RATE_CODE_6M:
			return 60;
		case  ATH5K_RATE_CODE_9M:
			return 90;
		case ATH5K_RATE_CODE_12M:
			return 120;
		case ATH5K_RATE_CODE_18M:
			return 180;
        case ATH5K_RATE_CODE_24M:
			return 240;
		case ATH5K_RATE_CODE_36M:
			return 360;
		case  ATH5K_RATE_CODE_48M:
			return 480;
		case ATH5K_RATE_CODE_54M:
			return 540;
		default:
			fprintf(stderr, "Error: GetRate() invalid rate[%d]\n", rate_);
			return 0;
	}
}

/*
pkt: the incoming packet
num_nacks: the number of seq numbers in seq_arr/pkt
seq_arr: the result of parsing(relative seq -> absolute seq) 
Have to allocate seq_arr of uint32 separately to prevent overflow
*/ 
void AckPkt::ParseNack(const char *pkt, uint32 *ack_seq, uint16 *num_nacks, uint32 *end_seq, uint32 *seq_arr) {
	ack_hdr_.type_ = ((AckHeader*)pkt)->type_;
	if (ack_hdr_.type_ != ACK) {
		Perror("ParseNack invalid type\n");
	}
	ack_hdr_.num_nacks_ = ((AckHeader*)pkt)->num_nacks_;
	if (ack_hdr_.num_nacks_ > ACK_WINDOW || ack_hdr_.num_nacks_ < 0) {
		Perror("ParseNack invalid num_nacks\n");
	}
	
	ack_hdr_.ack_seq_ = ((AckHeader*)pkt)->ack_seq_;
	ack_hdr_.start_nack_seq_ = ((AckHeader*)pkt)->start_nack_seq_;
	ack_hdr_.end_seq_ = ((AckHeader*)pkt)->end_seq_;

	// Fill out data
	*ack_seq = ack_hdr_.ack_seq_;
	*num_nacks = ack_hdr_.num_nacks_;
	*end_seq = ack_hdr_.end_seq_;
	if (ack_hdr_.num_nacks_ != 0) {
		NackTuple *nack_arr_pkt = (NackTuple *)(&pkt[ACK_HEADER_SIZE]);
		for (int i = 0; i < ack_hdr_.num_nacks_; i++) {
			seq_arr[i] = (uint32)(nack_arr_pkt[i].rel_seq_num + ack_hdr_.start_nack_seq_);
		}
	}
}

/*
Purpose: Generate nack packet based on the nack seq arr
len: the size of the packet
buf: the starting address to store the generated ack pkt including AckHeader
*/
void AckPkt::GenerateNack(uint16 *len, char *buf) {
	*len = ACK_HEADER_SIZE + sizeof(NackTuple) * ack_hdr_.num_nacks_;
	if (*len > PKT_SIZE) {
		Perror("GenerateNack *len[%u] > PKT_SIZE! ACK_HEADER_SIZE[%u] sizeof(NackTuple)[%u] num_nacks[%u]\n", 
				*len, ACK_HEADER_SIZE, sizeof(NackTuple), ack_hdr_.num_nacks_);
	}
	memcpy(buf, (char*)(&ack_hdr_), ACK_HEADER_SIZE);
	if (ack_hdr_.num_nacks_ > 0) {
		memcpy((char*)(&buf[ACK_HEADER_SIZE]), (char*)seq_arr_, sizeof(NackTuple) * ack_hdr_.num_nacks_);
	}
}
	
