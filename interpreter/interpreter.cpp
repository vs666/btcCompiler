#include<iostream>
#include<fstream>
#include<vector>
#include<stack>
#include<ios>
#include<unordered_map>
#include<limits>
#define byte uint8_t 

/**
 * Bitcoin Instruction Set to OP-Codes 
 * If MODE is TESTING and OP_NOP1 then print the stack (testing purposes...)
 * Currently each element in the stack is 32 bits, but it'll be increased to arbitrary later on 
 * */




static bool TESTING = true; // if testing is true then OP_NOP1 is used to print the stack to stdout.

#define  OP_0 		 		0x0
#define  OP_PUSHDATA1 		0x4c
#define  OP_PUSHDATA2 		0x4d
#define  OP_PUSHDATA4 		0x4e
#define  OP_1NEGATE 		0x4f
#define  OP_RESERVED 		0x50
#define  OP_1 				0x51
#define  OP_2 				0x52
#define  OP_3 				0x53
#define  OP_4 				0x54
#define  OP_5 				0x55
#define  OP_6 				0x56
#define  OP_7 				0x57
#define  OP_8 				0x58
#define  OP_9 				0x59
#define  OP_10 				0x5a
#define  OP_11 				0x5b
#define  OP_12 				0x5c
#define  OP_13 				0x5d
#define  OP_14 				0x5e
#define  OP_15 				0x5f
#define  OP_16 				0x60
#define  OP_NOP 			0x61
#define  OP_VER 			0x62
#define  OP_IF 				0x63
#define  OP_NOTIF 			0x64
#define  OP_VERIF 			0x65
#define  OP_VERNOTIF 		0x66
#define  OP_ELSE 			0x67
#define  OP_ENDIF 			0x68
#define  OP_VERIFY 			0x69
#define  OP_RETURN 			0x6a
#define  OP_TOALTSTACK 		0x6b
#define  OP_FROMALTSTACK 	0x6c
#define  OP_2DROP 			0x6d
#define  OP_2DUP 			0x6e
#define  OP_3DUP 			0x6f
#define  OP_2OVER 			0x70
#define  OP_2ROT 			0x71
#define  OP_2SWAP 			0x72
#define  OP_IFDUP 			0x73
#define  OP_DEPTH 			0x74
#define  OP_DROP 			0x75
#define  OP_DUP 			0x76
#define  OP_NIP 			0x77
#define  OP_OVER 			0x78
#define  OP_PICK 			0x79
#define  OP_ROLL 			0x7a
#define  OP_ROT 			0x7b
#define  OP_SWAP 			0x7c
#define  OP_TUCK 			0x7d
#define  OP_CAT 			0x7e
#define  OP_SUBSTR 			0x7f
#define  OP_LEFT 			0x80
#define  OP_RIGHT 			0x81
#define  OP_SIZE 			0x82
#define  OP_INVERT 	 		0x83
#define  OP_AND 			0x84
#define  OP_OR 				0x85
#define  OP_XOR 			0x86
#define  OP_EQUAL 			0x87
#define  OP_EQUALVERIFY 	0x88
#define  OP_RESERVED1 		0x89
#define  OP_RESERVED2 		0x8a
#define  OP_1ADD 			0x8b
#define  OP_1SUB 			0x8c
#define  OP_2MUL 			0x8d
#define  OP_2DIV 			0x8e
#define  OP_NEGATE 			0x8f
#define  OP_ABS 			0x90
#define  OP_NOT 			0x91
#define  OP_0NOTEQUAL 		0x92
#define  OP_ADD 			0x93
#define  OP_SUB 			0x94
#define  OP_MUL 			0x95
#define  OP_DIV 			0x96
#define  OP_MOD 			0x97
#define  OP_LSHIFT 			0x98
#define  OP_RSHIFT 			0x99
#define  OP_BOOLAND 		0x9a
#define  OP_BOOLOR 			0x9b
#define  OP_NUMEQUAL 		0x9c
#define  OP_NUMEQUALVERIFY 	0x9d
#define  OP_NUMNOTEQUAL 	0x9e
#define  OP_LESSTHAN 		0x9f
#define  OP_GREATERTHAN 	0xa0
#define  OP_LESSTHANOREQUAL 0xa1
#define  OP_GREATERTHANOREQUAL 	0xa2
#define  OP_MIN 			0xa3
#define  OP_MAX 			0xa4
#define  OP_WITHIN 			0xa5
#define  OP_RIPEMD160 		0xa6
#define  OP_SHA1 			0xa7
#define  OP_SHA256 			0xa8
#define  OP_HASH160 		0xa9
#define  OP_HASH256 		0xaa
#define  OP_CODESEPARATOR 	0xab
#define  OP_CHECKSIG 		0xac
#define  OP_CHECKSIGVERIFY 	0xad
#define  OP_CHECKMULTISIG 	0xae
#define  OP_CHECKMULTISIGVERIFY 0xaf
#define  OP_NOP1 			0xb0
#define  OP_CHECKLOCKTIMEVERIFY 0xb1
#define  OP_CHECKSEQUENCEVERIFY 0xb2
#define  OP_NOP4 			0xb3
#define  OP_NOP5 			0xb4
#define  OP_NOP6 			0xb5
#define  OP_NOP7 			0xb6
#define  OP_NOP8 			0xb7
#define  OP_NOP9 			0xb8
#define  OP_NOP10 			0xb9
#define  OP_INVALIDOPCODE 	0xff
#define  OP_TRUE 			0x01

// use of static is better than const because scope is the entire program thus can precompile the mapping or some shit... 
static std::unordered_map<std::string, uint32_t> instruction_map {
	{"OP_0" ,  		 		0x0},
	{"OP_PUSHDATA1" ,  		0x4c},
	{"OP_PUSHDATA2" ,  		0x4d},
	{"OP_PUSHDATA4" ,  		0x4e},
	{"OP_1NEGATE" ,  		0x4f},
	{"OP_RESERVED" ,  		0x50},
	{"OP_1" ,  				0x51},
	{"OP_2" ,  				0x52},
	{"OP_3" ,  				0x53},
	{"OP_4" ,  				0x54},
	{"OP_5" ,  				0x55},
	{"OP_6" ,  				0x56},
	{"OP_7" ,  				0x57},
	{"OP_8" ,  				0x58},
	{"OP_9" ,  				0x59},
	{"OP_10" ,  				0x5a},
	{"OP_11" ,  				0x5b},
	{"OP_12" ,  				0x5c},
	{"OP_13" ,  				0x5d},
	{"OP_14" ,  				0x5e},
	{"OP_15" ,  				0x5f},
	{"OP_16" ,  				0x60},
	{"OP_NOP" ,  			0x61},
	{"OP_VER" ,  			0x62},
	{"OP_IF" ,  				0x63},
	{"OP_NOTIF" ,  			0x64},
	{"OP_VERIF" ,  			0x65},
	{"OP_VERNOTIF" ,  		0x66},
	{"OP_ELSE" ,  			0x67},
	{"OP_ENDIF" ,  			0x68},
	{"OP_VERIFY" ,  			0x69},
	{"OP_RETURN" ,  			0x6a},
	{"OP_TOALTSTACK" ,  		0x6b},
	{"OP_FROMALTSTACK" ,  	0x6c},
	{"OP_2DROP" ,  			0x6d},
	{"OP_2DUP" ,  			0x6e},
	{"OP_3DUP" ,  			0x6f},
	{"OP_2OVER" ,  			0x70},
	{"OP_2ROT" ,  			0x71},
	{"OP_2SWAP" ,  			0x72},
	{"OP_IFDUP" ,  			0x73},
	{"OP_DEPTH" ,  			0x74},
	{"OP_DROP" ,  			0x75},
	{"OP_DUP" ,  			0x76},
	{"OP_NIP" ,  			0x77},
	{"OP_OVER" ,  			0x78},
	{"OP_PICK" ,  			0x79},
	{"OP_ROLL" ,  			0x7a},
	{"OP_ROT" ,  			0x7b},
	{"OP_SWAP" ,  			0x7c},
	{"OP_TUCK" ,  			0x7d},
	{"OP_CAT" ,  			0x7e},
	{"OP_SUBSTR" ,  			0x7f},
	{"OP_LEFT" ,  			0x80},
	{"OP_RIGHT" ,  			0x81},
	{"OP_SIZE" ,  			0x82},
	{"OP_INVERT" ,  	 		0x83},
	{"OP_AND" ,  			0x84},
	{"OP_OR" ,  				0x85},
	{"OP_XOR" ,  			0x86},
	{"OP_EQUAL" ,  			0x87},
	{"OP_EQUALVERIFY" ,  	0x88},
	{"OP_RESERVED1" ,  		0x89},
	{"OP_RESERVED2" ,  		0x8a},
	{"OP_1ADD" ,  			0x8b},
	{"OP_1SUB" ,  			0x8c},
	{"OP_2MUL" ,  			0x8d},
	{"OP_2DIV" ,  			0x8e},
	{"OP_NEGATE" ,  			0x8f},
	{"OP_ABS" ,  			0x90},
	{"OP_NOT" ,  			0x91},
	{"OP_0NOTEQUAL" ,  		0x92},
	{"OP_ADD" ,  			0x93},
	{"OP_SUB" ,  			0x94},
	{"OP_MUL" ,  			0x95},
	{"OP_DIV" ,  			0x96},
	{"OP_MOD" ,  			0x97},
	{"OP_LSHIFT" ,  			0x98},
	{"OP_RSHIFT" ,  			0x99},
	{"OP_BOOLAND" ,  		0x9a},
	{"OP_BOOLOR" ,  			0x9b},
	{"OP_NUMEQUAL" ,  		0x9c},
	{"OP_NUMEQUALVERIFY" ,  	0x9d},
	{"OP_NUMNOTEQUAL" ,  	0x9e},
	{"OP_LESSTHAN" ,  		0x9f},
	{"OP_GREATERTHAN" ,  	0xa0},
	{"OP_LESSTHANOREQUAL" ,  0xa1},
	{"OP_GREATERTHANOREQUAL" ,  	0xa2},
	{"OP_MIN" ,  			0xa3},
	{"OP_MAX" ,  			0xa4},
	{"OP_WITHIN" ,  			0xa5},
	{"OP_RIPEMD160" ,  		0xa6},
	{"OP_SHA1" ,  			0xa7},
	{"OP_SHA256" ,  			0xa8},
	{"OP_HASH160" ,  		0xa9},
	{"OP_HASH256" ,  		0xaa},
	{"OP_CODESEPARATOR" ,  	0xab},
	{"OP_CHECKSIG" ,  		0xac},
	{"OP_CHECKSIGVERIFY" ,  	0xad},
	{"OP_CHECKMULTISIG" ,  	0xae},
	{"OP_CHECKMULTISIGVERIFY" ,  0xaf},
	{"OP_NOP1" ,  			0xb0},
	{"OP_PRINT" ,  			0xb0},
	{"OP_CHECKLOCKTIMEVERIFY" ,  0xb1},
	{"OP_CHECKSEQUENCEVERIFY" ,  0xb2},
	{"OP_NOP4" ,  			0xb3},
	{"OP_NOP5" ,  			0xb4},
	{"OP_NOP6" ,  			0xb5},
	{"OP_NOP7" ,  			0xb6},
	{"OP_NOP8" ,  			0xb7},
	{"OP_NOP9" ,  			0xb8},
	{"OP_NOP10" ,  			0xb9},
	{"OP_INVALIDOPCODE" ,  	0xff},
	{"OP_TRUE",				0x01}
};


class Script{
public:

//	std::vector<uint8_t> txId;
//	uint32_t txIndex;	// 
	int32_t script_length;
	std::vector<int32_t> script;
//	uint32_t sequence;
//	std::vector<uint8_t> stack_count;
//	std::vector<vector<uint8_t>> stack_length; // variable (2-9 bytes)
//	std::vector<vector<uint8_t>> stack; // variable 

	Script(std::vector<int32_t> &in_script)
	{
		this->script = in_script;
	}

	uint8_t executeScript()
	{
		std::stack<int32_t> exec_stack;
		std::stack<int32_t> alt_stack;
		return this->executeScript(0,exec_stack,alt_stack);
	}

	uint8_t executeScript(int current_index,std::stack<int32_t>& execution_stack,std::stack<int32_t>& alt_stack)
	{
		if(current_index == script.size())	// end of script stack 
		{
			if (execution_stack.empty()){
				// error if stack is empty?? No
				// std::cerr << "ERROR::Empty Execution Stack on the end of script\nScript-Index: " << << "\nFile:decoder.cpp" << std::endl;
				return 0; // failure of script
			}
			return execution_stack.top()!=0x00?0x01:0x00;	// 1 means success 0 means failure 
		}
		else{	
			/**
			 * STEPS: 
			 * 		(1) Decode the OP_CODE 
			 * 		(2) Update the execution stack accordingly 
			 * 		(3) Return the recursive call to executeScript with updated pointers 
			 * */
			uint32_t instr = (uint32_t)script[current_index];
			if((instr>>8) != 0x00FFFFFF)
			{
				// data... just push into the stack and move on
				execution_stack.push(instr);
				return executeScript(current_index+1,execution_stack,alt_stack);
			}
			instr^=0xFFFFFF00;
			int instruction_offset = 1;
			switch(instr)
			{
			case OP_0:
				// do nothing or push 0
				execution_stack.push(0x00);
				break;
			case OP_PUSHDATA1:	// TODO: Add error handling for out of bounds here...
				{
					current_index++; 
					uint64_t data_length = (uint32_t)script[current_index];
					if(this->pushData(current_index,data_length,execution_stack)!=1)//error resolution block...
					{
						// error messages here... 
						return 0;
					}
					instruction_offset = 1 + data_length;
					break;
				}
			case OP_PUSHDATA2: // TODO: Add error handling for out of bounds here...
				{	
					current_index+=2;
					uint64_t data_length = (((uint32_t)script[current_index-1])<<8)+((uint32_t)script[current_index]);
					if(this->pushData(current_index,data_length,execution_stack)!=1)//error resolution block...
					{
						// error messages here... 
						return 0;
					}				
					instruction_offset = 1 + data_length;
					break;
				}
			case OP_PUSHDATA4: // TODO: Add error handling for out of bounds here...
				{	
					current_index+=4;
					uint64_t data_length = (((uint64_t)script[current_index-3])<<24) + (((uint64_t)script[current_index-2])<<16) + (((uint64_t)script[current_index-1])<<8)+((uint64_t)script[current_index]);
					if(this->pushData(current_index,data_length,execution_stack)!=1)//error resolution block...
					{
						// error messages here... 
						return 0;
					}
					instruction_offset = 1 + data_length;
					break;
				}
			case OP_1NEGATE:
				execution_stack.push(-1);
				break;
			case OP_1:
			case OP_TRUE:
				execution_stack.push(1);
				break;
			case OP_2:
			case OP_3:
			case OP_4:
			case OP_5:
			case OP_6:
			case OP_7:
			case OP_8:
			case OP_9:
			case OP_10:
			case OP_11:
			case OP_12:
			case OP_13:
			case OP_14:
			case OP_15:
			case OP_16:
				execution_stack.push(instr-0x50);
				break;
			case OP_NOP:
				break;
			case OP_IF:
				// handle this shit later....
				break;
			case OP_NOTIF:
				// handle this shit later....
				break;
			case OP_ELSE:
				// handle this crap later....
				break;
			case OP_ENDIF:
				// handle this crap later....
				break;
			case OP_VERIFY:
				if(execution_stack.top() != OP_TRUE){
					execution_stack.pop();
					return 0; 
				}
				execution_stack.pop();
				break;
			case OP_RETURN:
				return 0;
				break; // not needed but breaks symmetry 
			case OP_TOALTSTACK:	// To add error handling for empty stack
				alt_stack.push(execution_stack.top());
				execution_stack.pop();
				break;
			case OP_FROMALTSTACK: // To add error handling for empty stack
				execution_stack.push(alt_stack.top());
				alt_stack.pop();
				break;
			case OP_IFDUP: // error handling for empty stack
				if(execution_stack.top() != 0){
					execution_stack.push(execution_stack.top());
				}
				break;
			case OP_DEPTH:
				execution_stack.push(execution_stack.size());
				break;
			case OP_DROP:	// error handling for empty stack
				if(execution_stack.size() != 0){
					execution_stack.pop();
				}
				break;
			case OP_DUP: // error handling for empty stack
				execution_stack.push(execution_stack.top());
				break;
			case OP_NIP:
				{
					int32_t savor = execution_stack.top();
					execution_stack.pop();
					execution_stack.pop();
					execution_stack.push(savor);
					break;
				}
			case OP_OVER:
				{
					int32_t savor = execution_stack.top();
					execution_stack.pop();
					int32_t elt_copy = execution_stack.top();
					execution_stack.push(savor);
					execution_stack.push(elt_copy);
					break;
				}
			case OP_PICK:
				// implement later.... 
				break;
			case OP_ROLL: 
				// implement later.... 
				break;
			case OP_ROT:
				{
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					int32_t e3 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e2);
					execution_stack.push(e1);
					execution_stack.push(e3);
					break;
				}
			case OP_SWAP:
				{
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e1);
					execution_stack.push(e2);
					break;
				}
			case OP_TUCK:
				{	
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e1);
					execution_stack.push(e2);
					execution_stack.push(e1);
					break;
				}
			case OP_2DROP:
				execution_stack.pop();
				execution_stack.pop();
				break;
			case OP_3DUP:
				{
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					int32_t e3 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e3);
					execution_stack.push(e2);
					execution_stack.push(e1);
					execution_stack.push(e3);
					execution_stack.push(e2);
					execution_stack.push(e1);
					break;
				}
			case OP_2DUP:
				{
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e2);
					execution_stack.push(e1);
					execution_stack.push(e2);
					execution_stack.push(e1);
					break;
				}
			case OP_2OVER:
				{	
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					int32_t e3 = execution_stack.top();
					execution_stack.pop();
					int32_t e4 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e4);
					execution_stack.push(e3);
					execution_stack.push(e2);
					execution_stack.push(e1);
					execution_stack.push(e4);
					execution_stack.push(e3);
					break;
				}
			case OP_2SWAP:
				{	
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					int32_t e3 = execution_stack.top();
					execution_stack.pop();
					int32_t e4 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e2);
					execution_stack.push(e1);
					execution_stack.push(e4);
					execution_stack.push(e3);
					break;
				}
			case OP_2ROT:
				{
					int32_t e1 = execution_stack.top();
					execution_stack.pop();
					int32_t e2 = execution_stack.top();
					execution_stack.pop();
					int32_t e3 = execution_stack.top();
					execution_stack.pop();
					int32_t e4 = execution_stack.top();
					execution_stack.pop();
					int32_t e5 = execution_stack.top();
					execution_stack.pop();
					int32_t e6 = execution_stack.top();
					execution_stack.pop();
					execution_stack.push(e4);
					execution_stack.push(e3);
					execution_stack.push(e2);
					execution_stack.push(e1);
					execution_stack.push(e6);
					execution_stack.push(e5);
					break;
				}
			case OP_NOP1:
				std::cout << "here" << std::endl;
				if(TESTING){
					this->printStack(execution_stack,alt_stack);
				}
			}
			return executeScript(current_index+instruction_offset,execution_stack,alt_stack);
		}
	}

private:

	/**
	 * pushData: pushes specified bytes of data to the ececution-stack. 
	 * ToDo: Error handling for out of bound execptions along with returning error codes. 
	 * Verify: Approach used to push data to stack.
	 * */
	int pushData(uint32_t current_index,uint64_t data_length, std::stack<int32_t> &execution_stack)
	{
		for(uint64_t x=1;x<=data_length;x++){
			execution_stack.push(script[current_index+x]); 
		}
		return 1;
	}
	void printStack(std::stack<int32_t> execution_stack, std::stack<int32_t> alt_stack)	// copies stack so is slow 
	{
		std::cout << "=================================\n";
		std::cout << "EXECUTION STACK::\n";
		while(!execution_stack.empty()){
			std::cout << execution_stack.top() << "\n";
			execution_stack.pop();
		}
		std::cout << "=================================\n";
		std::cout << "ALTERNATE STACK::\n";
		while(!alt_stack.empty()){
			std::cout << alt_stack.top() << "\n";
			alt_stack.pop();
		}
		std::cout << "=================================\n";
	}
};


// struct OutputTx{

// }


// struct Transaction{
// 	uint32_t version; // actual size is 4 bytes
// 	uint8_t marker; // 
// 	uint8_t flag;
// 	std::vector<uint8_t> input_count; // 
// 	std::vector<Transaction> input_vector; // 
		
// }


uint32_t strToInt(std::string &s){
	uint32_t num = 0;
	for(int x=0;x<s.length();x++){
		if(s[x] > '9' || s[x] < '0')
		{
			// error parsing number 
			break;
		}
		else{
			num*=10;
			num+= (uint32_t)(s[x] - '0');
		}
	}
	return num;
}



int decode(){	// decode the byte file 
	std::vector<int32_t> script_stack;
	int input_size;
	std::cin >> input_size;
	std::cin.ignore();
	for(int x=0;x<input_size;x++){
		char intype;
		std::cin >> intype;
		std::string instr;
		std::cin >> instr;
		if(intype == 'i'){
			// instruction ... interpret from OP_CODES 
			script_stack.push_back(0xFFFFFF00|instruction_map[instr]); // hacky way...change to something more natural 
		}
		else if(intype == 'd'){
			script_stack.push_back(strToInt(instr));
		}
	}
	Script scr(script_stack);
	int ret = scr.executeScript();
	std::cout << "Execution over with return value " << ret << std::endl;
	return 0;
}


int main()
{
	if(TESTING){
		decode();
	}
	return 0;
}
