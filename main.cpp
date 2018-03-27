#include <stdlib.h>

#include "mbed.h"
#include "hash/SHA256.h"
#include "rtos.h"

#define COMMAND_LENGTH 20 // longest instruction is bitcoin key with 17 chars
#define MAX_DUTY_CYCLE 1000
#define MIN_DUTY_CYCLE 0
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

//Photointerrupter input pins
#define I1pin D2
#define I2pin D11
#define I3pin D12

//Incremental encoder input pins
#define CHA   D7
#define CHB   D8  

//Motor Drive output pins   //Mask in output byte
#define L1Lpin D4           //0x01
#define L1Hpin D5           //0x02
#define L2Lpin D3           //0x04
#define L2Hpin D6           //0x08
#define L3Lpin D9           //0x10
#define L3Hpin D10          //0x20

typedef struct{
    uint8_t code;
    uint32_t data;
 } message_t;
 
typedef enum{
    MOTOR,    
    NONCE,    
    KEY,       
    HASH, 
    ROTATIONS, 
    VELOCITY,  
    POSITION,  
    SPEED,   
    ERROR_M
} output_t;
    

//Mapping from sequential drive states to motor phase outputs
/*
State   L1  L2  L3
0       H   -   L
1       -   H   L
2       L   H   -
3       L   -   H
4       -   L   H
5       H   L   -
6       -   -   -
7       -   -   -
*/
//Drive state to output table
const int8_t driveTable[] = {0x12,0x18,0x09,0x21,0x24,0x06,0x00,0x00};

//Mapping from interrupter inputs to sequential rotor states. 0x00 and 0x07 are not valid
const int8_t stateMap[] = {0x07,0x05,0x03,0x04,0x01,0x00,0x02,0x07};  
//const int8_t stateMap[] = {0x07,0x01,0x03,0x02,0x05,0x00,0x04,0x07}; //Alternative if phase order of input or drive is reversed

//Status LED
DigitalOut led1(LED1);

//Photointerrupter inputs
InterruptIn I1(I1pin);
InterruptIn I2(I2pin);
InterruptIn I3(I3pin);

//Motor Drive outputs
PwmOut L1L(L1Lpin);
DigitalOut L1H(L1Hpin);
PwmOut L2L(L2Lpin);
DigitalOut L2H(L2Hpin);
PwmOut L3L(L3Lpin);
DigitalOut L3H(L3Hpin);

/*----------------------------- Global Part ----------------------------------*/
Thread commOutT(osPriorityNormal, 1024);        // Communicating with host
Thread decCmdT(osPriorityNormal, 2048);         // Decode the incoming serial command
Thread motorCtrlT(osPriorityNormal, 1024);

//Initialise the serial port
RawSerial pc(SERIAL_TX, SERIAL_RX);
/* Use it to pass information between the threads 
 * Creates a FIFO which can queue up to 16 messages
 */
Mail<message_t,16> outMessages;
/*
 * Buffers incoming characters
 * Passes pointers of type void to data structure
 */
Queue<void, 8> inCharQ;

int8_t orState = 0;    //Rotot offset at motor state 0
//Phase lead to make motor spin
int8_t lead = 2;  //2 for forwards, -2 for backwards
int32_t motorPosition = 0;  // revolutions times 6
int motorPower;         // motorpower - output of controller
bool rotate_forw = true;    // rotate forward
bool rotate_inf = false;    // perform infinite rotations
bool vel_max = false;       // rotate at max speed

float kps, kpr, kd;         // controllers parameters

// Will be used to pass the key from the decCmdFn to Bitcoin miner
volatile int32_t newKey1, newKey2;
volatile int32_t Target_Vel = 0;
volatile int32_t Target_Rot = 0;
/*
 * Used to block simultaneous access of newKey by decCmdFn and Bitcoin miner
 */
Mutex newKey_mutex;

void motorCtrlTick();
void motorOut(int8_t driveState,uint32_t torqueOut);
int8_t motorHome();
void putMessage(uint8_t code, uint32_t data);
void motorISR();
void motorCtrlFn();
void serialISR();
void decCmdFn();
void commOutFn();
/*----------------------------------------------------------------------------*/
//Set a given drive state
void motorOut(int8_t driveState,uint32_t torqueOut)
{

    //Lookup the output byte from the drive state.
    int8_t driveOut = driveTable[driveState & 0x07];

    //Turn off first
    if (~driveOut & 0x01) L1L.pulsewidth_us(MIN_DUTY_CYCLE);
    if (~driveOut & 0x02) L1H = 1;
    if (~driveOut & 0x04) L2L.pulsewidth_us(MIN_DUTY_CYCLE);
    if (~driveOut & 0x08) L2H = 1;
    if (~driveOut & 0x10) L3L.pulsewidth_us(MIN_DUTY_CYCLE);
    if (~driveOut & 0x20) L3H = 1;

    //Then turn on
    if (driveOut & 0x01) L1L.pulsewidth_us(torqueOut);
    if (driveOut & 0x02) L1H = 0;
    if (driveOut & 0x04) L2L.pulsewidth_us(torqueOut);
    if (driveOut & 0x08) L2H = 0;
    if (driveOut & 0x10) L3L.pulsewidth_us(torqueOut);
    if (driveOut & 0x20) L3H = 0;
}  
//Convert photointerrupter inputs to a rotor state
inline int8_t readRotorState()
{
    return stateMap[I1 + 2*I2 + 4*I3];
}
//Basic synchronisation routine    
int8_t motorHome() 
{
    //Put the motor in drive state 0 and wait for it to stabilise
    motorOut(0,MAX_DUTY_CYCLE); // 50% duty cycle
    wait(2.0);
    
    //Get the rotor state
    return readRotorState();
}
/*------------------------------ Functions -----------------------------------*/
/* 
 * Interrupt function to check the rotor state
 */
void motorISR()
{
    static int8_t oldRotorState;
    int8_t rotorState = readRotorState(); 
    int width;
    bool forward = rotate_forw;

    if(forward){    // if moving in the positive direction
        if(motorPower < 0){ // and the power is negative, need to decelerate
            lead = -2;      // lag the field
            width = -motorPower;    // make positive
        }else{
            lead = 2;           // keep accelerating
            width = motorPower;
        }
    }else{          // if moving in the negative direction
        if(motorPower > 0){     // and power negative, accelerate
            lead = -2;
            width = motorPower;
        }else{
            lead = 2;
            width = -motorPower;
        }
    }

    if(width > MAX_DUTY_CYCLE) // pwm pulsewidth saturated at 1000 us
        width = MAX_DUTY_CYCLE;

    motorOut((rotorState-orState+lead+6)%6, width);

    if (rotorState - oldRotorState == 5) motorPosition--;
    else if (rotorState - oldRotorState == -5) motorPosition++; 
    else motorPosition += (rotorState - oldRotorState); 

    oldRotorState = rotorState;
}
/*
 * Interupt function to handle data which is asynchronously arrive.
 * It receives the incoming byte and places it in the queue for processing later on
 */
void serialISR(){
    uint8_t newChar = pc.getc();
    inCharQ.put((void*)newChar); // buffers a single byte of character
}

void decCmdFn(){
    pc.attach(&serialISR);  // attach the ISR to serial port events

    static char newCmd[COMMAND_LENGTH];
    static int char_idx = 0;    // index of the current buffer position
    static bool start_ctrl = false;

    while(1) {
        osEvent newEvent = inCharQ.get();   // wait for new character 
        uint8_t newChar = (uint8_t)newEvent.value.p; // take it's value
        newCmd[char_idx++] = newChar;  // place it at the end of a character array
        
        // if the current index is past the length of the buffer print a message
        if(char_idx == COMMAND_LENGTH)
            putMessage(ERROR_M, 0);
        // if the new character is the end of the line command
        if(newCmd[char_idx-1] == '\r'){
            newCmd[char_idx] = '\0';   // add the termination character at the end
            char_idx = 0;   // reset the index
            // Decode the command
            if(newCmd[0] == 'K'){
                newKey_mutex.lock();
                sscanf(newCmd, "K%8x%8x", &newKey1, &newKey2); //Decode the command for mining
                putMessage(KEY, newKey1);
                putMessage(KEY, newKey2);
                newKey_mutex.unlock();
            }else if(newCmd[0] == 'V'){
                sscanf(newCmd, "V%d",  &Target_Vel);

                if(!start_ctrl){        // if the thread was not started, start it here
                    motorCtrlT.start(motorCtrlFn); 
                    start_ctrl = true;
                }

                if(Target_Vel == 0){    // raise the max velocity flag
                    vel_max = true;
                }else{
                    vel_max = false;
                    if(Target_Vel > 20){    // if the target velocity is large enough
                        kps = 20.3;
                        kpr = 26.7;
                        kd = 19.5;
                    }else{          // otherwise for small velocities change the parameters
                        kps = 5; 
                        kpr = 15; 
                        kd = 1;   
                    }
                }

                putMessage(VELOCITY, Target_Vel);
            }else if(newCmd[0] == 'R'){
                if(newCmd[1] == '-'){
                    lead = -2;
                    sscanf(newCmd, "R-%d", &Target_Rot);
                    rotate_forw = false;
                }else{
                    lead = 2;
                    sscanf(newCmd, "R%d", &Target_Rot);
                    rotate_forw = true;
                }

                if(!start_ctrl){
                    motorCtrlT.start(motorCtrlFn); // if the thread was not started, start it here
                    start_ctrl = true;
                }
                
                if(Target_Rot == 0){        // raise the infinite rotations flag
                    rotate_inf = true;
                    Target_Vel = 100;       // and rotate at 100 rps
                }else{
                    rotate_inf = false;
                }
                motorPosition = 0;      // reset motor position
                putMessage(ROTATIONS, Target_Rot);
            }
        }
    }
}
// Add messages to the queue
void putMessage(uint8_t code, uint32_t data){
    message_t *pMessage = outMessages.alloc();
    pMessage->code = code;
    pMessage->data = data;
    outMessages.put(pMessage);
}
/*
 * Receives messages from other parts of the code 
 * and writes them in the serial port
 */
void commOutFn(){
    static uint32_t msg_m = 0;
    static bool msg_exists = false;

    // Infinite loop which waits for a message to be available in the queue
    while(1) {
        osEvent newEvent = outMessages.get();
        message_t *pMessage = (message_t*)newEvent.value.p;
        if((pMessage->code == KEY) ||(pMessage->code == NONCE)){
            if(!msg_exists){
                msg_m = pMessage->data;
                msg_exists = true;
            }else{
                pc.printf("Message %d with data 0x%08x%08x\n\r",
                        pMessage->code, msg_m, pMessage->data);
                msg_m = 0;
                msg_exists = false;
            }
        }else if(pMessage->code == ERROR_M){
            pc.printf("Input Command Exceeds the preset Command Length\n\r");
        }else{
            pc.printf("Message %d with data %d\n\r",
                        pMessage->code, pMessage->data);
        }
        outMessages.free(pMessage);
     }
}

void motorCtrlTick(){ 
    motorCtrlT.signal_set(0x1); 
}

void motorCtrlFn(){
    int8_t sign = 1;
    Timer t_vel;
    float dt;
    float Ev, Er, dEr;  // velocity and rotation errors. derivative of rotations error
    int ys; // speed controller output
    int yr; // position controller output

    static int old_rot = 0;   // previous number of rotations
    static float old_Er = 0;    // previous rotation error
    int current_rot = 0;   // current rotations
    float current_vel = 0;   // current velocity
    static int8_t vel_ctr = 0;
    int position;

    Ticker motorCtrlTicker;

    motorCtrlTicker.attach_us(&motorCtrlTick, 100000);
    while(1){
        t_vel.start();
        motorCtrlT.signal_wait(0x1); // block the thread until the signal is set
        t_vel.stop();
        dt = t_vel.read();

        position = motorPosition;
        if(position < 0) position = -position;

        current_rot = position;
        current_vel = (current_rot - old_rot) / dt;

        if(current_vel<0){
            current_vel = -current_vel;
        }

        if(rotate_inf){     // ignore position controller
            Ev = (Target_Vel * 6 - current_vel)/6;  // velocity error          
            ys = (int)(kps * Ev * sign);       // proportional speed controller
            motorPower = ys;
        }else{  // read position and speed controller
            Ev = (Target_Vel * 6 - current_vel)/6;  // velocity error
            Er = (Target_Rot * 6 - current_rot)/6;  // position error
            dEr = (Er - old_Er) / dt;   // derivative of position error

            if(Er < 0)          // if rotating left, set velocity direction to the left
                sign = -1;       
            else
                sign = 1;

            ys = (int)(kps * Ev * sign);       // proportional speed controller
            yr = (int)(kpr * Er + kd * dEr);   // proportional derivative position controller
            
            // combine controllers
            if(sign < 0){
                motorPower = MAX(ys,yr);
            }else{
                motorPower = MIN(ys,yr);
            }          
            old_Er = Er;
        }

        if(vel_max){ // set speed to maximum
            motorPower = MAX_DUTY_CYCLE;
        } 

        old_rot = current_rot;
        vel_ctr++;

        if(vel_ctr == 9){
            putMessage(SPEED, current_vel/6);
            putMessage(POSITION, current_rot/6);
            vel_ctr = 0;
        }
         t_vel.reset();
    }
}
/*----------------------------------------------------------------------------*/
int main() {
    Timer t;  
    SHA256 h; // instance of SHA256 class
    
    // initialise the input sequence
    uint8_t sequence[] = {0x45,0x6D,0x62,0x65,0x64,0x64,0x65,0x64,
                          0x20,0x53,0x79,0x73,0x74,0x65,0x6D,0x73,
                          0x20,0x61,0x72,0x65,0x20,0x66,0x75,0x6E, 
                          0x20,0x61,0x6E,0x64,0x20,0x64,0x6F,0x20, 
                          0x61,0x77,0x65,0x73,0x6F,0x6D,0x65,0x20,
                          0x74,0x68,0x69,0x6E,0x67,0x73,0x21,0x20, 
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  //key
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; // nonce
                          
    uint64_t* key = (uint64_t*)((int)sequence + 48); 
    uint64_t* nonce = (uint64_t*)((int)sequence + 56); 
    uint32_t* nonce_lsw = (uint32_t*)((int)sequence + 56);
    uint32_t* nonce_msw = (uint32_t*)((int)sequence + 60);
    uint8_t hash[32];   // initialise hash
    int hash_total = 0;
    float hash_rate;
    float t_hash;

    //set PWM initialisations in main
    L1L.period_us(2000);
    L2L.period_us(2000);
    L3L.period_us(2000);

    pc.printf("In Chris We Trust\n\r");    
    //Run the motor synchronisation
    orState = motorHome();
    putMessage(MOTOR, orState); // add the motor state to the queue
    
    // input change interrupt
    I1.rise(&motorISR);
    I2.rise(&motorISR);
    I3.rise(&motorISR);
    I1.fall(&motorISR);
    I2.fall(&motorISR);
    I3.fall(&motorISR);
    
    commOutT.start(commOutFn); 
    decCmdT.start(decCmdFn);

    t_hash = 0;
    t.start();
    
    while (1) {
        newKey_mutex.lock();
        *key = (((uint64_t)newKey1) << 32) | newKey2;
        newKey_mutex.unlock();
        
        h.computeHash(hash, sequence, 64);
        hash_total += 1; // hashes tried
        if((hash[0]==0) && (hash[1]==0))
        {
           putMessage(NONCE, *nonce_msw);
           putMessage(NONCE, *nonce_lsw); 
        }
        *nonce += 1;    // increment the nonce by one

        t_hash = t.read();
        if(t_hash> 1){  // print every second
            hash_rate = hash_total / t_hash;
            hash_total = 0; // reset hash counter
            putMessage(HASH, hash_rate);
            t.reset();
        }    
    }
}