#pragma once

#include "type.h"

typedef struct
{
	uint32	magic;			//4 bytes
	uint16	major;			//2 bytes
	uint16	minor;			//2 bytes
	uint32	thisZone;		//4 bytes
	uint32	sigFigs;		//4 bytes
	uint32	snapLen;		//4 bytes
	uint32	linkType;		//4 bytes
}PcapFileHeader;

typedef struct
{
	uint32	timeSeconds;	//4 bytes
	uint32	timeUSeconds;	//4 bytes
	uint32	capLength;		//4 bytes
	uint32	receiveLength;	//4 bytes
}PcapPackageHeader;

typedef struct
{
	unsigned char	destiniationMacAddress[6];	//desitination mac address
	unsigned char	sourceMacAddress[6];		//source mac address
	uint16	protocalType;				//protocal type
}EthernetHeader;

typedef struct
{
	uint8 versionAndHeaderLength;		//version and header length
	uint8 TOS;							//service type
	uint16 totalLength;					//total length
	uint16 ID;							//flag
	uint16 flagAndSegment;				
	uint8 TTL;
	uint8 protocalType;
	uint16 checkSum;
	uint32 sourceIP;
	uint32 destinationIP;
}IPHeader;

typedef struct
{
	uint16 sourcePort;
	uint16 destinationPort;
    uint32 sequenceNO;
    uint32 acknowledgmentNO;
	uint8 headerLengthAndReserved;	//4 bits for header length and 4 bits for reserved
	uint8 controlFlags;				//top 2 bits reserved and last 6 bits for different control flag: URG ACK PSH RST SYN FIN
	uint16 windowSize;
	uint16 checkSum;
	uint16 urgentPointer;
}TCPHeader;

typedef struct
{
	uint16 sourcePort;
	uint16 destinationPort;
	uint16 length;
	uint16 checkSum;
}UDPHeader;

typedef enum {
	PROTOCAL_TYPE_TCP = 6,
	PROTOCAL_TYPE_UDP = 17
}IPProtocalType;

typedef struct fileNode
{
	uint16 sourcePort;
	uint16 destinationPort;
	uint32 sourceAddress;
	uint32 destinationAddress;
	uint32 pcapPackageStartPosition;
	uint32 pcapPackageEndPosition;
	uint32 pcapTimeSeconds;
	uint32 pcapTimeUseconds;
	IPProtocalType protocalType;
	union
	{
		struct {
			uint32 tcpDataStartPosition;
			uint32 tcpDataEndPosition;
			uint32 tcpSequenceNO;
			uint32 tcpAcknowledgmentNO;
		}tcpNode;

		struct {
			
		}udpNode;
	}nodeType;
    struct fileNode *next;
}PackageNode;

typedef struct sessionNode
{
	uint16 sourcePort;
	uint16 destinationPort;
	uint32 sourceAddress;
	uint32 destinationAddress;
	IPProtocalType protocalType;
	struct sessionNode *nextSession;
	PackageNode *nextPackage;
}SessionNode;
