#pragma pack(push, 1)
struct ETHER_HEADER
{
	u_char	EtherDestHost[6];
	u_char	EtherSrcHost[6];
	u_short	EtherType;
};

struct ARP_HEADER
{
	u_short HardwareType;
	u_short ProtocolType;
	u_char	HardwareLength;
	u_char	ProtocolLength;
	u_short	OprationCode;
	u_char	EtherSrcHost[6];
	DWORD	SrcIp;
	u_char	EtherDestHost[6];
	DWORD	DestIp;
};

#pragma pack(pop)