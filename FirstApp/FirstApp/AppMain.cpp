#include <iostream>
using namespace std;
char GetChar(int n)
{
	char *Title;
	Title="哥是犀利的黑客";
	return Title[n];
}
int main()
{
	char uint[100];
	for(int i=0;i<20;)
	{
		for(int j=i;j<i+2;j++)
		{	
			uint[j]=GetChar(j);
			cout<<uint[j];
		}
		cout<<" ";
		i+=2;
	}
	cout<<endl;
	return 0;
}