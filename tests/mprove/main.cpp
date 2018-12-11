#include "mprove.h"
#include <cstdlib>

using namespace std;

int main(int argc, char *argv[]) {
  if (argc < 4)
  {
    cout << "Usage: mprove-tests anonSetSize ownKeysSetSize print" << endl;
    cout << "print should be 0 or 1" << endl;
    return 1;
  }
  int anonSetSize, ownKeysSetSize, print;
  anonSetSize = atoi(argv[1]);
  ownKeysSetSize = atoi(argv[2]);
  print = atoi(argv[3]);

  rct::key msg = rct::pkGen(); // Random 32 byte message
  MoneroExchange exch(anonSetSize, ownKeysSetSize, msg);
  mproveProof p = exch.GenerateProofOfAssets();
  MProveProofPublicVerification(p);
  exch.PrivatelyVerifyProofOfAssets();
  if(print)
  {
    exch.PrintExchangeState();
  }
  return 0;
}
