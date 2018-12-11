#include "mprove.h"
#include <cstdlib>

using namespace std;

int main(int argc, char *argv[]) {
  if (argc < 3)
  {
    cout << "Usage: mprove-tests anonSetSize ownKeysSetSize" << endl;
    return 1;
  }
  int anonSetSize, ownKeysSetSize;
  anonSetSize = atoi(argv[1]);
  ownKeysSetSize = atoi(argv[2]);

  rct::key msg = rct::pkGen(); // Random 32 byte message
  MoneroExchange exch(anonSetSize, ownKeysSetSize, msg);
  mproveProof p = exch.GenerateProofOfAssets();
  MProveProofPublicVerification(p);
  exch.PrivatelyVerifyProofOfAssets();
  exch.PrintExchangeState();
  return 0;
}
