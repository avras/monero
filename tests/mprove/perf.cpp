#include "mprove.h"
#include <cstdlib>

using namespace std;

int main(int argc, char *argv[]) {
  if (argc < 4)
  {
    cout << "Usage: mprove-perf anonSetSize ownKeysSetSize numIterations" << endl;
    return 1;
  }
  int anonSetSize, ownKeysSetSize, numIterations;
  anonSetSize = atoi(argv[1]);
  ownKeysSetSize = atoi(argv[2]);
  numIterations = atoi(argv[3]);

  for (int i = 0; i < numIterations; i++)
  {
    cout << "Executing iteration number " << i+1 << " of " << numIterations << endl;
    rct::key msg = rct::pkGen(); // Random 32 byte message
    MoneroExchange exch(anonSetSize, ownKeysSetSize, msg);
    mproveProof p = exch.GenerateProofOfAssets();
  }
  return 0;
}
