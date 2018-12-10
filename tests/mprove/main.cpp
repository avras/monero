#include "mprove.h"

using namespace std;

int main(int argc, char *argv[]) {
  MoneroExchange exch(1000, 300, rct::identity());
  mproveProof p = exch.GenerateProofOfAssets();
  MProveProofPublicVerification(p);
  return 0;
}
