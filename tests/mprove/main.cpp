#include "mprove.h"

using namespace std;

int main(int argc, char *argv[]) {
  cout << "Running mprove-test" << endl;

  static const size_t ring_size = 500;
  static const size_t cols = ring_size;
  rct::key sk;
  rct::keyV P;
  size_t ind;
  lsagSig IIccss;

    rct::keyV xv = rct::keyV(cols);
    P  = rct::keyV(cols);
    ind = 2;
    for (size_t i = 0 ; i < cols ; i++)
    {
        xv[i] = rct::skGen();
        P[i] = rct::scalarmultBase(xv[i]);
    }
    sk = xv[ind];
    cout << "Generating LSAG signature" << endl;
    IIccss = LSAG_Gen(rct::identity(), P, sk, ind, hw::get_device("default"));
    cout << "Verifying LSAG signature" << endl;
    LSAG_Ver(rct::identity(), P, IIccss);

  return 0;
}
