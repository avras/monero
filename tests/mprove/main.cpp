#include "mprove.h"

using namespace std;

int main(int argc, char *argv[]) {
  cout << "Running mprove-test" << endl;

  static const size_t ring_size = 500;
  static const size_t cols = ring_size;
  rct::key sk;
  rct::keyV P;
  size_t ind;
  lsagSig Icss;
  ringSig css;
  bool valid;

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
    Icss = LSAG_Gen(rct::identity(), P, sk, ind, hw::get_device("default"));
    cout << "Verifying LSAG signature" << endl;
    valid = LSAG_Ver(rct::identity(), P, Icss);
    if(valid)
    {
      cout << "Verification successful!" << endl;
    }
    else
    {
      cout << "Verification failed!" << endl;
    }
    cout << endl;

    cout << "Generating ring signature" << endl;
    css = RingSig_Gen(rct::identity(), P, sk, ind);
    cout << "Verifying ring signature" << endl;
    valid = RingSig_Ver(rct::identity(), P, css);
    if(valid)
    {
      cout << "Verification successful!" << endl;
    }
    else
    {
      cout << "Verification failed!" << endl;
    }

  return 0;
}
