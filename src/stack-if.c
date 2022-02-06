#include "rawsock-adapter.h"
#include "rawsock.h"

/***************************************************************************
 ***************************************************************************/
int stack_if_datalink(struct Adapter *adapter) {
  if (adapter->ring)
    return 1; /* ethernet */
  else {
    return adapter->link_type;
  }
}
