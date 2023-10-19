# Some random stuff

* `c2switch_t` holds the details of switches ("cmd") parsed by `c2.dll`: struct differs from `c1.dll` and `c1xx.dll`
  * first field is the offset to a `wchar_t*` containing the canonical form of the switch
  * second field is the offset to the storage of whatever gets set
  * ...
* `c1switch_t` seems to be the same struct for `c1.dll` and `c1xx.dll`
  * first field is the offset to a `char*` containing the canonical form of the switch
  * second field is the offset to the storage of whatever gets set (or a callback function, depending on the type
  * third field (offs 0x10) could be the `x` from `/dx` (e.g. `/d1`)
  * fourth fields (offs 0x11) appears to indicate the type:
    * 1: `bool` (1 byte)
    * 5: `bool` (1 byte) inverted
    * 0xA: some callback function
    * 0x22: C string, i.e. `char*`
    * 0x24: `unsigned int*` ???
    * 0x26: list of `char*` ???
    * 0x29: some callback function

* `/d1...` switches correspond to `c1*.dll` I _think_
* `/d2...` switches correspond to `c2.dll` I _think_
* `DummyFlag` and `DummyString` exist to catch stuff that was probably supported in the past but is now only handled for compat.?
