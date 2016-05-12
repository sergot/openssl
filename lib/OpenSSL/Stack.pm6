use NativeCall;

class OpenSSL::Stack is repr('CStruct') {
    has int32 $.num;
    has CArray[CArray[uint8]] $.data;
    has int32 $.sorted;
    has int32 $.num_alloc;
    has Pointer $.comp;
}
