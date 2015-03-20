function y = getBitAt(x,pos)
y = ~~(bitand(x,(bitsll(1, pos))));