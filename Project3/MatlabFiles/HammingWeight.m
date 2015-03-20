function y = HammingWeight(x)
y = 0;
for i = 0:7
  if getBitAt(x,i) == 1 
      y = y + 1;
  end
end
    