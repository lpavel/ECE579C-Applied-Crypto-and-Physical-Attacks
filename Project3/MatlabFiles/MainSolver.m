fid1 = fopen('plaintext.dat');
fid2 = fopen('PowerTrace.dat');
pt = fread(fid1, [16 500], 'uint8');
pt = transpose(pt);
T = fread(fid2, [30000 500], 'uint8');
T = transpose(T);
fclose(fid1);
fclose(fid2);


parfor key = 0:255
    for i = 1:500
        V(i, key+1) = SBox(pt(i,1), key);% careful with not having key + 1 here
        H(i, key+1) = getBitAt(V(i,key+1),7);
%       H(i, key+1) = HammingWeight(V(i,key+1)); % uncomment this and
%       comment above fi you want the Hamming Weight leakage
    end
end


parfor i = 1:256
    for j = 1:30000
        temp = corrcoef(H(:,i), T(:,j));
        R(i,j) = temp(1,2);
    end
end

figure
for i = 43:43
    plot(R(i,:));
    hold on; xlabel('time'); ylabel('Correlation Coefficient'); title('Leakage of 43 on most significant bit');
end

