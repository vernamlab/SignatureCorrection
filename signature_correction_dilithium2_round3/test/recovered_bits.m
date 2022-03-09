close all;
clear all;
clc;

L = 4;
N = 256;

bits = importdata("recovered_bits.txt");
num_faulty_sig = length(bits)
map = ones(L, N, 32);
for i=1:num_faulty_sig
    map(bits(i,1)+1, bits(i,2)+1, bits(i,3)+1) = bits(i,4)+2;    % +1 is for matlab indexing    
end

num_zeros = sum(map(:) == 2)
num_ones = sum(map(:) == 3)

num_bits_recovered = num_zeros+num_ones
num_bits_recovered_repeated = num_faulty_sig - num_bits_recovered

figure
cmap = [0 0 0;  % Background color
        0 1 0;  % Color for 0's (GREEN)
        1 0 0]; % Color for 1's (RED)
t = tiledlayout(1,4);
txt = xlabel(t, 'Bits per Coefficient', 'FontSize',12);
txt = ylabel(t, 'Coefficients', 'FontSize',12);

font_size = 10;

% Tile 1
nexttile
map1 = squeeze(map(1,:,:));
imshow(map1, cmap)
axis on
set(gca,'xtick',[1 16 32])
set ( gca, 'xdir', 'reverse' )
set(gca,'ytick',[1, 32:32:256])
title('Polynomial s_{1}^{(1)}')
set(gca,'FontSize',font_size)

% Tile 2
nexttile
map2 = squeeze(map(2,:,:));
imshow(map2, cmap)
axis on
set(gca,'xtick',[1 16 32])
set ( gca, 'xdir', 'reverse' )
set(gca,'ytick',[1, 32:32:256])
title('Polynomial s_{1}^{(2)}')
set(gca,'FontSize',font_size)

% Tile 3
nexttile
map3 = squeeze(map(3,:,:));
imshow(map3, cmap)
axis on
set(gca,'xtick',[1 16 32])
set ( gca, 'xdir', 'reverse' )
set(gca,'ytick',[1, 32:32:256])
title('Polynomial s_{1}^{(3)}')
set(gca,'FontSize',font_size)

% Tile 4
nexttile
map4 = squeeze(map(4,:,:));
imshow(map4, cmap)
axis on
set(gca,'xtick',[1 16 32])
set ( gca, 'xdir', 'reverse' )
set(gca,'ytick',[1, 32:32:256])
title('Polynomial s_{1}^{(4)}')
set(gca,'FontSize',font_size)