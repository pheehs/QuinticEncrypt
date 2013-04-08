# Gnuplot script

set terminal x11
#set terminal png
#set output "benchmark_plot2.png"
set xlabel "param_chars"
set ylabel "num_of_keys"
set palette model HSV functions gray,1,1 # HSV color space
splot "benchmark.dat" with lines palette
