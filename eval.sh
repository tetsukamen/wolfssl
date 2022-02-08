#!/bin/sh

N=100 # 繰り返し数


# 書き込みファイルのリセット
: > eval_cpu_rrcend.txt
: > eval_cpu_rest.txt
: > eval_cpu_total.txt
: > eval_vmhwm.txt

# N回計測して記録
for i in `seq $N`
do
  ./examples/server/server -u &
  sleep 0.1
  ./examples/client/client -u
  sleep 0.1
done

# 平均の計算
echo "\n"
echo "=========結果========="
echo "繰り返し数": $N
# cpu_rrcend
cpu_sum=0
cpu_count=0
while read value
do
  cpu_sum=$(($cpu_sum+$value))
  cpu_count=$(($cpu_count+1))
done < ./eval_cpu_rrcend.txt
echo cpu_time_rrcend_avg: $(($cpu_sum/$cpu_count))
# cpu_rest
cpu_sum=0
cpu_count=0
while read value
do
  cpu_sum=$(($cpu_sum+$value))
  cpu_count=$(($cpu_count+1))
done < ./eval_cpu_rest.txt
echo cpu_time_rest_avg: $(($cpu_sum/$cpu_count))
# cpu_total
cpu_sum=0
cpu_count=0
while read value
do
  cpu_sum=$(($cpu_sum+$value))
  cpu_count=$(($cpu_count+1))
done < ./eval_cpu_total.txt
echo cpu_time_total_avg: $(($cpu_sum/$cpu_count))
# maxrss
maxrss_sum=0
maxrss_count=0
while read value
do
  maxrss_sum=$(($maxrss_sum+$value))
  maxrss_count=$(($maxrss_count+1))
done < ./eval_vmhwm.txt
echo maxrss_avg: $(($maxrss_sum/$maxrss_count))


