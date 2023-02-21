# A script to test quickly

killall {node} &> /dev/null
rm -rf /tmp/*.db &> /dev/null

TESTDIR=${TESTDIR:="testdata/apx_10"}
TYPE=${TYPE:="release"}
EXP=${EXP:-"appxcox_new"}
W=${W:="10000"}
curr_date=$(date +"%s%3N")
sleep=$1
st_time=$((curr_date+sleep))
echo $st_time
for((i=0;i<10;i++)); do
./target/$TYPE/node \
    --config $TESTDIR/nodes-$i.json \
    --ip ip_file \
    --sleep $st_time \
    --vsstype $2 \
    --batch $3 > $i.log &
done

sleep 20

# Client has finished; Kill the nodes
killall ./target/$TYPE/appxcox_new &> /dev/null