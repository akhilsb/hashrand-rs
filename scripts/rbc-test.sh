# A script to test quickly

killall {rbc_ex} &> /dev/null

TESTDIR=${TESTDIR:="testdata/new_rbc_test"}
TYPE=${TYPE:="debug"}
EXP=${EXP:-"rbc_ex"}
W=${W:="10000"}

for((i=0;i<4;i++)); do
./target/$TYPE/rbc_ex \
    --config $TESTDIR/nodes-$i.json \
    --ip ip_file \
    -debug \
    --sleep 10 > $i.log &
done

sleep 20

# Client has finished; Kill the nodes
killall ./target/$TYPE/{node,client}-{synchs,apollo} &> /dev/null