# A script to test quickly

killall {vss} &> /dev/null

TESTDIR=${TESTDIR:="testdata/new_rbc_test"}
TYPE=${TYPE:="debug"}
EXP=${EXP:-"vss_ex"}
W=${W:="10000"}

for((i=0;i<4;i++)); do
./target/$TYPE/vss_ex \
    --config $TESTDIR/nodes-$i.json \
    --ip ip_file \
    -debug \
    --sleep 10 > $i.log &
echo $i started
done

sleep 20

# Client has finished; Kill the nodes
killall ./target/$TYPE/{node,client}-{synchs,apollo} &> /dev/null
