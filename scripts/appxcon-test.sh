# A script to test quickly

killall {appxcox_new} &> /dev/null
rm -rf /tmp/*.db &> /dev/null

TESTDIR=${TESTDIR:="testdata/baa_test_16"}
TYPE=${TYPE:="release"}
EXP=${EXP:-"appxcox_new"}
W=${W:="10000"}

for((i=0;i<16;i++)); do
./target/$TYPE/appxcox_new \
    --config $TESTDIR/nodes-$i.json \
    --ip ip_file \
    --sleep 10 > $i.log &
done

sleep 20

# Client has finished; Kill the nodes
killall ./target/$TYPE/appxcox_new &> /dev/null