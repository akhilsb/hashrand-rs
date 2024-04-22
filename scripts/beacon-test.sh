# A script to test quickly

killall {node} &> /dev/null
rm -rf /tmp/*.db &> /dev/null
# vals=(531336 498474 527599 507272)
tri=32862

TESTDIR=${TESTDIR:="testdata/cc_16"}
TYPE=${TYPE:="release"}
EXP=${EXP:-"appxcox_new"}
W=${W:="10000"}
curr_date=$(date +"%s%3N")
sleep=100
st_time=$((curr_date+sleep))
echo $st_time
# Run the syncer now
# ./scripts/beacon-test.sh 10 bea testdata/cc_16/syncer 200 10
./target/$TYPE/node \
    --config $TESTDIR/nodes-0.json \
    --ip ip_file \
    --sleep $st_time \
    --vsstype sync \
    --epsilon 10 \
    --delta 5000 \
    --val 100 \
    --tri $tri \
    --syncer $1 \
    --batch $3 \
    --frequency $4 > logs/syncer.log &

for((i=0;i<16;i++)); do
./target/$TYPE/node \
    --config $TESTDIR/nodes-$i.json \
    --ip ip_file \
    --sleep $st_time \
    --epsilon 10 \
    --delta 10 \
    --val 100 \
    --tri $tri \
    --vsstype $2 \
    --syncer $1 \
    --batch $3 \
    --frequency $4 > logs/$i.log &
done