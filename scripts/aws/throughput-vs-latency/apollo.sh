ID=$1
TESTDIR=${2:-"testdata/b100-n3"}
DELAY=${3:-"50"}
CLI_TYPE=${4:-"client-artemis"}

cd libchatter-rs

if [ $CLI_TYPE == "client-artemis" ]; then
    CLI_TYPE="-s"
else
    CLI_TYPE=""
fi

# sleep 30
# echo "Using arguments: --config $TESTDIR/nodes-$ID.json --ip ips_file --delta "$DELAY" -s"

./target/release/node-artemis \
    --config $TESTDIR/nodes-$ID.json \
    --ip ips_file \
    --delta "$DELAY" \
    $CLI_TYPE &