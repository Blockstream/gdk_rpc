#!/usr/bin/env bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    export PATH=${PATH}:/bitcoin/bin:/liquid/bin
    source /root/.cargo/env
fi

DATADIR=${DATADIR:-~/tmp/test_gdk_rpc}
EXEC_NODE=${EXEC_NODE:-bitcoind}
EXEC_CLI=${EXEC_CLI:-bitcoin-cli}

TEST_MODE=${TEST_MODE:-bitcoinregtest}


CLI_CMD="$EXEC_CLI -rpcwait -datadir=$DATADIR"
if [ "x$TEST_MODE" = "xbitcoinregtest" ]
then
    CLI_CMD="$CLI_CMD -regtest"
elif [ "x$TEST_MODE" = "xelementsregtest" ]
then
    CLI_CMD="$CLI_CMD -chain=elementsregtest"
fi


echo "Killing existing nodes..."
$CLI_CMD stop || true
sleep 1


echo "Removing datadir..."
rm -fr "$DATADIR"
mkdir -p "$DATADIR"


echo "Starting daemon..."
if [ "x$TEST_MODE" = "xbitcoinregtest" ]
then
    EXTRA_ARGS="-regtest"
elif [ "x$TEST_MODE" = "xelementsregtest" ]
then
    EXTRA_ARGS="-chain=elementsregtest -minrelaytxfee=0 -blockmintxfee=0 -validatepegin=0 -con_blocksubsidy=5000000000"
fi
$EXEC_NODE -server=1 -daemon -datadir=$DATADIR $EXTRA_ARGS


echo "Mining blocks..."
ADDR=$($CLI_CMD getnewaddress)
echo "Mining 200 blocks to $ADDR..."
$CLI_CMD generatetoaddress 200 $ADDR

echo "Running tests..."
# we capture the return value so that we can run the teardown commands
set +e
if [ "x$TEST_MODE" = "xbitcoinregtest" ]
then
    BITCOIND_DIR="$DATADIR/regtest" \
    TEST_MODE="bitcoinregtest" \
    cargo test --features stderr_logger --all  -- --test-threads=1
elif [ "x$TEST_MODE" = "xelementsregtest" ]
then
    BITCOIND_DIR="$DATADIR/elementsregtest" \
    BITCOIND_URL="http://127.0.0.1:7040" \
    GDK_RPC_NETWORK="elementsregtest-cookie" \
    TEST_MODE="elementsregtest" \
    cargo test --features stderr_logger --all  -- --test-threads=1
fi
RET=$?

make tests/c-test && ./tests/c-test

echo "Stopping daemon..."
$CLI_CMD stop
sleep 1
echo "Removing datadir..."
rm -fr "$DATADIR"

exit $RET
