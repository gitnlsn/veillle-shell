#!/bin/bash
# benchmark.sh - Performance testing and profiling for nlsn-monitor

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}🚀 nlsn-monitor Performance Benchmark Suite${NC}"
echo "=============================================="
echo ""

cd "$PROJECT_ROOT"

# Create benchmark output directory
BENCH_DIR="$PROJECT_ROOT/benchmarks"
mkdir -p "$BENCH_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${GREEN}1. Running Go Benchmarks${NC}"
echo ""

# Parser benchmarks
echo "📊 DNS Parser Benchmarks:"
go test ./internal/parser/... -bench=. -benchmem -benchtime=3s | tee "$BENCH_DIR/parser_${TIMESTAMP}.txt"
echo ""

# Run all benchmarks with CPU profiling
echo -e "${GREEN}2. CPU Profiling${NC}"
echo ""
go test ./internal/parser/... -bench=BenchmarkParseRaw -cpuprofile="$BENCH_DIR/cpu_${TIMESTAMP}.prof" -benchtime=5s > /dev/null 2>&1

if [ -f "$BENCH_DIR/cpu_${TIMESTAMP}.prof" ]; then
    echo "✅ CPU profile saved: $BENCH_DIR/cpu_${TIMESTAMP}.prof"
    echo ""
    echo "View with: go tool pprof $BENCH_DIR/cpu_${TIMESTAMP}.prof"
    echo "  Commands in pprof:"
    echo "    top10     - Show top 10 functions by CPU"
    echo "    list ParseRaw - Show source with timing"
    echo "    web       - Open graph in browser (needs graphviz)"
fi

echo ""

# Memory profiling
echo -e "${GREEN}3. Memory Profiling${NC}"
echo ""
go test ./internal/parser/... -bench=BenchmarkParseRaw -memprofile="$BENCH_DIR/mem_${TIMESTAMP}.prof" -benchtime=5s > /dev/null 2>&1

if [ -f "$BENCH_DIR/mem_${TIMESTAMP}.prof" ]; then
    echo "✅ Memory profile saved: $BENCH_DIR/mem_${TIMESTAMP}.prof"
    echo ""
    echo "View with: go tool pprof -alloc_space $BENCH_DIR/mem_${TIMESTAMP}.prof"
fi

echo ""

# Build and check binary size
echo -e "${GREEN}4. Binary Size Analysis${NC}"
echo ""
make build > /dev/null 2>&1

if [ -f "nlsn-monitor" ]; then
    SIZE=$(du -h nlsn-monitor | cut -f1)
    echo "Binary size: $SIZE"

    # Show binary sections
    if command -v size &> /dev/null; then
        echo ""
        size nlsn-monitor
    fi
fi

echo ""

# Test data throughput
echo -e "${GREEN}5. Theoretical Throughput Analysis${NC}"
echo ""

# Parse benchmark results
if [ -f "$BENCH_DIR/parser_${TIMESTAMP}.txt" ]; then
    NS_PER_OP=$(grep "BenchmarkParseRaw" "$BENCH_DIR/parser_${TIMESTAMP}.txt" | awk '{print $3}')

    if [ ! -z "$NS_PER_OP" ]; then
        # Calculate packets per second (ns to seconds)
        # pps = 1,000,000,000 / ns_per_op
        PPS=$(echo "scale=0; 1000000000 / $NS_PER_OP" | bc)

        echo "Parse time: ${NS_PER_OP} ns/op"
        echo "Theoretical max: $(printf "%'d" $PPS) packets/second"
        echo ""

        # At average DNS packet size (512 bytes)
        MBPS=$(echo "scale=2; ($PPS * 512 * 8) / 1000000" | bc)
        echo "Bandwidth @ 512B packets: ${MBPS} Mbps"

        # Calculate for different packet sizes
        echo ""
        echo "Throughput by packet size:"
        for SIZE in 64 128 256 512 1024; do
            MBPS=$(echo "scale=1; ($PPS * $SIZE * 8) / 1000000" | bc)
            printf "  %4d bytes: %8.1f Mbps\n" $SIZE $MBPS
        done
    fi
fi

echo ""

# Memory usage estimation
echo -e "${GREEN}6. Memory Usage Estimation${NC}"
echo ""

BYTES_PER_OP=$(grep "BenchmarkParseRaw" "$BENCH_DIR/parser_${TIMESTAMP}.txt" | awk '{print $5}')

if [ ! -z "$BYTES_PER_OP" ]; then
    echo "Memory per packet: ${BYTES_PER_OP} B/op"

    # Estimate for 1 million packets
    MB_PER_MILLION=$(echo "scale=2; ($BYTES_PER_OP * 1000000) / 1048576" | bc)
    echo "Memory for 1M packets: ${MB_PER_MILLION} MB"

    # Estimate for 1 hour at 1000 pps
    PACKETS_PER_HOUR=$((1000 * 3600))
    MB_PER_HOUR=$(echo "scale=2; ($BYTES_PER_OP * $PACKETS_PER_HOUR) / 1048576" | bc)
    echo "Memory for 1h @ 1000pps: ${MB_PER_HOUR} MB"
fi

echo ""

# Performance goals check
echo -e "${GREEN}7. Performance Goals Check${NC}"
echo ""

# Goals from STATUS.md
GOAL_PPS=10000
GOAL_FPR=5  # 5% false positive rate

echo "📋 Phase 1 Performance Goals:"
echo ""

# Check throughput goal
if [ ! -z "$PPS" ]; then
    if [ $PPS -gt $GOAL_PPS ]; then
        echo -e "✅ Throughput: ${GREEN}PASS${NC}"
        echo "   Target: ${GOAL_PPS} pps"
        echo "   Actual: $(printf "%'d" $PPS) pps"
        PERCENT=$((($PPS * 100) / $GOAL_PPS))
        echo "   Performance: ${PERCENT}% of goal"
    else
        echo -e "❌ Throughput: ${YELLOW}NEEDS IMPROVEMENT${NC}"
        echo "   Target: ${GOAL_PPS} pps"
        echo "   Actual: $(printf "%'d" $PPS) pps"
    fi
else
    echo "⚠️  Could not calculate throughput"
fi

echo ""

# False positive rate (requires real testing)
echo "⏳ False Positive Rate: PENDING"
echo "   Target: <${GOAL_FPR}%"
echo "   Actual: Requires real-world testing"
echo "   Run: sudo ./nlsn-monitor start (monitor for 1 hour)"

echo ""

# Summary
echo -e "${CYAN}📊 Benchmark Summary${NC}"
echo "================================"
echo "Results saved to: $BENCH_DIR/"
echo ""
echo "Files generated:"
ls -lh "$BENCH_DIR" | grep "$TIMESTAMP" | awk '{print "  " $9 " (" $5 ")"}'

echo ""
echo -e "${GREEN}✅ Benchmarking complete!${NC}"
echo ""

echo "💡 Next steps:"
echo "   1. View CPU profile: go tool pprof $BENCH_DIR/cpu_${TIMESTAMP}.prof"
echo "   2. View memory profile: go tool pprof $BENCH_DIR/mem_${TIMESTAMP}.prof"
echo "   3. Compare with previous runs in $BENCH_DIR/"
echo "   4. Run real-world test: sudo ./nlsn-monitor start -v"
