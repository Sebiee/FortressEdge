#!/bin/sh
# Loadgen VM: curl checks routing/308, vegeta measures HTTPS.
# CA is the root the edge's ACME certificates chain to.
#
#   EDGE=192.0.2.10 CA=ca.crt test/perf/loadgen.sh
#   RATE=0 WORKERS=50 DURATION=30s   # max throughput
set -eu
cd "$(dirname "$0")"
edge=${EDGE:?set EDGE to the fortressedge VM IP}
ca=${CA:?set CA to the root the edge certificates chain to}
http_port=${HTTP_PORT:-80}
https_port=${HTTPS_PORT:-443}
duration=${DURATION:-30s}
rate=${RATE:-50}
workers=${WORKERS:-10}
timeout=${TIMEOUT:-5s}
vegeta_ver=12.13.0

need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
need curl
need tar
need gzip
need sha256sum

bindir=$PWD/.bin
mkdir -p "$bindir"
vegeta=$bindir/vegeta
if ! [ -x "$vegeta" ]; then
	arch=$(uname -m)
	case "$arch" in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "unsupported arch $arch" >&2; exit 1 ;;
	esac
	base=https://github.com/tsenart/vegeta/releases/download/v${vegeta_ver}
	asset=vegeta_${vegeta_ver}_linux_${arch}.tar.gz
	tgz=$bindir/$asset
	sums=$bindir/vegeta_checksums.txt
	curl -fsSL -o "$sums" "${base}/vegeta_${vegeta_ver}_checksums.txt"
	curl -fsSL -o "$tgz" "${base}/${asset}"
	(
		cd "$bindir"
		grep " ${asset}$" vegeta_checksums.txt | sha256sum -c
	)
	tar -xzf "$tgz" -C "$bindir" vegeta
	rm -f "$tgz" "$sums"
	chmod +x "$vegeta"
fi

norm() { tr -d '\r\n'; }

check_308() {
	host=$1
	url="http://${host}/x"
	resolve="${host}:80:${edge}"
	if [ "$http_port" != 80 ]; then
		url="http://${host}:${http_port}/x"
		resolve="${host}:${http_port}:${edge}"
	fi
	got=$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --connect-timeout 3 --resolve "$resolve" "$url" || true)
	want="308 https://${host}/x"
	if [ "$got" != "$want" ]; then
		echo "e2e: 308 $host: got $got want $want" >&2
		exit 1
	fi
	echo "ok  308  $host -> https://${host}/x"
}

check_https() {
	host=$1
	want=$2
	url="https://${host}/"
	resolve="${host}:443:${edge}"
	if [ "$https_port" != 443 ]; then
		url="https://${host}:${https_port}/"
		resolve="${host}:${https_port}:${edge}"
	fi
	got=$(curl -sS --fail --connect-timeout 3 --cacert "$ca" --resolve "$resolve" "$url" | norm)
	if [ "$got" != "$want" ]; then
		echo "e2e: https $host: got ${got:-<empty>} want $want" >&2
		exit 1
	fi
	echo "ok  https $host body=$want"
}

echo "== correctness"
check_308 a.example.com
check_308 b.example.com
check_308 c.example.com
check_https a.example.com origin-a
check_https b.example.com origin-b
check_https c.example.com origin-c

targets=$bindir/targets.txt
if [ "$https_port" = 443 ]; then
	cat >"$targets" <<'EOF'
GET https://a.example.com/
GET https://b.example.com/
GET https://c.example.com/
EOF
	connect_a=a.example.com:443:${edge}:443
	connect_b=b.example.com:443:${edge}:443
	connect_c=c.example.com:443:${edge}:443
else
	cat >"$targets" <<EOF
GET https://a.example.com:${https_port}/
GET https://b.example.com:${https_port}/
GET https://c.example.com:${https_port}/
EOF
	connect_a=a.example.com:${https_port}:${edge}:${https_port}
	connect_b=b.example.com:${https_port}:${edge}:${https_port}
	connect_c=c.example.com:${https_port}:${edge}:${https_port}
fi

bin=$bindir/results.bin
echo "== vegeta rate=$rate duration=$duration workers=$workers"
"$vegeta" attack \
	-targets="$targets" \
	-root-certs="$ca" \
	-connect-to="$connect_a" \
	-connect-to="$connect_b" \
	-connect-to="$connect_c" \
	-http2=true \
	-keepalive=true \
	-redirects=0 \
	-timeout="$timeout" \
	-workers="$workers" \
	-max-workers="$workers" \
	-rate="$rate" \
	-duration="$duration" \
	>"$bin"

echo
"$vegeta" report "$bin"
"$vegeta" report -type=json "$bin" | tee "$bindir/results.json"
echo
success=$(sed -n 's/.*"success":\([0-9.]*\).*/\1/p' "$bindir/results.json")
case "$success" in
1 | 1.0 | 1.00 | 1.000*) ;;
*)
	echo "e2e: vegeta success=$success (want 1)" >&2
	exit 1
	;;
esac

echo "== correctness after load"
check_https a.example.com origin-a
check_https b.example.com origin-b
check_https c.example.com origin-c
echo "e2e: ok"
