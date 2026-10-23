# TheHive 5 — Installation & Configuration

TheHive is the case-management system of record, where enriched alerts become investigable cases. It needs two backing stores — Apache Cassandra (data) and Elasticsearch (full-text index) — plus Java, so most of the work is standing those up and tuning them to fit the host.

## Specifications

- RAM: 8 GB minimum (16 GB recommended — three JVMs run side by side)
- Disk: 50 GB minimum
- OS: Ubuntu 22.04 LTS

## 1. Dependencies

```bash
sudo apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java \
  curl software-properties-common python3-pip lsb-release
```

## 2. Java (Amazon Corretto 11)

```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | \
  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo 'JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"' | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

## 3. Cassandra (data store)

```bash
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | \
  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

## 4. Elasticsearch (index)

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

**Heap tuning (important on a small VM).** Create `/etc/elasticsearch/jvm.options.d/jvm.options` and size the heap to fit the host — Cassandra, Elasticsearch and TheHive each run a JVM, and all three must fit in RAM or TheHive crashes on startup:

```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

On a constrained VM (e.g. 6 GB) cap each of the three JVMs at **1 GB** instead (`-Xms1g -Xmx1g`). Also raise the memory-map limit Elasticsearch requires:

```bash
sudo sysctl -w vm.max_map_count=262144
```

## 5. TheHive

```bash
wget -O /tmp/thehive.deb https://thehive.download.strangebee.com/5.5/deb/thehive_5.5.13-1_all.deb
sudo apt-get install -y /tmp/thehive.deb
```

> The old `archives.strangebee.com` path returns 404 — use `thehive.download.strangebee.com` as above.

## 6. Configuration

Pick one `cluster-name` value (e.g. `SOC-Lab`) and use it identically in Cassandra and in `application.conf`. Replace `x.x.x.x` with this VM's IP throughout.

### Cassandra — `/etc/cassandra/cassandra.yaml`

```yaml
cluster_name: 'SOC-Lab'
listen_address: x.x.x.x
rpc_address:    x.x.x.x
seed_provider:
  - class_name: org.apache.cassandra.locator.SimpleSeedProvider
    parameters:
      - seeds: "x.x.x.x:7000"
```

Changing `cluster_name` means the existing data directory no longer matches, so Cassandra must be reset once before it will start:

```bash
sudo systemctl stop cassandra
sudo rm -rf /var/lib/cassandra/*
sudo systemctl start cassandra
```

### Elasticsearch — `/etc/elasticsearch/elasticsearch.yml`

```yaml
cluster.name: SOC-Lab
node.name: node-1                     # uncomment this line
network.host: x.x.x.x
http.port: 9200
cluster.initial_master_nodes: ["node-1"]
```

```bash
sudo systemctl start elasticsearch
```

### TheHive — `/etc/thehive/application.conf`

Point TheHive at the two stores and set its base URL:

```hocon
db.janusgraph {
  storage {
    hostname = ["x.x.x.x"]
    cql { cluster-name = SOC-Lab }     # must match cassandra.yaml
  }
  index.search {
    hostname = ["x.x.x.x"]
  }
}
application.baseUrl = "http://x.x.x.x:9000"
```

Give the TheHive service account ownership of its data path, then start and enable the service:

```bash
sudo chown -R thehive:thehive /opt/thp
sudo systemctl start thehive
sudo systemctl enable thehive
```

## 7. Start order and verification

The services must come up in dependency order, and each must be enabled so it survives a reboot:

```bash
sudo systemctl enable --now cassandra
sudo systemctl enable --now elasticsearch
sudo systemctl enable --now thehive
```

TheHive takes a minute to initialise. Browse to `http://x.x.x.x:9000` and log in with the defaults `admin@thehive.local` / `secret` (change the password on first login). If the page does not load, check `sudo systemctl status thehive` — a `status=1` exit almost always means the three JVMs did not fit in RAM (revisit the heap caps in step 4).

## 8. Reaching TheHive from cloud Shuffle (the NAT problem)

Shuffle runs in the cloud; TheHive sits on a private `x.x.x.x/24` network with no public address, so Shuffle cannot call it directly. Bridge the gap with an ngrok tunnel on the TheHive host, then use the public forwarding URL ngrok prints as TheHive's base URL in the Shuffle app:

```bash
ngrok http x.x.x.x:9000
```
