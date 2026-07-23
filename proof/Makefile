JAR      := tools/tla2tools.jar
APALACHE := tools/apalache/bin/apalache-mc
SPECS    := TaskLifecycle ContractChain ReceivePipeline Introduction \
            BrokerBudget RollbackAdversary TaskLiveness

all: $(SPECS)

$(SPECS): $(JAR)
	./check.sh $@

negative: $(JAR) $(APALACHE)
	./negative-checks.sh

conformance:
	cd conformance && cargo test

inductive: $(APALACHE)
	./inductive.sh

full: all conformance inductive negative

$(JAR):
	mkdir -p tools
	curl -sL -o $(JAR) https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

$(APALACHE):
	mkdir -p tools
	curl -sL -o tools/apalache.tgz https://github.com/apalache-mc/apalache/releases/latest/download/apalache.tgz
	tar xzf tools/apalache.tgz -C tools && rm tools/apalache.tgz

.PHONY: all negative conformance inductive full $(SPECS)
