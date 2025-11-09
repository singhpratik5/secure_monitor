secure_monitor/
├── src/
│   ├── main.c
│   ├── daemon.c
│   ├── network.c
│   ├── signal_handler.c
│   ├── monitor.c
│   ├── protocol.c
│   ├── plugin.c
│   └── security.c
├── include/
│   ├── daemon.h
│   ├── network.h
│   ├── monitor.h
│   ├── protocol.h
│   ├── plugin.h
│   └── security.h
├── config/
│   ├── monitor.conf
│   └── inetd.conf.example
├── scripts/
│   ├── init-script.sh
│   └── test_suite.sh
├── plugins/
│   ├── cpu_monitor.c
│   └── mem_monitor.c
├── tests/
│   ├── test_protocol.c
│   └── test_fault_injection.c
├── Makefile
└── README.md