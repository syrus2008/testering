import sys

if len(sys.argv) > 1 and sys.argv[1] == "__worker__":
    # Frozen builds start workers as `acet __worker__ request.json` (engines.worker.worker_command).
    from acet.engines.worker import main as worker_main

    raise SystemExit(worker_main(sys.argv[2:]))

from acet.cli.main import main

raise SystemExit(main())
