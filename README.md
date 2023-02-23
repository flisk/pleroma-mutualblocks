# pleroma-mutualblocks

Automated mutual blocking for Pleroma and Akkoma instances.

⚠️ **This software is experimental. Don't use it unless you understand the following:**

* You should have a database backup of your instance **before** you run this.
* Any part of this might break. Be prepared to break out the toolbox and fix
  things yourself, or to report the problems you run into.
* This tool uses fba.ryona.agency, and it doesn't work without it. If you have
  reservations about that, don't use this software.

## About

This program automatically creates and deletes suspend rules against other
instances that are known by [ryona.agency's fediblock API][1] to be suspending
your instance. This is to avoid "shadowban dynamics", i.e. users unknowingly
trying to interact from suspended instances.

## How It Works

* information on suspensions is fetched from fba.ryona.agency
* the program only manages blocks that have a special block reason set
* managed blocks are kept at the top of your block rules
* blocking instances are automatically "blocked back" if:
  - there isn't already a manual block against the blocking instance in place
  - the block was last seen no later than a configurable threshold ago
* automatically blocked instances are unblocked if:
  - the block data has gone stale, i.e. hasn't been seen for longer than the
    configured threshold

## Requirements

Python 3.9 or newer. That's it, I think. The pipenv stuff in this repo is just
for type checking and not required just to run the program.

## Usage

### Setup

```
$ git clone https://github.com/flisk/pleroma-mutualblocks
$ cd pleroma-mutualblocks
$ cp config.sample.ini config.ini
$ chmod 600 config.ini  # this is important, you'll be putting a sensitive secret in here
# now customize config.ini with an editor of your choice
```

### Operation

```
$ cd pleroma-mutualblocks
$ python3 -m mutualblocks
```

## License

[GPLv3][COPYING.txt].

[1]: https://fba.ryona.agency/
