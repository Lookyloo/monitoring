# Lookyloo Monitoring

A companion tool for Lookyloo that lets you schedule the monitoring of URLs, using the Lookyloo stack as a backend.

# Install guide

## System dependencies

You need poetry installed, see the [install guide](https://python-poetry.org/docs/).

## Prerequisites

You need to have redis cloned and installed in the same directory you clone this template in:
this repoitory and and `redis` must be in the same directory, and **not** `redis` cloned in the
this directory. See [this guide](https://www.lookyloo.eu/docs/main/install-lookyloo.html#_install_redis).

## Installation

From the directory you just cloned, run:

```bash
poetry install
```

Initialize the `.env` file:

```bash
echo WEBMONITORING_HOME="`pwd`" >> .env
```

**Note**: `WEBMONITORING_HOME` is the name you have in `webmonitoring/default/__init__.py`

## Configuration

Copy the config file:

```bash
cp config/generic.json.sample config/generic.json
```

And configure it accordingly to your needs.

# Usage

Start the tool (as usual, from the directory):

```bash
poetry run start
```

You can stop it with

```bash
poetry run stop
```

With the default configuration, you can access the web interface on `http://0.0.0.0:5200`,
where you will find the API and can start playing with it.
