# Contributing

To contribute to this charm, you will have to prepare the develpoment environment by installing the
following tools.

- [uv](https://docs.astral.sh/uv/)
- [just](https://github.com/casey/just)
- [Juju](https://documentation.ubuntu.com/juju/3.6/howto/manage-your-juju-deployment/set-up-your-juju-deployment/)
- [Charmcraft](https://documentation.ubuntu.com/charmcraft/stable/howto/)

## Testing

This project uses `uv` for managing test environments. There are some pre-configured recipes that
can be used for linting and formatting code when you're preparing contributions to the charm. You
can learn more about the recipes by running `just --help` or `just`:

```shell
$ just
Available recipes:
    check  # Format and analyze the code
    fix    # Format the Python code
    static # Run static code analysis
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```
