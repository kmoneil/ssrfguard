# Documentation

Start with **[Getting started](getting-started.md)**. After that the guides are shaped by task
rather than by module.

| Guide                                           | What is in it                                                                                                                                            |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Getting started](getting-started.md)           | Install, your first request, what the default policy does, what a refusal looks like, and the one thing worth understanding                              |
| [Configuring a policy](policy.md)               | Every field and its default, reaching your own internal services, partial answers, redirects, proxies, and the policies that are refused at construction |
| [The clients](clients.md)                       | The three surfaces, why they are clients and not transports, TLS, the async resolver pool, what is checked and when, and the three named asymmetries     |
| [Errors](errors.md)                             | The hierarchy, what each carries, how to handle them, and what is deliberately not wrapped                                                               |
| [Using the pieces directly](building-blocks.md) | `check_url` / `resolve` / `connect` for a protocol this package ships no client for, including the correct TLS wrap                                      |
| [The address table](address-table.md)           | What is in it, how a wrapper is decoded, longest-prefix-wins, building your own, and every place it departs from IANA                                    |
| [What it costs](cost.md)                        | The measured numbers, the shape that matters more than the numbers, and what is not bounded                                                              |
| [Why this exists](architecture.md)              | The bug, the fix, where the seam is, the failures this prevents and the test that proves each one, and what this is not                                  |
| [Threat model](threat-model.md)                 | What an attacker controls, what meets each capability, and the residual risk in detail: what is not defended, what is defended less than it looks, and where the tests would not notice |

**[`examples/`](../examples/README.md) is the other half of the documentation**, and it is
executed rather than described: nine runnable files, each of which works with **no arguments**, no
network and no fixtures, and every one of them is run by the test suite. If you would rather read
code than prose, start there.

## Elsewhere in the repository

|                                         |                                                            |
| --------------------------------------- | ---------------------------------------------------------- |
| [`README.md`](../README.md)             | The front page                                             |
| [`CHANGELOG.md`](../CHANGELOG.md)       | What changed, and why                                      |
| [`SECURITY.md`](../SECURITY.md)         | Reporting a vulnerability, and what is in and out of scope |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Setup, the lanes, and what a review will send back         |

```sh
python scripts/lanes.py     # every lane, what it checks, whether it gates
```
