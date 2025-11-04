# Impala bridge

The Payala impala bridge uses the Rust SDK to exercise the Horizon API or RPC API for
[accounts](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/accounts), 
[assets](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/assets),
[payments](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/payments),
and [transactions](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/transactions).

In turn, the Payala API is invoked by the impala bridge to correlate payments and accounts
in a Payala program with the Stellar network.

