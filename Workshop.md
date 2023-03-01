# Workshop Advancing Bitcoin

## Fedimint is more than E-Cash

TODO: graphic of consensus flow
TODO: graphic of module system



## Builing your first own module

Idea:
* Generate consensus on BTC price
* Allow betting on price in 10 minutes

## Step 0: Dev setup
[We use a Nix-based developer environment, see documentation for details.](docs/dev-env.md)

## Step 1: Add a dummy module
* There already is a [dummy module in the repository](https://github.com/fedimint/fedimint/tree/master/modules/fedimint-dummy)
* We just need to add it to `fedimintd`

## Step 2: Implement consensus on price
* Add price API endpoint to config
* Use module consensus items 
* Returned by [`ServerModule::consensus_proposal`](https://github.com/fedimint/fedimint/blob/3f9e4b59884b5ea495cb36f4f8398df133ff97dc/fedimint-core/src/module/mod.rs#L659) each epoch
* Given to [`begin_consensus_epoch`](https://github.com/fedimint/fedimint/blob/3f9e4b59884b5ea495cb36f4f8398df133ff97dc/fedimint-core/src/module/mod.rs#LL669C14-L669C35) as input after consensus is achieved and gets processed there

## Step 3: Implement bet smart contract
* Create struct saved to DB containing bet details
* Implement deposit/withdraw functionality by defining module transaction inputs and outputs
* Define withdraw logic that limits who can withdraw when
* Implement audit function so there's no discrepancy making Fedimint crash

## Step 3: 
