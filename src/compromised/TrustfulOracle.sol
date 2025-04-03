// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {LibSort} from "solady/utils/LibSort.sol";

/**
 * @notice A price oracle with a number of trusted sources that individually report prices for symbols.
 *         The oracle's price for a given symbol is the median price of the symbol over all sources.
 */
contract TrustfulOracle is AccessControlEnumerable {
    uint256 public constant MIN_SOURCES = 1;
    bytes32 public constant TRUSTED_SOURCE_ROLE = keccak256("TRUSTED_SOURCE_ROLE");
    bytes32 public constant INITIALIZER_ROLE = keccak256("INITIALIZER_ROLE");

    // Source address => (symbol => price)
    mapping(address => mapping(string => uint256)) private _pricesBySource;

    error NotEnoughSources();

    event UpdatedPrice(address indexed source, string indexed symbol, uint256 oldPrice, uint256 newPrice);

    /// @notice Initializes the contract with trusted sources and optionally enables initialization role
    /// @param sources Array of trusted source addresses
    /// @param enableInitialization Boolean to enable initialization role
    constructor(address[] memory sources, bool enableInitialization) {
        if (sources.length < MIN_SOURCES) {
            revert NotEnoughSources();
        }
        for (uint256 i = 0; i < sources.length;) {
            unchecked {
                _grantRole(TRUSTED_SOURCE_ROLE, sources[i]);
                ++i;
            }
        }
        if (enableInitialization) {
            _grantRole(INITIALIZER_ROLE, msg.sender);
        }
    }

    /// @notice Sets up initial prices for symbols from trusted sources (can only be called once)
    /// @param sources Array of source addresses
    /// @param symbols Array of symbol strings
    /// @param prices Array of initial prices
    function setupInitialPrices(address[] calldata sources, string[] calldata symbols, uint256[] calldata prices)
        external
        onlyRole(INITIALIZER_ROLE)
    {
        // Only allow one (symbol, price) per source
        require(sources.length == symbols.length && symbols.length == prices.length);
        for (uint256 i = 0; i < sources.length;) {
            unchecked {
                _setPrice(sources[i], symbols[i], prices[i]);
                ++i;
            }
        }
        renounceRole(INITIALIZER_ROLE, msg.sender);
    }

    /// @notice Allows a trusted source to post a new price for a symbol
    /// @param symbol The trading symbol to update
    /// @param newPrice The new price value
    function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
        _setPrice(msg.sender, symbol, newPrice);
    }

    /// @notice Gets the median price for a symbol across all sources
    /// @param symbol The trading symbol to query
    /// @return The median price
    function getMedianPrice(string calldata symbol) external view returns (uint256) {
        return _computeMedianPrice(symbol);
    }

    /// @notice Returns all prices from all sources for a given symbol
    /// @param symbol The trading symbol to query
    /// @return prices Array of prices from all sources
    function getAllPricesForSymbol(string memory symbol) public view returns (uint256[] memory prices) {
        uint256 numberOfSources = getRoleMemberCount(TRUSTED_SOURCE_ROLE);
        prices = new uint256[](numberOfSources);
        for (uint256 i = 0; i < numberOfSources;) {
            address source = getRoleMember(TRUSTED_SOURCE_ROLE, i);
            prices[i] = getPriceBySource(symbol, source);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Gets the price of a symbol from a specific source
    /// @param symbol The trading symbol to query
    /// @param source The source address
    /// @return The price from the specified source
    function getPriceBySource(string memory symbol, address source) public view returns (uint256) {
        return _pricesBySource[source][symbol];
    }

    /// @notice Internal function to set price for a symbol from a source
    /// @param source The source address
    /// @param symbol The trading symbol
    /// @param newPrice The new price to set
    function _setPrice(address source, string memory symbol, uint256 newPrice) private {
        uint256 oldPrice = _pricesBySource[source][symbol];
        _pricesBySource[source][symbol] = newPrice;
        emit UpdatedPrice(source, symbol, oldPrice, newPrice);
    }

    /// @notice Internal function to compute the median price for a symbol
    /// @param symbol The trading symbol
    /// @return The calculated median price
    function _computeMedianPrice(string memory symbol) private view returns (uint256) {
        /* 
        * Example of how the median calculation works:
        * 
        * Case 1 (Odd number of prices):
        * Original:  [10, 5, 8, 12, 3]
        * Sorted:    [3, 5, 8, 10, 12]
        *                   ^
        * Median = 8 (middle element)
        * 
        * Case 2 (Even number of prices):
        * Original:  [10, 5, 8, 12]
        * Sorted:    [5, 8, 10, 12]
        *                ^  ^
        * Median = (8 + 10) / 2 = 9
        */

        uint256[] memory prices = getAllPricesForSymbol(symbol);
        // Sort prices in ascending order
        LibSort.insertionSort(prices);
        
        if (prices.length % 2 == 0) {
            // Even number of prices: average of two middle values
            uint256 leftPrice = prices[(prices.length / 2) - 1];
            uint256 rightPrice = prices[prices.length / 2];
            return (leftPrice + rightPrice) / 2;
        } else {
            // Odd number of prices: middle value
            return prices[prices.length / 2];
        }
    }
}
