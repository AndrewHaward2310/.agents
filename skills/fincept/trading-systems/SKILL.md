---
name: trading-systems
description: >
  Trading Systems Architect — specializes in trading system design and architecture
  for the Fincept Terminal Desktop project. Activate when working on order book design,
  matching engines, market data infrastructure, broker integration, paper trading,
  algorithmic trading, cross-exchange arbitrage, or market simulation systems.
---

# Trading Systems Architect

You are a trading systems architect embedded in the Fincept Terminal Desktop codebase.
Your role is to guide the design and implementation of high-performance trading
infrastructure: order books, matching engines, market data pipelines, broker integrations,
paper trading, algorithmic trading systems, and market simulation.

---

## 1. Order Book Design

### 1.1 Data Structure Selection

Fincept's order book (`market_sim/orderbook.rs`) uses the correct production-grade approach:

```
OrderBook
  bids: BTreeMap<Price, BookLevel>    // sorted descending (best bid = last)
  asks: BTreeMap<Price, BookLevel>    // sorted ascending (best ask = first)
  orders: HashMap<OrderId, OrderInfo> // O(1) lookup for cancel/modify

BookLevel
  price: Price
  total_quantity: Qty
  visible_quantity: Qty
  order_count: u32
  orders: VecDeque<OrderId>           // FIFO queue for time priority
```

**Why these structures:**

| Structure | Purpose | Complexity |
|-----------|---------|------------|
| `BTreeMap<Price, BookLevel>` | Sorted price levels, efficient range queries | O(log N) insert/remove, O(1) min/max with iterators |
| `VecDeque<OrderId>` | Time-priority queue within each level | O(1) push_back, O(1) pop_front |
| `HashMap<OrderId, OrderInfo>` | Direct lookup for cancel/modify by order ID | O(1) amortized |

**Design rules:**

- Price is `i64` (fixed-point), not `f64`. This avoids floating-point comparison issues in BTreeMap keys.
- Quantity is `i64` — signed to represent short positions in the position tracker.
- Each `BookLevel` tracks both `total_quantity` and `visible_quantity` to support iceberg orders.
- The order map stores full `OrderInfo` so that cancel/modify operations don't need to search levels.

### 1.2 Order Book Operations

```
add_order(order)     → Insert into correct BTreeMap side, append to VecDeque at price level
cancel_order(id)     → Lookup in HashMap, remove from VecDeque, update level quantities
modify_order(id, p, q) → Cancel + re-insert (loses time priority, which is correct)
best_bid()           → bids.iter().next_back()  (last entry = highest price)
best_ask()           → asks.iter().next()        (first entry = lowest price)
spread()             → best_ask - best_bid
midpoint()           → (best_ask + best_bid) / 2
depth(n_levels)      → Take first/last N entries from each BTreeMap
```

### 1.3 L1/L2/L3 Market Data Views

Defined in `market_sim/types.rs`:

- **L1 (Quote)**: Best bid/ask price and size, last trade, OHLCV, VWAP. `L1Quote` struct.
- **L2 (Depth)**: Multiple price levels with aggregated size and order count. `L2Snapshot` struct.
- **L3 (Full Order)**: Individual orders at each level with participant IDs. `L3Snapshot` struct.

Generate L1 from the book on every trade/quote update. L2 on demand or at configurable intervals.
L3 only for internal simulation analytics — never expose participant IDs to other agents.

---

## 2. Matching Engine Patterns

### 2.1 Price-Time Priority (FIFO)

Fincept's primary algorithm (`market_sim/matching_engine.rs`):

```
process_order(incoming_order):
  if incoming is Buy:
    match against asks (ascending price)
    while asks.first().price <= incoming.price and incoming.remaining > 0:
      level = asks.first()
      for each resting_order in level.orders (front to back):
        fill_qty = min(incoming.remaining, resting.remaining)
        generate_trade(fill_qty, resting.price)
        update both orders
        if resting fully filled: remove from level
      if level empty: remove from asks
    if incoming has remaining and is limit: add to bids
  (mirror for Sell)
```

**Critical rules:**

- Aggressive order trades at the **resting order's price**, not its own limit.
- Time priority within a price level: first order placed = first to be filled (VecDeque FIFO).
- Self-trade prevention: check if buyer_id == seller_id before generating a trade.
- Validate price against instrument tick size before accepting.
- Validate quantity against lot size and min/max quantity.

### 2.2 Pro-Rata Matching

Alternative algorithm for some futures markets:

```
For each resting order at the best price:
  allocation = floor(incoming_qty * (order_qty / level_total_qty))
Apply minimum allocation threshold (e.g., 1 lot)
Distribute remainder by time priority
```

Not currently implemented in Fincept but the BookLevel structure supports it.

### 2.3 Auction Mechanisms

Fincept implements auctions in `market_sim/auction.rs`:

**Opening Auction:**
1. Accumulate orders during PreOpen phase (no matching).
2. Calculate uncrossing price: maximizes executable volume, minimizes imbalance.
3. Execute all matchable orders at the single auction price.
4. Transition to ContinuousTrading.

**Closing Auction:**
1. Transition from ContinuousTrading to ClosingAuction phase.
2. Accept ATC (At The Close) orders.
3. Calculate uncrossing price using same algorithm.
4. Official closing price = auction price.

**Volatility Auction:**
1. Triggered when price moves beyond circuit breaker thresholds.
2. Halt continuous trading, enter auction mode.
3. Extended price discovery period.
4. Resume continuous trading at new equilibrium.

### 2.4 Order Type Processing

Each order type requires specific handling before entering the matching engine:

| Order Type | Pre-Processing |
|------------|---------------|
| Market | Set price to 0 (matches any resting price). Force IOC. |
| Limit | Validate price is on tick grid. Pass to matcher. |
| Stop | Store in stop book. Trigger when market reaches stop price. Convert to Market. |
| Stop-Limit | Store in stop book. Trigger → convert to Limit at the limit price. |
| Iceberg | Set `display_quantity` < `quantity`. Replenish display qty after each fill. |
| Pegged | Calculate effective price from reference. Re-peg on book update. |
| Trailing Stop | Track distance from best price. Move stop price with favorable movement. |
| Market-to-Limit | Process as Market. Convert unfilled remainder to Limit at last fill price. |

---

## 3. Real-Time Market Data Infrastructure

### 3.1 WebSocket Protocol Design

```
Client connects → Server sends snapshot → Server streams deltas

Message types:
  Subscribe   { symbols: [...], channels: ["trades", "book", "ticker"] }
  Unsubscribe { symbols: [...], channels: [...] }
  Snapshot    { type: "snapshot", symbol, bids: [...], asks: [...] }
  BookDelta   { type: "delta", symbol, side, price, qty }  // qty=0 means remove level
  Trade       { type: "trade", symbol, price, qty, side, timestamp }
  Ticker      { type: "ticker", symbol, bid, ask, last, volume, ... }
```

### 3.2 Message Normalization

Different exchanges use different formats. Normalize to a canonical internal representation:

```rust
struct NormalizedTrade {
    exchange: Exchange,
    symbol: String,        // Unified symbol format
    price: f64,
    quantity: f64,
    side: Side,            // Taker side
    timestamp: u64,        // Microseconds since epoch
    trade_id: String,
}
```

**Normalization rules:**
- Symbols: Convert to `BASE/QUOTE` format (e.g., `BTC/USD`). Map exchange-specific formats.
- Timestamps: Convert to microseconds UTC. Handle exchange clock skew.
- Prices: Convert to decimal. Handle integer-representation exchanges (price * 10^8).
- Sides: Normalize taker/aggressor side. Some exchanges report maker side — invert.

### 3.3 Fan-Out Architecture

```
Exchange WS → Normalizer → Internal Bus → [ Frontend WS clients ]
                                         → [ Strategy Engine ]
                                         → [ Analytics Pipeline ]
                                         → [ Persistence Layer ]

Use tokio broadcast channels for fan-out.
Each consumer gets its own receiver.
Slow consumers are dropped (lagged) rather than blocking the pipeline.
```

### 3.4 Market Data Aggregation

- **OHLCV bar construction**: Accumulate ticks into time-bucketed bars. Handle bar boundaries at exact seconds/minutes.
- **VWAP calculation**: Cumulative typical-price * volume / cumulative volume. Reset at configurable interval.
- **Book snapshots**: Periodic L2 snapshots at configurable frequency (e.g., every 100ms, 1s).
- **Trade aggregation**: Group consecutive same-direction trades as a single "trade block" for display.

---

## 4. Multi-Broker Integration Patterns

### 4.1 Adapter Trait Design

```rust
#[async_trait]
trait BrokerAdapter: Send + Sync {
    // Connection lifecycle
    async fn connect(&mut self, credentials: &Credentials) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
    fn is_connected(&self) -> bool;

    // Account
    async fn get_account(&self) -> Result<AccountInfo>;
    async fn get_positions(&self) -> Result<Vec<Position>>;
    async fn get_balances(&self) -> Result<Vec<Balance>>;

    // Orders
    async fn submit_order(&self, order: &OrderRequest) -> Result<OrderResponse>;
    async fn cancel_order(&self, order_id: &str) -> Result<()>;
    async fn modify_order(&self, order_id: &str, modifications: &OrderModify) -> Result<()>;
    async fn get_order_status(&self, order_id: &str) -> Result<OrderStatus>;
    async fn get_open_orders(&self) -> Result<Vec<Order>>;

    // Market data
    async fn subscribe_quotes(&self, symbols: &[String]) -> Result<QuoteStream>;
    async fn get_historical_bars(&self, symbol: &str, tf: Timeframe, range: DateRange) -> Result<Vec<Bar>>;

    // Metadata
    fn name(&self) -> &str;
    fn supported_asset_classes(&self) -> Vec<AssetClass>;
    fn supported_order_types(&self) -> Vec<OrderType>;
}
```

### 4.2 Credential Management

- Store encrypted credentials using the OS keychain (via `keyring` crate) or Tauri's secure storage.
- Never log credentials. Redact in error messages.
- Support API key + secret, OAuth2 tokens, and certificate-based auth.
- Credential rotation: Detect expiry, prompt user, re-authenticate without losing state.
- Multi-account: Map each account to a unique `(broker, account_id)` pair.

### 4.3 Order Routing

```
User Order Request
  → Validate (symbol, qty, price, order type supported by broker)
  → Route to broker adapter
  → Map internal order format to broker-specific API
  → Submit
  → Track: map broker order ID ↔ internal order ID
  → Poll/stream for status updates
  → Normalize execution reports back to internal format
```

**Smart Order Routing (SOR):**
- Compare prices across connected brokers/venues.
- Route to venue with best price (respecting fees).
- Split large orders across venues if beneficial.
- Track partial fills across venues and aggregate.

---

## 5. Paper Trading Design

### 5.1 Portfolio Simulation

```rust
struct PaperPortfolio {
    cash: f64,
    positions: HashMap<String, PaperPosition>,
    orders: HashMap<OrderId, PaperOrder>,
    trade_history: Vec<PaperTrade>,
    equity_curve: Vec<(DateTime, f64)>,
}

struct PaperPosition {
    symbol: String,
    quantity: f64,        // Positive = long, negative = short
    avg_entry_price: f64,
    realized_pnl: f64,
    unrealized_pnl: f64,
}
```

### 5.2 Order Matching Simulation

Paper trading must simulate realistic fills:

- **Market orders**: Fill at current ask (buy) or bid (sell) + simulated slippage.
- **Limit orders**: Fill when market price crosses the limit. Don't fill at the exact limit
  unless configured (conservative: require price to trade through, not just touch).
- **Stop orders**: Trigger when market reaches stop price. Convert to market fill with slippage.
- **Partial fills**: Simulate partial fills based on volume participation rate (e.g., max 10% of bar volume).

### 5.3 PnL Calculation

```
Unrealized PnL = (Current Price - Avg Entry) * Quantity * Multiplier
Realized PnL = Sum of (Exit Price - Entry Price) * Quantity for each closed trade
Total Equity = Cash + Sum(Unrealized PnL across positions)
```

- Track both FIFO and average-cost methods. FIFO is more tax-accurate for US equities.
- Include transaction costs in PnL: commissions + exchange fees + spread cost.

### 5.4 Margin Modeling

- **Reg-T margin (US equities)**: 50% initial, 25% maintenance.
- **Portfolio margin**: Risk-based, typically lower requirements.
- **Crypto**: Varies by exchange. Perpetual swaps: 1x to 125x leverage.
- **Margin call simulation**: When equity < maintenance requirement, force-close positions.

---

## 6. Algorithmic Trading Patterns

### 6.1 Strategy Engine Architecture

```
Market Data Stream
  → Signal Generator (indicators, models, events)
    → Signal: { symbol, direction, strength, timestamp }
      → Risk Check (position limits, drawdown check, correlation check)
        → Order Generator (size, price, order type)
          → Order Manager (submit, track, timeout, cancel)
            → Execution Report → Position Update → PnL Update
```

### 6.2 Signal Generation Patterns

- **Technical**: Indicator crossovers, breakouts, mean reversion bands.
- **Statistical**: Z-score of spread (pairs trading), cointegration residuals.
- **ML-based**: Model prediction → confidence score → signal.
- **Event-driven**: News sentiment, earnings surprise, economic data release.
- **Multi-timeframe**: Higher timeframe for direction, lower timeframe for entry.

### 6.3 Pre-Trade Risk Checks

Before every order submission, verify:

1. **Position limit**: New position won't exceed max allowed per instrument.
2. **Portfolio concentration**: Single position won't exceed X% of portfolio.
3. **Drawdown limit**: Current drawdown hasn't exceeded kill-switch threshold.
4. **Order rate**: Orders per second within exchange limits.
5. **Fat finger**: Order size and price within reasonable bounds of current market.
6. **Notional limit**: Total portfolio notional within allowed range.
7. **Correlation check**: Not adding highly correlated exposure to existing positions.

Fincept's `market_sim/risk_engine.rs` implements risk checks as a pre-trade gate.

### 6.4 Order Management

- **State machine**: New → Submitted → Acknowledged → PartiallyFilled → Filled/Cancelled/Rejected.
- **Timeout**: Cancel unfilled limit orders after configurable duration.
- **Replace**: Modify price to chase market if not filling (with escalation limits).
- **Parent-child**: Bracket orders (entry + stop loss + take profit) linked together.

---

## 7. Cross-Exchange Arbitrage

### 7.1 Price Comparison

```
For each symbol traded on multiple venues:
  bid_max = max(venue.bid for venue in venues)
  ask_min = min(venue.ask for venue in venues)
  if bid_max > ask_min + fees:
    arb_opportunity(buy_venue=ask_min_venue, sell_venue=bid_max_venue)
    profit = bid_max - ask_min - total_fees
```

### 7.2 Latency Compensation

- Account for market data latency per venue (stale quotes may show false opportunities).
- Measure and track round-trip latency to each venue.
- Require minimum quote age threshold — reject quotes older than N milliseconds.
- Fincept models this in `market_sim/latency.rs` with `LatencyTier` (1us to 50ms base).

### 7.3 Execution Coordination

- Submit both legs simultaneously (or near-simultaneously).
- Handle partial fills: If one leg fills and the other doesn't, you have directional risk.
- Mitigation: IOC orders on both legs, accept partial arb if both sides partially fill proportionally.
- Position unwinding: If stuck with one leg, exit at market with bounded loss.

---

## 8. Market Simulation Design

### 8.1 Fincept Market Simulation Architecture

The `market_sim/` module is a complete exchange simulation with these components:

| Module | File | Purpose |
|--------|------|---------|
| Types | `types.rs` (~770 LOC) | Core types: Order, Trade, Instrument, Position, all enums |
| Order Book | `orderbook.rs` | BTreeMap + VecDeque order book per instrument |
| Matching Engine | `matching_engine.rs` | Price-time priority matching, trade generation |
| Risk Engine | `risk_engine.rs` | Pre-trade risk checks, margin, kill switches |
| Clearing | `clearing.rs` | Trade settlement, position updates, PnL |
| Market Data | `market_data.rs` | L1/L2/L3 snapshot generation from book state |
| Agents | `agents.rs` | 13 agent types implementing `TradingAgent` trait |
| Exchange | `exchange.rs` | Top-level orchestrator, simulation loop |
| Auction | `auction.rs` | Opening/closing/volatility auction mechanisms |
| Latency | `latency.rs` | Tiered latency simulation (co-lo to retail) |
| Analytics | `analytics.rs` | Market quality metrics, agent performance |
| Events | `events.rs` | Event types for the simulation event bus |
| Commands | `commands.rs` | Tauri command bindings for frontend |

### 8.2 Agent Types (13 Participant Types)

From `market_sim/types.rs::ParticipantType`:

| Agent | Behavior |
|-------|----------|
| MarketMaker | Two-sided quotes, inventory management, spread capture, skew by position |
| HFT | High-frequency, low-latency, co-located, exploits microstructure |
| StatArb | Statistical arbitrage, pairs/basket trading, mean-reversion signals |
| Momentum | Trend-following, breakout detection, momentum factor exposure |
| MeanReversion | Contrarian, buys dips / sells rallies, oscillator-based |
| NoiseTrader | Random trading, provides liquidity, models uninformed flow |
| InformedTrader | Trades on fundamental information, directional, size-aware |
| Institutional | Large block orders, VWAP/TWAP execution, minimizes market impact |
| RetailTrader | Small orders, market orders, price-insensitive timing |
| ToxicFlow | Adversarial agent, trades to exploit other participants |
| Spoofer | Places and cancels orders to manipulate prices (for detection training) |
| Arbitrageur | Cross-venue arbitrage, price convergence trading |
| SniperBot | Latency arbitrage, queue jumping, stale quote exploitation |

All agents implement the `TradingAgent` trait:

```rust
pub trait TradingAgent: Send {
    fn participant_type(&self) -> ParticipantType;
    fn on_tick(&mut self, view: &AgentView, rng: &mut Rng) -> Vec<AgentAction>;
    fn on_fill(&mut self, trade: &Trade);
    fn on_cancel(&mut self, order_id: OrderId);
    fn name(&self) -> &str;
}
```

### 8.3 Stochastic Price Generation

For standalone testing, prices are generated via deterministic random walk
(see `finscript/src/lib.rs::generate_ohlcv()`):

```
seed = hash(symbol)
base_price = 50 + (seed % 450)
volatility = 0.015 + (seed % 20) * 0.001

For each day:
  change = price * volatility * random(-1, 1)
  open = prev_close
  close = open + change
  high = max(open, close) + spread * random
  low = min(open, close) - spread * random
  volume = base_vol * (1 + |change|/price * 10) * random
```

Uses PCG-style LCG (Linear Congruential Generator) for reproducibility.

### 8.4 Latency Simulation

From `market_sim/types.rs::LatencyTier`:

| Tier | Base Latency | Jitter Range | Typical User |
|------|-------------|--------------|--------------|
| CoLocated | 1 us | 0.5 us | HFT firms, market makers |
| ProximityHosted | 50 us | 20 us | Prop trading firms |
| DirectConnect | 1 ms | 0.5 ms | Institutional, algo desks |
| Retail | 50 ms | 30 ms | Retail brokers, web platforms |

Latency affects order arrival time in the simulation, creating realistic microstructure dynamics.

---

## 9. Design Principles

### 9.1 Performance

- **Hot path**: Order insertion and matching must be O(log N) worst case.
- **Memory**: Pre-allocate vectors and hash maps. Avoid allocations in the matching loop.
- **Lock-free**: In multi-threaded designs, use lock-free structures or per-instrument sharding.
- **Batch processing**: Process market data updates in batches rather than one at a time.

### 9.2 Correctness

- **Determinism**: Given the same inputs and seed, simulation must produce identical results.
- **Consistency**: Order book invariants (bid < ask, quantities non-negative) must hold after every operation.
- **Atomicity**: A trade is either fully recorded (both sides) or not at all.
- **Audit trail**: Every state change produces an event for replay and debugging.

### 9.3 Extensibility

- **New order types**: Add variant to `OrderType` enum, add processing branch in matching engine.
- **New agent types**: Add variant to `ParticipantType`, implement `TradingAgent` trait.
- **New venues**: Implement `BrokerAdapter` trait with venue-specific API mapping.
- **New analytics**: Subscribe to event stream, compute metrics independently.
