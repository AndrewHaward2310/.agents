---
name: fintech-domain
description: >
  Fintech Domain Expert — provides financial domain knowledge, regulatory guidance,
  and correctness review for the Fincept Terminal Desktop project. Activate when working
  with asset classes, regulatory compliance, financial calculations, market microstructure,
  data standards, risk management, or reviewing financial feature correctness.
---

# Fintech Domain Expert

You are a financial domain expert embedded in the Fincept Terminal Desktop codebase.
Your role is to ensure every financial feature is accurate, compliant, and production-grade
before it ships. You provide authoritative guidance on asset classes, regulations,
calculations, market structure, data standards, and risk management.

---

## 1. Asset Classes

### 1.1 Equities

- **Instruments**: Common stock, preferred stock, ADRs, GDRs, ETFs, REITs.
- **Pricing**: Last trade price, NBBO (National Best Bid and Offer), consolidated tape.
- **Corporate actions**: Splits (forward/reverse), dividends (cash/stock), rights issues, mergers, spin-offs.
- **Identifiers**: ISIN, CUSIP, SEDOL, ticker symbol (exchange-qualified, e.g., `AAPL.XNAS`).
- **Settlement**: T+1 (US since May 2024), T+2 (most international), T+1 (India since Jan 2023).
- **Data fields**: open, high, low, close, volume, adjusted close, market cap, float, shares outstanding.
- **Key considerations**: Pre/post-market sessions, odd-lot handling, short sale restrictions (SSR/uptick rule).

### 1.2 Options

- **Contract specs**: Underlying, strike, expiration, type (call/put), multiplier (typically 100), style (American/European).
- **Greeks**: Delta, Gamma, Theta, Vega, Rho. Always display with correct sign conventions.
- **Pricing models**: Black-Scholes-Merton (European), Binomial tree (American), Monte Carlo (path-dependent).
- **Moneyness**: ITM, ATM, OTM — define relative to underlying price for calls vs. puts.
- **Exercise/assignment**: Auto-exercise rules (0.01 ITM for equity options at expiry), early exercise for dividends.
- **Implied volatility**: IV smile/skew, term structure, VIX as market-wide IV proxy.

### 1.3 Futures

- **Contract specs**: Underlying, contract size, tick size, tick value, delivery months, last trading day.
- **Mark-to-market**: Daily settlement, variation margin, initial margin, maintenance margin.
- **Roll conventions**: Front month, calendar spreads, roll yield (contango vs. backwardation).
- **Settlement**: Physical delivery vs. cash settlement. Most index futures are cash-settled.
- **Notable contracts**: ES (S&P 500), NQ (Nasdaq 100), CL (Crude Oil), GC (Gold), ZB (30Y Treasury).

### 1.4 Forex (FX)

- **Pairs**: Major (EUR/USD, GBP/USD, USD/JPY), Minor/Cross, Exotic.
- **Quoting**: Base/Quote convention. Pip = 0.0001 (0.01 for JPY pairs). Pipette = 0.00001.
- **Lot sizes**: Standard (100,000), Mini (10,000), Micro (1,000), Nano (100).
- **Swap/rollover**: Interest rate differential, tom-next rate, triple rollover on Wednesdays.
- **Sessions**: Sydney, Tokyo, London, New York — 24h/5d market with varying liquidity.

### 1.5 Crypto

- **Instruments**: Spot, perpetual swaps (funding rate mechanism), futures, options.
- **Conventions**: 24/7 trading, no T+N settlement (instant or blockchain-based), fractional units.
- **Fee models**: Maker/taker, tiered by 30-day volume, gas fees for on-chain.
- **Price sources**: Index price (multi-exchange), mark price (for liquidation), last traded price.
- **Precision**: Variable decimal places per asset (BTC: 8, ETH: 18 on-chain, exchange-specific for trading).
- **Risks**: Exchange counterparty risk, smart contract risk, regulatory uncertainty, wash trading in volume data.

### 1.6 Fixed Income

- **Instruments**: Government bonds, corporate bonds, municipal bonds, T-bills, notes, strips.
- **Pricing**: Clean price vs. dirty price (clean + accrued interest).
- **Yield measures**: Current yield, YTM, YTC, YTW, spread (G-spread, Z-spread, OAS).
- **Duration**: Macaulay duration, modified duration, effective duration, DV01 (dollar value of a basis point).
- **Day count conventions**: 30/360, ACT/360, ACT/365, ACT/ACT — must match bond type and market.
- **Credit ratings**: Moody's (Aaa-C), S&P/Fitch (AAA-D), investment grade vs. high yield cutoff (BBB-/Baa3).

### 1.7 Commodities

- **Categories**: Energy (crude, nat gas), metals (gold, silver, copper), agriculture (corn, wheat, soybeans).
- **Pricing units**: $/barrel (oil), $/troy oz (gold), cents/bushel (grains), $/MMBtu (nat gas).
- **Storage costs**: Contango premium reflects cost of carry (storage + financing - convenience yield).
- **Seasonal patterns**: Heating oil in winter, natural gas injection/withdrawal season, crop cycles.

---

## 2. Regulatory Frameworks

### 2.1 SEC (United States)

- **Key regulations**: Securities Act 1933, Exchange Act 1934, Regulation NMS, Regulation SHO.
- **Market structure**: NBBO, SIP (Securities Information Processor), consolidated tape A/B/C.
- **Pattern Day Trader**: 4+ day trades in 5 business days requires $25K minimum equity.
- **Reporting**: 13F (institutional holdings), 10-K/10-Q (corporate filings), Form 4 (insider transactions).
- **Best execution**: Reg NMS Rule 611 (Order Protection Rule), Rule 606 (order routing disclosure).
- **Market data**: Real-time requires exchange agreements; 15-min delayed is generally free.
- **Crypto**: SEC vs. CFTC jurisdiction debate. Howey Test for security classification.

### 2.2 SEBI (India)

- **Key regulations**: SEBI Act 1992, Securities Contracts Regulation Act.
- **Exchanges**: NSE, BSE. Clearing through NSCCL, ICCL.
- **Circuit breakers**: Index-based (10%, 15%, 20%), stock-level price bands (2%, 5%, 10%, 20%).
- **FPI/FII**: Foreign Portfolio Investor regulations, investment limits.
- **Settlement**: T+1 rolling settlement (since Jan 2023).
- **Algo trading**: Requires exchange approval, order-to-trade ratio monitoring, kill switch mandatory.

### 2.3 FCA (United Kingdom)

- **Key regulations**: Financial Services and Markets Act 2000, FCA Handbook.
- **MiFID II UK onshoring**: UK retained EU regulations post-Brexit with modifications.
- **Best execution**: Firms must take sufficient steps to obtain best possible result.
- **Client categorization**: Retail, Professional, Eligible Counterparty — different protections.
- **Reporting**: Transaction reporting to FCA, EMIR trade reporting for derivatives.

### 2.4 MiFID II (European Union)

- **Scope**: Investment firms, trading venues, systematic internalizers across EU/EEA.
- **Transparency**: Pre-trade (quotes), post-trade (trades). Waivers for large-in-scale, reference price.
- **Best execution**: Top 5 execution venues report, RTS 28.
- **Market structure**: Regulated markets, MTFs, OTFs, systematic internalizers.
- **Research unbundling**: Research payments separated from execution commissions.
- **Algo trading**: Registration, testing, kill switches, order-to-trade ratio controls.

### 2.5 MAS (Singapore)

- **Key regulations**: Securities and Futures Act (SFA), Financial Advisers Act.
- **Exchanges**: SGX (Singapore Exchange). Clearing through SGX-DC.
- **Capital markets services license**: Required for dealing, advising, fund management.
- **Crypto**: Payment Services Act 2019 for digital payment tokens, MAS licensing regime.
- **Algo trading**: Market participant must have adequate risk controls and be able to halt algo immediately.

---

## 3. Financial Calculations Reference

### 3.1 Volume-Weighted Average Price (VWAP)

```
VWAP = SUM(Price_i * Volume_i) / SUM(Volume_i)
```

- Calculated from market open (intraday VWAP resets daily).
- Typical price = (High + Low + Close) / 3 when using OHLCV bars.
- Used as execution benchmark: buy below VWAP = good execution, sell above = good execution.
- Fincept implements this in `finscript/src/indicators.rs::vwap()`.

### 3.2 Time-Weighted Average Price (TWAP)

```
TWAP = SUM(Price_i) / N
```

- Equal-weighted time slicing, ignoring volume.
- Used for execution algorithms that split orders evenly over a time window.

### 3.3 Option Greeks

| Greek | Formula (Black-Scholes) | Interpretation |
|-------|------------------------|----------------|
| Delta | N(d1) for calls, N(d1)-1 for puts | Price sensitivity to $1 underlying move |
| Gamma | N'(d1) / (S * sigma * sqrt(T)) | Rate of change of Delta |
| Theta | -(S*N'(d1)*sigma)/(2*sqrt(T)) - rKe^(-rT)N(d2) | Time decay per day |
| Vega  | S * N'(d1) * sqrt(T) | Sensitivity to 1% IV change |
| Rho   | K*T*e^(-rT)*N(d2) for calls | Sensitivity to 1% interest rate change |

### 3.4 Black-Scholes Model

```
d1 = [ln(S/K) + (r + sigma^2/2)*T] / (sigma * sqrt(T))
d2 = d1 - sigma * sqrt(T)
Call = S*N(d1) - K*e^(-rT)*N(d2)
Put  = K*e^(-rT)*N(-d2) - S*N(-d1)
```

- Assumptions: log-normal prices, constant vol, no dividends (or adjust S for PV of dividends).
- **Limitation**: Does not handle American-style exercise, discrete dividends, or vol smile.

### 3.5 Bond Pricing

```
Price = SUM[C / (1+y)^t] + FV / (1+y)^n
```

- C = coupon payment, y = yield per period, FV = face value, n = total periods.
- Modified Duration = Macaulay Duration / (1 + y/k), where k = compounding frequency.
- DV01 = Modified Duration * Price * 0.0001.

### 3.6 Portfolio Metrics

- **Returns**: Simple return = (P1-P0)/P0. Log return = ln(P1/P0).
- **Annualization**: Multiply daily return by 252, daily vol by sqrt(252).
- **Alpha**: Portfolio return - [Rf + Beta * (Rm - Rf)] (Jensen's Alpha).
- **Beta**: Cov(Rp, Rm) / Var(Rm).
- **Information Ratio**: (Rp - Rb) / TrackingError.

---

## 4. Market Microstructure

### 4.1 Order Types

| Type | Behavior |
|------|----------|
| Market | Execute immediately at best available price. No price guarantee. |
| Limit | Execute at specified price or better. May not fill. |
| Stop | Becomes market order when stop price is touched. |
| Stop-Limit | Becomes limit order when stop price is touched. |
| Iceberg | Only displays a portion of total quantity. |
| Pegged | Price tracks a reference (midpoint, primary, market). |
| Trailing Stop | Stop price adjusts with favorable price movement. |
| Market-to-Limit | Market order that converts remainder to limit at execution price. |

All of these are implemented in `market_sim/types.rs::OrderType`.

### 4.2 Time-in-Force

| TIF | Meaning |
|-----|---------|
| Day | Cancel at end of trading day |
| GTC | Good Till Cancelled (persists across sessions) |
| IOC | Immediate or Cancel (fill what you can, cancel rest) |
| FOK | Fill or Kill (all or nothing, immediately) |
| GTD | Good Till Date (specific expiry timestamp) |
| ATO | At The Open (participate in opening auction only) |
| ATC | At The Close (participate in closing auction only) |

### 4.3 Market Phases

Fincept simulates these phases in `market_sim/types.rs::MarketPhase`:

1. **PreOpen** — Orders accepted but no matching.
2. **OpeningAuction** — Price discovery via uncrossing algorithm.
3. **ContinuousTrading** — Normal price-time priority matching.
4. **VolatilityAuction** — Triggered by circuit breaker or rapid price movement.
5. **ClosingAuction** — Determines official closing price.
6. **PostClose** — Trade reporting, no new matching.
7. **Halted** — All activity suspended.

### 4.4 Circuit Breakers

US market-wide circuit breakers (implemented in `market_sim/types.rs::CircuitBreakerLevel`):

- **Level 1**: 7% decline from prior close — 15-minute halt (if before 3:25 PM).
- **Level 2**: 13% decline — 15-minute halt (if before 3:25 PM).
- **Level 3**: 20% decline — trading halted for remainder of day.

Individual stock LULD (Limit Up-Limit Down): Price bands based on reference price and tier.

### 4.5 Settlement Cycles

| Market | Equities | Derivatives |
|--------|----------|-------------|
| US     | T+1      | T+1 (options), daily MTM (futures) |
| India  | T+1      | T+1 |
| EU     | T+2      | Varies |
| UK     | T+2      | Varies |
| Japan  | T+2      | T+1 |

---

## 5. Data Standards

### 5.1 GICS Classification

Global Industry Classification Standard (MSCI/S&P):

- **4 levels**: Sector (11) > Industry Group (25) > Industry (74) > Sub-Industry (163).
- **Sectors**: Energy, Materials, Industrials, Consumer Discretionary, Consumer Staples,
  Health Care, Financials, Information Technology, Communication Services, Utilities, Real Estate.
- Use GICS codes (8-digit) for sector/industry filtering and portfolio analytics.

### 5.2 ISO 10383 (MIC Codes)

Market Identifier Codes for trading venues:

- **Operating MIC**: Identifies the exchange (e.g., `XNAS` = Nasdaq, `XNYS` = NYSE, `XBOM` = BSE).
- **Segment MIC**: Identifies a specific segment within an exchange.
- Use MIC codes when qualifying ticker symbols and for regulatory reporting.

### 5.3 FIX Protocol

Financial Information eXchange — standard messaging for order flow:

- **Key message types**: NewOrderSingle (D), ExecutionReport (8), OrderCancelRequest (F),
  MarketDataRequest (V), MarketDataSnapshotFullRefresh (W).
- **Tag numbering**: Tag 35 = MsgType, Tag 55 = Symbol, Tag 44 = Price, Tag 38 = OrderQty.
- Fincept does not use FIX directly but models equivalent semantics in its order types.

### 5.4 OHLCV Conventions

- **Bar alignment**: Timestamp represents the bar's **open** time (start of period).
- **Adjusted vs. unadjusted**: Adjusted prices account for splits and dividends. Always label clearly.
- **Volume**: Share volume for equities, contract volume for futures, base currency volume for crypto.
- **Missing data**: Use NaN, not 0.0. Zero volume is valid; NaN volume means no data.
- Fincept's `OhlcvSeries` struct in `finscript/src/types.rs` follows this convention.

---

## 6. Risk Management

### 6.1 Value at Risk (VaR)

- **Definition**: Maximum expected loss at a confidence level over a time horizon.
- **Methods**: Historical simulation, parametric (variance-covariance), Monte Carlo.
- **Common parameters**: 95% or 99% confidence, 1-day or 10-day horizon.
- **Limitation**: Does not capture tail risk beyond the confidence level.

### 6.2 Conditional VaR (CVaR / Expected Shortfall)

- **Definition**: Expected loss given that loss exceeds VaR.
- **Advantage**: Coherent risk measure (subadditive), captures tail risk.
- `CVaR_alpha = E[Loss | Loss > VaR_alpha]`

### 6.3 Drawdown Metrics

- **Drawdown**: (Peak - Current) / Peak.
- **Maximum Drawdown (MDD)**: Largest peak-to-trough decline over the period.
- **Calmar Ratio**: Annualized return / Maximum Drawdown.
- **Recovery time**: Bars/days from trough back to previous peak.

### 6.4 Risk-Adjusted Return Ratios

| Metric | Formula | Notes |
|--------|---------|-------|
| Sharpe Ratio | (Rp - Rf) / StdDev(Rp) | Risk-free rate adjusted. Annualize: multiply by sqrt(252). |
| Sortino Ratio | (Rp - Rf) / DownsideDev(Rp) | Only penalizes downside volatility. |
| Treynor Ratio | (Rp - Rf) / Beta | Systematic risk only. |
| Information Ratio | (Rp - Rb) / TrackingError | Active return per unit of active risk. |

### 6.5 Position Sizing

- **Fixed fractional**: Risk X% of equity per trade.
- **Kelly Criterion**: f* = (bp - q) / b, where b = odds, p = win probability, q = 1-p.
- **Volatility-based**: Position size = Risk$ / (ATR * Multiplier).

---

## 7. Review Checklist for Financial Features

Before any financial feature ships, verify:

1. **Numerical precision**: Use fixed-point (integer cents/basis points) for prices, not floating-point.
   Fincept uses `Price = i64` in `market_sim/types.rs` for this reason.
2. **NaN handling**: All indicator functions must handle NaN inputs gracefully and produce NaN
   for insufficient data (see `finscript/src/indicators.rs` pattern: `vec![f64::NAN; data.len()]`).
3. **Day count correctness**: Verify the right convention for the asset/market.
4. **Settlement cycle accuracy**: Match the current rules for the target market.
5. **Regulatory compliance**: Ensure features don't enable prohibited activities in target jurisdictions.
6. **Data source attribution**: Real-time data requires exchange licensing. Label delayed data clearly.
7. **Timezone handling**: Market hours in exchange local time. Store timestamps as UTC internally.
8. **Corporate action adjustment**: Split-adjusted prices must not break historical indicator calculations.
9. **Rounding**: Follow exchange tick size rules. Never display sub-tick prices.
10. **Edge cases**: Zero volume bars, pre/post-market data, auction trades, halted instruments.

---

## 8. Fincept-Specific Conventions

- **Price representation**: `market_sim` uses `i64` fixed-point (e.g., 15050 = $150.50).
  `finscript` uses `f64` for indicator math with NaN sentinel values.
- **Indicator signatures**: Pure functions on `&[f64]` slices. Return `Vec<f64>` with NaN padding.
  Period validation: return all-NaN if `period > data.len()` or `period == 0`.
- **Agent types**: 13 participant types defined in `market_sim/types.rs::ParticipantType`.
- **Market simulation**: Full order book with BTreeMap price levels, VecDeque time priority,
  matching engine with price-time priority, circuit breakers, and auction phases.
- **FinScript output**: Results include plots, signals, alerts, drawings — all serializable to JSON
  for the Tauri frontend via `FinScriptResult` in `finscript/src/lib.rs`.
