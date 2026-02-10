---
name: dsl-engineering
description: >
  DSL Engineering — specializes in domain-specific language design for financial scripting
  within the Fincept Terminal Desktop project. Activate when working on FinScript development,
  language design, lexer/parser/interpreter implementation, financial indicator functions,
  PineScript compatibility, trading strategy DSL, visualization commands, or any work in
  the finscript/ crate.
---

# DSL Engineering

You are a domain-specific language engineer embedded in the Fincept Terminal Desktop
codebase. Your role is to guide the design and implementation of FinScript — the custom
financial scripting language written in Rust, located in `src-tauri/finscript/`.

---

## 1. FinScript Overview

### 1.1 Architecture

FinScript is a custom DSL for financial scripting, written entirely in Rust.
It follows a classic interpreter pipeline:

```
Source Code → Lexer → Tokens → Parser → AST → Interpreter → Results
                                                    ↓
                                              FinScriptResult {
                                                plots, signals, alerts,
                                                drawings, output, errors
                                              }
```

### 1.2 Source Files

| File | Purpose | Approximate Role |
|------|---------|------------------|
| `ast.rs` (225 lines) | Abstract Syntax Tree node definitions | Expr and Statement enums |
| `lexer.rs` | Tokenizer / lexical analysis | Character-by-character scanning |
| `parser.rs` | Recursive-descent parser | Token stream → AST |
| `interpreter.rs` | Tree-walking interpreter | AST evaluation with scope stack |
| `indicators.rs` (826 lines) | Technical indicator functions | Pure functions on `&[f64]` slices |
| `types.rs` (173 lines) | Value types and data structures | Value enum, OhlcvSeries, ColorValue |
| `lib.rs` (186 lines) | Public API and data generation | `execute()` entry point, synthetic OHLCV |
| `main.rs` | CLI entry point | REPL and file execution |

### 1.3 Entry Point

The public API is `finscript::execute(code: &str) -> FinScriptResult`:

```rust
pub fn execute(code: &str) -> FinScriptResult {
    // 1. Tokenize
    let tokens = lexer::tokenize(code)?;
    // 2. Parse
    let program = parser::parse(tokens)?;
    // 3. Collect referenced symbols & generate synthetic data
    let symbols = interpreter::collect_symbols(&program);
    let symbol_data = generate_symbol_data(&symbols);
    // 4. Interpret
    let mut interp = interpreter::Interpreter::new(symbol_data);
    let result = interp.execute(&program);
    // 5. Package results
    FinScriptResult { success, output, signals, plots, errors, alerts, drawings, execution_time_ms }
}
```

---

## 2. Language Design Principles

### 2.1 Type System

FinScript uses a dynamically-typed value system defined in `types.rs::Value`:

```rust
enum Value {
    Number(f64),          // All numbers are f64
    Series(SeriesData),   // Time series: Vec<f64> + Vec<i64> timestamps
    String(String),       // UTF-8 strings
    Bool(bool),           // Boolean
    Array(Vec<Value>),    // Heterogeneous array
    Map(HashMap<String, Value>),  // Key-value map
    Color(ColorValue),    // RGBA color (r, g, b, a as u8)
    Struct { type_name, fields },  // User-defined struct
    Drawing(DrawingValue), // Chart drawing (line, label, box)
    Table(TableValue),    // Data table with cells
    Na,                   // Missing value (PineScript na, equivalent to NaN)
    Void,                 // No value (function with no return)
}
```

**Type coercion rules:**
- `Number` + `Number` → arithmetic
- `Number` + `String` → string concatenation (number converted to string)
- `Bool` → `Number`: `true = 1.0`, `false = 0.0`
- `Na` in arithmetic → `Na` (NaN propagation)
- `Series` + `Number` → element-wise operation on the series

**Truthiness:**
- `false`, `0.0`, `NaN`, empty string, empty array, empty map, `Na`, `Void` → falsy
- Everything else → truthy

### 2.2 Operator Precedence

From lowest to highest (as implemented in the parser):

| Level | Operators | Associativity |
|-------|-----------|---------------|
| 1 | `or` | Left |
| 2 | `and` | Left |
| 3 | `==`, `!=` | Left |
| 4 | `<`, `>`, `<=`, `>=` | Left |
| 5 | `+`, `-` | Left |
| 6 | `*`, `/`, `%` | Left |
| 7 | `not`, `-` (unary) | Right (prefix) |
| 8 | `()`, `[]`, `.` | Left (postfix) |

The ternary operator `condition ? then : else` binds loosely, wrapping an entire expression.

### 2.3 Scoping Rules

FinScript uses lexical scoping with a scope stack:

```rust
struct Interpreter {
    env: Vec<HashMap<String, Value>>,  // scope stack, index 0 = global
    // ...
}

fn push_scope(&mut self) { self.env.push(HashMap::new()); }
fn pop_scope(&mut self) { self.env.pop(); }

fn set_variable(&mut self, name: &str, value: Value) {
    // Set in the innermost scope
    self.env.last_mut().unwrap().insert(name.to_string(), value);
}

fn get_variable(&self, name: &str) -> Option<&Value> {
    // Search from innermost to outermost scope
    for scope in self.env.iter().rev() {
        if let Some(val) = scope.get(name) {
            return Some(val);
        }
    }
    None
}
```

**Scope creation points:**
- Function call body
- For loop body
- While loop body
- If/else blocks (each branch gets its own scope)

**Variable mutation:** Assignment in the current scope creates or overwrites the variable
in that scope. Variables in outer scopes are not modified by default (no explicit `nonlocal`
or `global` keyword — this is a known limitation).

---

## 3. Lexer Patterns

### 3.1 Token Types

Defined in `lexer.rs::Token`:

```rust
enum Token {
    // Literals
    Number(f64),           // 42, 3.14, 0.5
    StringLit(String),     // "hello", 'world'
    Ident(String),         // variable_name, functionName

    // Keywords (34 total)
    If, Else, For, While, In, Fn, Return, Break, Continue,
    Buy, Sell, Plot, PlotCandlestick, PlotLine, PlotHistogram,
    PlotShape, Bgcolor, Hline, And, Or, Not, True, False, Na,
    Switch, Strategy, Input, Struct, Import, Export, Alert,
    Print, Request, Color,

    // Operators
    Plus, Minus, Star, Slash, Percent,
    Gt, Lt, Gte, Lte, EqEq, Neq,
    PlusAssign, MinusAssign, StarAssign, SlashAssign,

    // Delimiters
    Assign, LParen, RParen, LBrace, RBrace, LBracket, RBracket,
    Comma, Colon, Dot, Arrow, DotDot, Question,

    // Structure
    Newline, Comment(String), EOF,
}
```

### 3.2 Character-by-Character Tokenization

The lexer scans source code character by character with position tracking:

```rust
struct TokenWithSpan {
    token: Token,
    line: usize,
    col: usize,
}

fn tokenize(input: &str) -> Result<Vec<TokenWithSpan>, String> {
    // Track line/col for error reporting
    // Handle:
    //   - Single-char operators: +, -, *, etc.
    //   - Multi-char operators: ==, !=, >=, <=, +=, -=, .., =>
    //   - String literals: "..." and '...' with escape sequences
    //   - Numbers: integer and floating point
    //   - Identifiers and keyword detection
    //   - Comments: // line comments
    //   - Newlines: significant for statement termination
}
```

### 3.3 Keyword Detection

After scanning an identifier, check against the keyword table:

```rust
fn classify_ident(word: &str) -> Token {
    match word {
        "if" => Token::If,
        "else" => Token::Else,
        "for" => Token::For,
        "while" => Token::While,
        "in" => Token::In,
        "fn" => Token::Fn,
        "return" => Token::Return,
        "break" => Token::Break,
        "continue" => Token::Continue,
        "buy" => Token::Buy,
        "sell" => Token::Sell,
        "true" => Token::True,
        "false" => Token::False,
        "na" => Token::Na,
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "plot" => Token::Plot,
        "plot_candlestick" => Token::PlotCandlestick,
        // ... remaining keywords
        _ => Token::Ident(word.to_string()),
    }
}
```

**Design decisions:**
- Keywords are case-sensitive (like PineScript).
- `na` is a keyword (not an identifier), producing `Token::Na`.
- `buy`/`sell` are statement-level keywords (like `print`), not functions.
- `plot`, `plot_line`, `plot_histogram`, `plot_shape` are separate keywords, not overloaded.
- Comments (`//`) are preserved as `Token::Comment(String)` for potential doc generation.

---

## 4. Parser Patterns

### 4.1 Recursive-Descent Structure

The parser is a hand-written recursive-descent parser in `parser.rs`:

```rust
struct Parser {
    tokens: Vec<TokenWithSpan>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Token { ... }
    fn advance(&mut self) -> &Token { ... }
    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> { ... }
    fn skip_newlines(&mut self) { ... }

    // Entry point
    fn parse_program(&mut self) -> Result<Program, ParseError> {
        let mut stmts = Vec::new();
        while !self.at_end() {
            self.skip_newlines();
            if !self.at_end() {
                stmts.push(self.parse_statement()?);
            }
        }
        Ok(stmts)
    }

    // Statement parsing (dispatches by first token)
    fn parse_statement(&mut self) -> Result<Statement, ParseError> {
        match self.peek() {
            Token::If => self.parse_if(),
            Token::For => self.parse_for(),
            Token::While => self.parse_while(),
            Token::Fn => self.parse_fn_def(),
            Token::Return => self.parse_return(),
            Token::Buy => self.parse_buy(),
            Token::Sell => self.parse_sell(),
            Token::Plot => self.parse_plot(),
            Token::Strategy => self.parse_strategy_command(),
            Token::Struct => self.parse_struct_def(),
            Token::Import => self.parse_import(),
            Token::Export => self.parse_export(),
            Token::Input => self.parse_input_decl(),
            Token::Alert => self.parse_alert(),
            Token::Print => self.parse_print(),
            Token::Switch => self.parse_switch(),
            // ... more statement types
            Token::Ident(_) => self.parse_assignment_or_expr(),
            _ => self.parse_expr_statement(),
        }
    }
}
```

### 4.2 Operator Precedence Climbing

Expression parsing uses precedence climbing (a variant of Pratt parsing):

```rust
fn parse_expression(&mut self) -> Result<Expr, ParseError> {
    self.parse_ternary()
}

fn parse_ternary(&mut self) -> Result<Expr, ParseError> {
    let expr = self.parse_or()?;
    if matches!(self.peek(), Token::Question) {
        self.advance();
        let then_expr = self.parse_expression()?;
        self.expect(&Token::Colon)?;
        let else_expr = self.parse_expression()?;
        Ok(Expr::Ternary { condition: Box::new(expr), then_expr: Box::new(then_expr), else_expr: Box::new(else_expr) })
    } else {
        Ok(expr)
    }
}

fn parse_or(&mut self) -> Result<Expr, ParseError> {
    let mut left = self.parse_and()?;
    while matches!(self.peek(), Token::Or) {
        self.advance();
        let right = self.parse_and()?;
        left = Expr::BinaryOp { left: Box::new(left), op: BinOp::Or, right: Box::new(right) };
    }
    Ok(left)
}

// ... parse_and, parse_equality, parse_comparison, parse_addition,
//     parse_multiplication, parse_unary, parse_postfix, parse_primary
```

### 4.3 Postfix Chains

Postfix operations (function calls, indexing, method calls) chain left-to-right:

```rust
fn parse_postfix(&mut self, mut expr: Expr) -> Result<Expr, ParseError> {
    loop {
        match self.peek() {
            Token::LParen => {
                // Function call: expr(args...)
                self.advance();
                let args = self.parse_arg_list()?;
                self.expect(&Token::RParen)?;
                expr = Expr::FunctionCall { name: extract_name(expr), args };
            }
            Token::LBracket => {
                // Index access: expr[index]
                self.advance();
                let index = self.parse_expression()?;
                self.expect(&Token::RBracket)?;
                expr = Expr::IndexAccess { object: Box::new(expr), index: Box::new(index) };
            }
            Token::Dot => {
                // Method call or field access: expr.method(args...)
                self.advance();
                let method = self.expect_ident()?;
                if matches!(self.peek(), Token::LParen) {
                    self.advance();
                    let args = self.parse_arg_list()?;
                    self.expect(&Token::RParen)?;
                    expr = Expr::MethodCall { object: Box::new(expr), method, args };
                } else {
                    // Field access desugars to method call with no args
                    expr = Expr::MethodCall { object: Box::new(expr), method, args: vec![] };
                }
            }
            _ => break,
        }
    }
    Ok(expr)
}
```

### 4.4 AST Node Definitions

From `ast.rs`:

**Expressions (`Expr`):**

| Variant | Syntax | Example |
|---------|--------|---------|
| `Number(f64)` | Numeric literal | `42`, `3.14` |
| `Bool(bool)` | Boolean literal | `true`, `false` |
| `StringLiteral(String)` | String literal | `"hello"` |
| `Symbol(String)` | Ticker symbol | Referenced via `request` |
| `Variable(String)` | Variable reference | `my_var` |
| `Na` | Missing value | `na` |
| `BinaryOp { left, op, right }` | Binary operation | `a + b`, `x > y` |
| `UnaryOp { op, operand }` | Unary operation | `not x`, `-y` |
| `FunctionCall { name, args }` | Function call | `sma(close, 14)` |
| `MethodCall { object, method, args }` | Method call | `arr.push(42)` |
| `ArrayLiteral(Vec<Expr>)` | Array literal | `[1, 2, 3]` |
| `IndexAccess { object, index }` | Index/history access | `close[1]` |
| `Range { start, end }` | Range | `0..10` |
| `Ternary { condition, then, else }` | Ternary | `x > 0 ? "up" : "down"` |
| `MapLiteral(Vec<(String, Expr)>)` | Map literal | `{"key": value}` |
| `StructLiteral { type_name, fields }` | Struct instantiation | `Point { x: 1, y: 2 }` |

**Statements (`Statement`):**

| Variant | Syntax | Notes |
|---------|--------|-------|
| `Assignment { name, value }` | `x = expr` | Creates/updates variable |
| `CompoundAssign { name, op, value }` | `x += expr` | `+=`, `-=` |
| `IndexAssign { object, index, value }` | `arr[i] = expr` | Array/map mutation |
| `IfBlock { condition, body, else_if, else }` | `if ... else if ... else` | Full if/else chains |
| `ForLoop { var, iterable, body }` | `for x in expr` | Iterates arrays, ranges |
| `WhileLoop { condition, body }` | `while condition` | Max 100,000 iterations |
| `FnDef { name, params, body }` | `fn name(params)` | User-defined functions |
| `Return { value }` | `return expr` | Function return |
| `Break` / `Continue` | Loop control | Standard semantics |
| `Buy { message }` / `Sell { message }` | Signal generation | Produces Signal records |
| `Plot { expr, label }` | Basic plot | Adds PlotData to results |
| `PlotCandlestick { symbol, title }` | OHLCV chart | Candlestick visualization |
| `PlotLine { value, label, color }` | Line overlay | Indicator line on chart |
| `PlotHistogram { value, label, colors }` | Histogram | Volume, MACD histogram |
| `PlotShape { condition, shape, location, ... }` | Shape markers | Buy/sell arrows, circles |
| `Bgcolor { color, condition }` | Background color | Conditional highlighting |
| `Hline { value, label, color }` | Horizontal line | Support/resistance levels |
| `StrategyEntry { id, direction, qty, ... }` | Strategy entry | `strategy.entry(...)` |
| `StrategyExit { id, from_entry, ... }` | Strategy exit | `strategy.exit(...)` |
| `StrategyClose { id }` | Strategy close | `strategy.close(...)` |
| `InputDecl { name, type, default, title }` | User input | Configurable parameters |
| `StructDef { name, fields }` | Struct definition | Custom types |
| `AlertStatement { message, type }` | Alert | Price/condition alerts |
| `ImportStatement { module, alias }` | Import | Module system (future) |
| `ExportStatement { name }` | Export | Mark as public |
| `PrintStatement { args }` | Print | Debug output |
| `SwitchBlock { expr, cases, default }` | Switch | Multi-way branch |

---

## 5. Interpreter Patterns

### 5.1 Scope Stack

The interpreter maintains a `Vec<HashMap<String, Value>>` as a scope stack:

```
Global scope (index 0):
  ├── Built-in functions (sma, ema, rsi, ...)
  ├── Built-in variables (close, open, high, low, volume)
  └── User global variables

Function call scope (pushed/popped per call):
  ├── Function parameters
  └── Local variables

Loop/block scope (pushed/popped per block):
  └── Block-local variables
```

### 5.2 Variable Mutation

Assignment always writes to the **current** (innermost) scope:

```rust
fn execute_assignment(&mut self, name: &str, value: Value) {
    // Check if variable exists in any scope (for compound assignment)
    // Then set in the current scope
    self.env.last_mut().unwrap().insert(name.to_string(), value);
}
```

**Known limitation:** Cannot mutate a variable in an outer scope from an inner scope.
A `nonlocal` keyword or explicit scoping mechanism would fix this.

### 5.3 Function Calls

```rust
fn call_function(&mut self, name: &str, args: Vec<Value>) -> Value {
    // 1. Check built-in functions first
    if let Some(result) = self.call_builtin(name, &args) {
        return result;
    }

    // 2. Check user-defined functions
    if let Some(func) = self.user_functions.get(name).cloned() {
        self.push_scope();
        // Bind parameters
        for (param, arg) in func.params.iter().zip(args) {
            self.set_variable(param, arg);
        }
        // Execute body
        let result = self.execute_block(&func.body);
        self.pop_scope();
        return match result {
            ControlFlow::Return(val) => val,
            _ => Value::Void,
        };
    }

    // 3. Error: unknown function
    self.errors.push(format!("Unknown function: {}", name));
    Value::Na
}
```

### 5.4 Series Operations

Series (time series) are first-class values. Operations on series are element-wise:

```rust
// Series + Number → Series (broadcast)
// Series + Series → Series (element-wise, aligned by index)
// Series[n] → Number (historical lookback: close[1] = previous close)
```

Built-in variables `close`, `open`, `high`, `low`, `volume` resolve to Series
from the loaded symbol data (`OhlcvSeries` from `types.rs`).

### 5.5 Strategy State Machine

The interpreter tracks strategy state for backtesting:

```rust
struct Interpreter {
    strategy_position: i64,      // +ve long, -ve short, 0 flat
    strategy_equity: f64,        // Starting at 100,000
    strategy_entry_price: f64,   // Price of current position entry
    // ...
}
```

`strategy.entry("id", "long")` opens a position. `strategy.exit(...)` with stops and limits
manages risk. `strategy.close("id")` flattens the position.

---

## 6. Financial Indicator Implementation

### 6.1 Implementation Pattern

All indicators in `indicators.rs` follow a consistent pattern:

```rust
pub fn indicator_name(data: &[f64], period: usize) -> Vec<f64> {
    // 1. Validate inputs
    if data.is_empty() || period == 0 || period > data.len() {
        return vec![f64::NAN; data.len()];
    }

    // 2. Initialize result with NaN
    let mut result = vec![f64::NAN; data.len()];

    // 3. Compute indicator values starting at first valid index
    // First valid index is typically (period - 1)

    // 4. Return result (same length as input, NaN-padded at start)
    result
}
```

### 6.2 Implemented Indicators (25+)

| Category | Indicators |
|----------|-----------|
| Moving Averages | SMA, EMA, WMA, RMA, HMA |
| Momentum | RSI, MACD (line + signal + histogram), Stochastic (%K, %D), ROC, Momentum, CCI, Williams %R, MFI |
| Volatility | ATR, Bollinger Bands (upper, middle, lower), True Range, Standard Deviation, SuperTrend |
| Trend | ADX, Parabolic SAR, Linear Regression |
| Volume | OBV, VWAP |
| Statistical | Highest, Lowest, Change, Cumulative Sum, Percent Rank |
| Pattern | Pivot High, Pivot Low |

### 6.3 NaN Handling Rules

- **Input validation**: If `period > data.len()` or `period == 0`, return all NaN.
- **Warm-up period**: First `period - 1` values are NaN (insufficient data).
- **NaN in data**: Most indicators propagate NaN. Some (like `cum`) skip NaN values.
- **Multi-input indicators**: Use `min()` of input lengths to avoid index out of bounds.
  Example: `fn vwap(high: &[f64], low: &[f64], close: &[f64], volume: &[f64])` uses
  `let len = close.len().min(volume.len()).min(high.len()).min(low.len());`

### 6.4 Period Validation

```rust
// Standard guard clause — every indicator must have this
if data.is_empty() || period == 0 || period > data.len() {
    return vec![f64::NAN; data.len()];
}

// For multi-period indicators (e.g., ADX needs period * 2)
if len < period * 2 || period == 0 {
    return vec![f64::NAN; len];
}
```

---

## 7. PineScript Compatibility

### 7.1 Features to Match

FinScript aims for directional compatibility with TradingView's PineScript v5:

**Already implemented:**
- Basic types: int/float (as f64), string, bool, na, color
- Operators: arithmetic, comparison, logical, ternary
- Control flow: if/else, for/while, break/continue, switch
- Functions: user-defined with `fn`, built-in indicators
- Series: historical referencing with `close[1]` syntax
- Plotting: plot, plotline, plothistogram, plotshape, hline, bgcolor
- Strategy: strategy.entry, strategy.exit, strategy.close
- Input: input declarations for configurable parameters
- Alerts: alert statement

**Priority features to add:**
- `var` keyword (initialize once, persist across bars)
- `varip` keyword (persist even on real-time bar updates)
- Arrays: `array.new_float()`, `array.push()`, `array.pop()`, etc.
- Matrix operations
- Pine Tables: `table.new()`, `table.cell()`
- `request.security()` for multi-timeframe data
- `label.new()`, `line.new()`, `box.new()` drawing objects
- Type annotations: `float myVar = 0.0`

### 7.2 Features to Skip

- **PineScript v1-v3 syntax**: Only target v5 semantics.
- **study() / indicator()**: Use a simpler script header mechanism.
- **Pine-specific quirks**: Like implicit series conversion of every variable.
- **Paid features**: TradingView premium-only features (alerts beyond basic).
- **Compilation to native**: FinScript is interpreted, not compiled.

### 7.3 Migration Path

For users migrating PineScript to FinScript:

1. Rename `study()` / `indicator()` → Remove (FinScript doesn't require it).
2. Replace `//@version=5` → Remove.
3. `ta.sma()` → `sma()` (drop the `ta.` prefix for built-in indicators).
4. `input.int()` → `input("name", "int", default)`.
5. `strategy()` → Direct `strategy.entry()` / `strategy.exit()` calls.
6. `color.new(color.red, 80)` → `color("red")` (simplified color model).
7. Multi-timeframe: `request.security()` → `request("AAPL", "1D")` (future).

---

## 8. Known Limitations and Fix Roadmap

### 8.1 Module System

**Current state:** `ImportStatement` and `ExportStatement` are parsed but not fully implemented
in the interpreter. Imports don't actually load external files.

**Fix plan:**
1. Define a module search path (relative to script, then a stdlib directory).
2. Parse and cache imported modules (avoid circular imports with a visited set).
3. Bind exported names into the importing scope under the alias.
4. Standard library modules: `math`, `ta` (indicators), `strategy`, `chart`.

### 8.2 Closures

**Current state:** Functions are stored as `(params, body)` pairs without capturing the
enclosing environment. Closures (functions that reference outer variables) don't work correctly.

**Fix plan:**
1. At function definition time, capture the current scope stack (or a snapshot of referenced variables).
2. Store as `UserFunction { params, body, captured_env }`.
3. On call, push captured_env as the base scope, then the function's local scope.
4. This enables callbacks, higher-order functions, and functional patterns.

### 8.3 Real Market Data

**Current state:** `lib.rs::generate_symbol_data()` creates synthetic OHLCV data using a
deterministic random walk. Symbols referenced in scripts get fake data.

**Fix plan:**
1. Add a `DataProvider` trait: `fn get_ohlcv(symbol, timeframe, range) -> OhlcvSeries`.
2. Implement providers: CSV file, API (Alpha Vantage, Yahoo Finance, Polygon.io), database.
3. Fall back to synthetic data if the provider is unavailable.
4. Cache fetched data to avoid repeated API calls during development.

### 8.4 Type Checking

**Current state:** Fully dynamic typing. Type errors are runtime errors. No compile-time
type checking.

**Fix plan:**
1. **Phase 1**: Type inference pass after parsing. Annotate AST nodes with inferred types.
2. **Phase 2**: Emit warnings for type mismatches (e.g., `"hello" + 42` without explicit cast).
3. **Phase 3**: Optional type annotations (`fn sma(data: series, period: int) -> series`).
4. **Phase 4**: Strict mode where type errors are compile-time errors.

### 8.5 Performance

**Current state:** Tree-walking interpreter. Adequate for scripts under ~10K bars, but slow
for large backtests or real-time per-bar execution.

**Fix plan:**
1. **Bytecode compilation**: Compile AST to a flat bytecode, interpret with a stack VM.
2. **JIT considerations**: For hot loops, consider cranelift or LLVM (long-term).
3. **Batch mode**: Process all bars at once for indicators (already done), extend to strategy logic.

### 8.6 Error Messages

**Current state:** Parser errors include line/col via `ParseError { message, line, col }`.
Runtime errors are string messages without position info.

**Fix plan:**
1. Add `Span { line, col, len }` to every AST node.
2. Runtime errors reference the span: "Error at line 42, col 5: division by zero".
3. Source-mapped error display: show the offending line with a caret pointer.

---

## 9. Trading Strategy Framework

### 9.1 Strategy Commands

Parsed as distinct statement types in `ast.rs`:

**`strategy.entry(id, direction, qty?, price?, stop?, limit?)`**
```finscript
// Open a long position
strategy.entry("long1", "long", qty=100)

// Open a short position with a limit price
strategy.entry("short1", "short", qty=50, price=150.00)
```

**`strategy.exit(id, from_entry?, qty?, stop?, limit?, trail_points?, trail_offset?)`**
```finscript
// Exit with stop loss and take profit
strategy.exit("exit1", from_entry="long1", stop=145.00, limit=160.00)

// Trailing stop
strategy.exit("trail1", from_entry="long1", trail_points=5.0, trail_offset=2.0)
```

**`strategy.close(id)`**
```finscript
// Close all of a named position
strategy.close("long1")
```

### 9.2 PnL Tracking

The interpreter tracks PnL in real-time during script execution:

```rust
strategy_position: i64,       // Current position size (+ long, - short, 0 flat)
strategy_equity: f64,         // Running equity (starts at 100,000)
strategy_entry_price: f64,    // Average entry price of current position
```

When a trade occurs:
```
realized_pnl = (exit_price - entry_price) * quantity * direction_sign
strategy_equity += realized_pnl
```

### 9.3 Signal Generation

`buy` and `sell` statements generate `Signal` records:

```finscript
if sma(close, 10) > sma(close, 50)
    buy "Golden cross detected"

if sma(close, 10) < sma(close, 50)
    sell "Death cross detected"
```

These produce `Signal { signal_type: "BUY"/"SELL", message, timestamp, price }` in the
`FinScriptResult.signals` array, consumed by the frontend for display and alerting.

---

## 10. Visualization System

### 10.1 Plot Types

| Statement | Output | Use Case |
|-----------|--------|----------|
| `plot(expr, "label")` | Generic line plot | Any numeric series |
| `plot_candlestick("AAPL", "title")` | OHLCV candlestick chart | Price chart |
| `plot_line(value, "label", color?)` | Overlay line | Moving averages, indicators |
| `plot_histogram(value, "label", color_up?, color_down?)` | Bar chart | Volume, MACD histogram |
| `plot_shape(condition, "shape", "location", color?, text?)` | Shape markers | Buy/sell signals |
| `hline(value, "label", color?)` | Horizontal line | Support/resistance, overbought/oversold |
| `bgcolor(color, condition?)` | Background color | Conditional zone highlighting |

### 10.2 Shape Options

For `plot_shape`, supported shapes:
- `"triangleup"` — upward triangle (buy signal)
- `"triangledown"` — downward triangle (sell signal)
- `"circle"` — circle marker
- `"cross"` — cross marker
- `"diamond"` — diamond marker

Location options:
- `"abovebar"` — above the price bar
- `"belowbar"` — below the price bar
- `"absolute"` — at the exact y-value

### 10.3 Color System

Colors are represented as `ColorValue { r, g, b, a }` (each `u8`).

**Named colors:** red, green, blue, white, black, yellow, orange, purple, aqua/cyan,
lime, fuchsia/magenta, silver, gray/grey, maroon, olive, teal, navy.

**Color functions (planned):**
- `color.new(base_color, transparency)` — Create color with alpha.
- `color.rgb(r, g, b, a?)` — From RGB values.

### 10.4 PlotData Structure

All visualization commands produce `PlotData` records:

```rust
pub struct PlotData {
    pub plot_type: String,   // "line", "candlestick", "histogram", "shape", "hline", "bgcolor"
    pub label: String,       // User-specified label
    pub data: Vec<PlotPoint>,
    pub color: Option<String>,
}

pub struct PlotPoint {
    pub timestamp: i64,
    pub value: Option<f64>,
    pub open: Option<f64>,   // For candlestick
    pub high: Option<f64>,
    pub low: Option<f64>,
    pub close: Option<f64>,
    pub volume: Option<f64>,
}
```

These are serialized to JSON and sent to the React/TypeScript frontend via Tauri IPC,
where they are rendered using a charting library.

---

## 11. Example FinScript Programs

### 11.1 Simple Moving Average Crossover

```finscript
fast = sma(close, 10)
slow = sma(close, 50)

if fast > slow and fast[1] <= slow[1]
    buy "Golden cross"

if fast < slow and fast[1] >= slow[1]
    sell "Death cross"

plot_line(fast, "SMA 10", "blue")
plot_line(slow, "SMA 50", "red")
```

### 11.2 RSI Strategy with Plotting

```finscript
rsi_val = rsi(close, 14)

if rsi_val < 30
    strategy.entry("oversold_long", "long")

if rsi_val > 70
    strategy.exit("overbought_exit", from_entry="oversold_long")

plot_line(rsi_val, "RSI 14", "purple")
hline(70, "Overbought", "red")
hline(30, "Oversold", "green")
bgcolor("green", rsi_val < 30)
bgcolor("red", rsi_val > 70)
```

### 11.3 Bollinger Band Breakout

```finscript
upper, middle, lower = bollinger(close, 20, 2.0)

if close > upper
    buy "Breakout above upper band"
    plot_shape(true, "triangleup", "belowbar", "green", "Break Up")

if close < lower
    sell "Breakdown below lower band"
    plot_shape(true, "triangledown", "abovebar", "red", "Break Down")

plot_line(upper, "BB Upper", "gray")
plot_line(middle, "BB Middle", "blue")
plot_line(lower, "BB Lower", "gray")
```
