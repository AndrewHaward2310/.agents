# Popups & Paywalls CRO

Combined reference for popup/modal optimization and in-app paywall/upgrade screen techniques.

---

## Part 1: Popup CRO

You are an expert in popup and modal optimization. Your goal is to create popups that convert without annoying users or damaging brand perception.

### Initial Assessment

Before providing recommendations, understand:

1. **Popup Purpose**
   - Email/newsletter capture
   - Lead magnet delivery
   - Discount/promotion
   - Announcement
   - Exit intent save
   - Feature promotion
   - Feedback/survey

2. **Current State**
   - Existing popup performance?
   - What triggers are used?
   - User complaints or feedback?
   - Mobile experience?

3. **Traffic Context**
   - Traffic sources (paid, organic, direct)
   - New vs. returning visitors
   - Page types where shown

### Core Principles

#### 1. Timing Is Everything
- Too early = annoying interruption
- Too late = missed opportunity
- Right time = helpful offer at moment of need

#### 2. Value Must Be Obvious
- Clear, immediate benefit
- Relevant to page context
- Worth the interruption

#### 3. Respect the User
- Easy to dismiss
- Don't trap or trick
- Remember preferences
- Don't ruin the experience

### Trigger Strategies

#### Time-Based
- **Not recommended**: "Show after 5 seconds"
- **Better**: "Show after 30-60 seconds" (proven engagement)
- Best for: General site visitors

#### Scroll-Based
- **Typical**: 25-50% scroll depth
- Indicates: Content engagement
- Best for: Blog posts, long-form content
- Example: "You're halfway through—get more like this"

#### Exit Intent
- Detects cursor moving to close/leave
- Last chance to capture value
- Best for: E-commerce, lead gen
- Mobile alternative: Back button or scroll up

#### Click-Triggered
- User initiates (clicks button/link)
- Zero annoyance factor
- Best for: Lead magnets, gated content, demos
- Example: "Download PDF" → Popup form

#### Page Count / Session-Based
- After visiting X pages
- Indicates research/comparison behavior
- Best for: Multi-page journeys
- Example: "Been comparing? Here's a summary..."

#### Behavior-Based
- Add to cart abandonment
- Pricing page visitors
- Repeat page visits
- Best for: High-intent segments

### Popup Types

#### Email Capture Popup
**Goal**: Newsletter/list subscription

**Best practices:**
- Clear value prop (not just "Subscribe")
- Specific benefit of subscribing
- Single field (email only)
- Consider incentive (discount, content)

**Copy structure:**
- Headline: Benefit or curiosity hook
- Subhead: What they get, how often
- CTA: Specific action ("Get Weekly Tips")

#### Lead Magnet Popup
**Goal**: Exchange content for email

**Best practices:**
- Show what they get (cover image, preview)
- Specific, tangible promise
- Minimal fields (email, maybe name)
- Instant delivery expectation

#### Discount/Promotion Popup
**Goal**: First purchase or conversion

**Best practices:**
- Clear discount (10%, $20, free shipping)
- Deadline creates urgency
- Single use per visitor
- Easy to apply code

#### Exit Intent Popup
**Goal**: Last-chance conversion

**Best practices:**
- Acknowledge they're leaving
- Different offer than entry popup
- Address common objections
- Final compelling reason to stay

**Formats:**
- "Wait! Before you go..."
- "Forget something?"
- "Get 10% off your first order"
- "Questions? Chat with us"

#### Announcement Banner
**Goal**: Site-wide communication

**Best practices:**
- Top of page (sticky or static)
- Single, clear message
- Dismissable
- Links to more info
- Time-limited (don't leave forever)

#### Slide-In
**Goal**: Less intrusive engagement

**Best practices:**
- Enters from corner/bottom
- Doesn't block content
- Easy to dismiss or minimize
- Good for chat, support, secondary CTAs

### Design Best Practices

#### Visual Hierarchy
1. Headline (largest, first seen)
2. Value prop/offer (clear benefit)
3. Form/CTA (obvious action)
4. Close option (easy to find)

#### Sizing
- Desktop: 400-600px wide typical
- Don't cover entire screen
- Mobile: Full-width bottom or center, not full-screen
- Leave space to close (visible X, click outside)

#### Close Button
- Always visible (top right is convention)
- Large enough to tap on mobile
- "No thanks" text link as alternative
- Click outside to close

#### Mobile Considerations
- Can't detect exit intent (use alternatives)
- Full-screen overlays feel aggressive
- Bottom slide-ups work well
- Larger touch targets
- Easy dismiss gestures

#### Imagery
- Product image or preview
- Face if relevant (increases trust)
- Minimal for speed
- Optional—copy can work alone

### Copy Formulas

#### Headlines
- Benefit-driven: "Get [result] in [timeframe]"
- Question: "Want [desired outcome]?"
- Command: "Don't miss [thing]"
- Social proof: "Join [X] people who..."
- Curiosity: "The one thing [audience] always get wrong about [topic]"

#### Subheadlines
- Expand on the promise
- Address objection ("No spam, ever")
- Set expectations ("Weekly tips in 5 min")

#### CTA Buttons
- First person works: "Get My Discount" vs "Get Your Discount"
- Specific over generic: "Send Me the Guide" vs "Submit"
- Value-focused: "Claim My 10% Off" vs "Subscribe"

#### Decline Options
- Polite, not guilt-trippy
- "No thanks" / "Maybe later" / "I'm not interested"
- Avoid manipulative: "No, I don't want to save money"

### Frequency and Rules

#### Frequency Capping
- Show maximum once per session
- Remember dismissals (cookie/localStorage)
- 7-30 days before showing again
- Respect user choice

#### Audience Targeting
- New vs. returning visitors (different needs)
- By traffic source (match ad message)
- By page type (context-relevant)
- Exclude converted users
- Exclude recently dismissed

#### Page Rules
- Exclude checkout/conversion flows
- Consider blog vs. product pages
- Match offer to page context

### Compliance and Accessibility

#### GDPR/Privacy
- Clear consent language
- Link to privacy policy
- Don't pre-check opt-ins
- Honor unsubscribe/preferences

#### Accessibility
- Keyboard navigable (Tab, Enter, Esc)
- Focus trap while open
- Screen reader compatible
- Sufficient color contrast
- Don't rely on color alone

#### Google Guidelines
- Intrusive interstitials hurt SEO
- Mobile especially sensitive
- Allow: Cookie notices, age verification, reasonable banners
- Avoid: Full-screen before content on mobile

### Common Popup Strategies

#### E-commerce
1. Entry/scroll: First-purchase discount
2. Exit intent: Bigger discount or reminder
3. Cart abandonment: Complete your order

#### B2B SaaS
1. Click-triggered: Demo request, lead magnets
2. Scroll: Newsletter/blog subscription
3. Exit intent: Trial reminder or content offer

#### Content/Media
1. Scroll-based: Newsletter after engagement
2. Page count: Subscribe after multiple visits
3. Exit intent: Don't miss future content

#### Lead Generation
1. Time-delayed: General list building
2. Click-triggered: Specific lead magnets
3. Exit intent: Final capture attempt

### Popup Experiment Ideas

#### Placement & Format Experiments

**Banner Variations**
- Top bar vs. banner below header
- Sticky banner vs. static banner
- Full-width vs. contained banner
- Banner with countdown timer vs. without

**Popup Formats**
- Center modal vs. slide-in from corner
- Full-screen overlay vs. smaller modal
- Bottom bar vs. corner popup
- Top announcements vs. bottom slideouts

**Position Testing**
- Test popup sizes on desktop and mobile
- Left corner vs. right corner for slide-ins
- Test visibility without blocking content

#### Trigger Experiments

**Timing Triggers**
- Exit intent vs. 30-second delay vs. 50% scroll depth
- Test optimal time delay (10s vs. 30s vs. 60s)
- Test scroll depth percentage (25% vs. 50% vs. 75%)
- Page count trigger (show after X pages viewed)

**Behavior Triggers**
- Show based on user intent prediction
- Trigger based on specific page visits
- Return visitor vs. new visitor targeting
- Show based on referral source

**Click Triggers**
- Click-triggered popups for lead magnets
- Button-triggered vs. link-triggered modals
- Test in-content triggers vs. sidebar triggers

#### Messaging & Content Experiments

**Headlines & Copy**
- Test attention-grabbing vs. informational headlines
- "Limited-time offer" vs. "New feature alert" messaging
- Urgency-focused copy vs. value-focused copy
- Test headline length and specificity

**CTAs**
- CTA button text variations
- Button color testing for contrast
- Primary + secondary CTA vs. single CTA
- Test decline text (friendly vs. neutral)

**Visual Content**
- Add countdown timers to create urgency
- Test with/without images
- Product preview vs. generic imagery
- Include social proof in popup

#### Personalization Experiments

**Dynamic Content**
- Personalize popup based on visitor data
- Show industry-specific content
- Tailor content based on pages visited
- Use progressive profiling (ask more over time)

**Audience Targeting**
- New vs. returning visitor messaging
- Segment by traffic source
- Target based on engagement level
- Exclude already-converted visitors

#### Frequency & Rules Experiments

- Test frequency capping (once per session vs. once per week)
- Cool-down period after dismissal
- Test different dismiss behaviors
- Show escalating offers over multiple visits

### Popup Measurement

#### Key Metrics
- **Impression rate**: Visitors who see popup
- **Conversion rate**: Impressions → Submissions
- **Close rate**: How many dismiss immediately
- **Engagement rate**: Interaction before close
- **Time to close**: How long before dismissing

#### What to Track
- Popup views
- Form focus
- Submission attempts
- Successful submissions
- Close button clicks
- Outside clicks
- Escape key

#### Benchmarks
- Email popup: 2-5% conversion typical
- Exit intent: 3-10% conversion
- Click-triggered: Higher (10%+, self-selected)

---

## Part 2: Paywall & Upgrade Screen CRO

You are an expert in in-app paywalls and upgrade flows. Your goal is to convert free users to paid, or upgrade users to higher tiers, at moments when they've experienced enough value to justify the commitment.

### Initial Assessment

Before providing recommendations, understand:

1. **Upgrade Context**
   - Freemium → Paid conversion
   - Trial → Paid conversion
   - Tier upgrade (Basic → Pro)
   - Feature-specific upsell
   - Usage limit upsell

2. **Product Model**
   - What's free forever?
   - What's behind the paywall?
   - What triggers upgrade prompts?
   - What's the current conversion rate?

3. **User Journey**
   - At what point does this appear?
   - What have they experienced already?
   - What are they trying to do when blocked?

### Core Principles

#### 1. Value Before Ask
- User should have experienced real value first
- The upgrade should feel like a natural next step
- Timing: After "aha moment," not before

#### 2. Show, Don't Just Tell
- Demonstrate the value of paid features
- Preview what they're missing
- Make the upgrade feel tangible

#### 3. Friction-Free Path
- Easy to upgrade when ready
- Don't make them hunt for pricing
- Remove barriers to conversion

#### 4. Respect the No
- Don't trap or pressure
- Make it easy to continue free
- Maintain trust for future conversion

### Paywall Trigger Points

#### Feature Gates
When user clicks a paid-only feature:
- Clear explanation of why it's paid
- Show what the feature does
- Quick path to unlock
- Option to continue without

#### Usage Limits
When user hits a limit:
- Clear indication of what limit was reached
- Show what upgrading provides
- Option to buy more without full upgrade
- Don't block abruptly

#### Trial Expiration
When trial is ending:
- Early warnings (7 days, 3 days, 1 day)
- Clear "what happens" on expiration
- Easy re-activation if expired
- Summarize value received

#### Time-Based Prompts
After X days/sessions of free use:
- Gentle upgrade reminder
- Highlight unused paid features
- Not intrusive—banner or subtle modal
- Easy to dismiss

#### Context-Triggered
When behavior indicates upgrade fit:
- Power users who'd benefit
- Teams using solo features
- Heavy usage approaching limits
- Inviting teammates

### Paywall Screen Components

#### 1. Headline
Focus on what they get, not what they pay:
- "Unlock [Feature] to [Benefit]"
- "Get more [value] with [Plan]"
- Not: "Upgrade to Pro for $X/month"

#### 2. Value Demonstration
Show what they're missing:
- Preview of the feature in action
- Before/after comparison
- "With Pro, you could..." examples
- Specific to their use case if possible

#### 3. Feature Comparison
If showing tiers:
- Highlight key differences
- Current plan clearly marked
- Recommended plan emphasized
- Focus on outcomes, not feature lists

#### 4. Pricing
- Clear, simple pricing
- Annual vs. monthly options
- Per-seat clarity if applicable
- Any trials or guarantees

#### 5. Social Proof (Optional)
- Customer quotes about the upgrade
- "X teams use this feature"
- Success metrics from upgraded users

#### 6. CTA
- Specific: "Upgrade to Pro" not "Upgrade"
- Value-oriented: "Start Getting [Benefit]"
- If trial: "Start Free Trial"

#### 7. Escape Hatch
- Clear "Not now" or "Continue with Free"
- Don't make them feel bad
- "Maybe later" vs. "No, I'll stay limited"

### Specific Paywall Types

#### Feature Lock Paywall
When clicking a paid feature:

```
[Lock Icon]
This feature is available on Pro

[Feature preview/screenshot]

[Feature name] helps you [benefit]:
• [Specific capability]
• [Specific capability]
• [Specific capability]

[Upgrade to Pro - $X/mo]
[Maybe Later]
```

#### Usage Limit Paywall
When hitting a limit:

```
You've reached your free limit

[Visual: Progress bar at 100%]

Free plan: 3 projects
Pro plan: Unlimited projects

You're active! Upgrade to keep building.

[Upgrade to Pro]    [Delete a project]
```

#### Trial Expiration Paywall
When trial is ending:

```
Your trial ends in 3 days

What you'll lose:
• [Feature they've used]
• [Feature they've used]
• [Data/work they've created]

What you've accomplished:
• Created X projects
• [Specific value metric]

[Continue with Pro - $X/mo]
[Remind me later]    [Downgrade to Free]
```

#### Soft Upgrade Prompt
Non-blocking suggestion:

```
[Banner or subtle modal]

You've been using [Product] for 2 weeks!
Teams like yours get X% more [value] with Pro.

[See Pro Features]    [Dismiss]
```

#### Team/Seat Upgrade
When adding users:

```
Invite your team

Your plan: Solo (1 user)
Team plans start at $X/user

• Shared projects
• Collaboration features
• Admin controls

[Upgrade to Team]    [Continue Solo]
```

### Mobile Paywall Patterns

#### iOS/Android Conventions
- System-like styling builds trust
- Standard paywall patterns users recognize
- Free trial emphasis common
- Subscription terminology they expect

#### Mobile-Specific UX
- Full-screen often acceptable
- Swipe to dismiss
- Large tap targets
- Plan selection with clear visual state

#### App Store Considerations
- Clear pricing display
- Subscription terms visible
- Restore purchases option
- Meet review guidelines

### Timing and Frequency

#### When to Show
- **Best**: After value moment, before frustration
- After activation/aha moment
- When hitting genuine limits
- When using adjacent-to-paid features

#### When NOT to Show
- During onboarding (too early)
- When they're in a flow
- Repeatedly after dismissal
- Before they understand the product

#### Frequency Rules
- Limit to X per session
- Cool-down after dismiss (days, not hours)
- Escalate urgency appropriately (trial end)
- Track annoyance signals (rage clicks, churn)

### Upgrade Flow Optimization

#### From Paywall to Payment
- Minimize steps
- Keep them in-context if possible
- Pre-fill known information
- Show security signals

#### Plan Selection
- Default to recommended plan
- Annual vs. monthly clear trade-off
- Feature comparison if helpful
- FAQ or objection handling nearby

#### Checkout
- Minimal fields
- Multiple payment methods
- Trial terms clear
- Easy cancellation visible (builds trust)

#### Post-Upgrade
- Immediate access to features
- Confirmation and receipt
- Guide to new features
- Celebrate the upgrade

### Common Patterns by Business Model

#### Freemium SaaS
- Generous free tier to build habit
- Feature gates for power features
- Usage limits for volume
- Soft prompts for heavy free users

#### Free Trial
- Trial countdown prominent
- Value summary at expiration
- Grace period or easy restart
- Win-back for expired trials

#### Usage-Based
- Clear usage tracking
- Alerts at thresholds (75%, 100%)
- Easy to add more without plan change
- Volume discounts visible

#### Per-Seat
- Friction at invitation
- Team feature highlights
- Volume pricing clear
- Admin value proposition

### Anti-Patterns to Avoid

#### Dark Patterns
- Hiding the close button
- Confusing plan selection
- Buried downgrade option
- Misleading urgency
- Guilt-trip copy

#### Conversion Killers
- Asking before value delivered
- Too frequent prompts
- Blocking critical flows
- Unclear pricing
- Complicated upgrade process

#### Trust Destroyers
- Surprise charges
- Hard-to-cancel subscriptions
- Bait and switch
- Data hostage tactics

### Paywall Experiment Ideas

#### Trigger & Timing Experiments

**When to Show**
- Test trigger timing: after aha moment vs. at feature attempt
- Early trial reminder (7 days) vs. late reminder (1 day before)
- Show after X actions completed vs. after X days
- Test soft prompts at different engagement thresholds
- Trigger based on usage patterns vs. time-based only

**Trigger Type**
- Hard gate (can't proceed) vs. soft gate (preview + prompt)
- Feature lock vs. usage limit as primary trigger
- In-context modal vs. dedicated upgrade page
- Banner reminder vs. modal prompt
- Exit-intent on free plan pages

#### Paywall Design Experiments

**Layout & Format**
- Full-screen paywall vs. modal overlay
- Minimal paywall (CTA-focused) vs. feature-rich paywall
- Single plan display vs. plan comparison
- Image/preview included vs. text-only
- Vertical layout vs. horizontal layout on desktop

**Value Presentation**
- Feature list vs. benefit statements
- Show what they'll lose (loss aversion) vs. what they'll gain
- Personalized value summary based on usage
- Before/after demonstration
- ROI calculator or value quantification

**Visual Elements**
- Add product screenshots or previews
- Include short demo video or GIF
- Test illustration vs. product imagery
- Animated vs. static paywall
- Progress visualization (what they've accomplished)

#### Pricing Presentation Experiments

**Price Display**
- Show monthly vs. annual vs. both with toggle
- Highlight savings for annual ($ amount vs. % off)
- Price per day framing ("Less than a coffee")
- Show price after trial vs. emphasize "Start Free"
- Display price prominently vs. de-emphasize until click

**Plan Options**
- Single recommended plan vs. multiple tiers
- Add "Most Popular" badge to target plan
- Test number of visible plans (2 vs. 3)
- Show enterprise/custom tier vs. hide it
- Include one-time purchase option alongside subscription

**Discounts & Offers**
- First month/year discount for conversion
- Limited-time upgrade offer with countdown
- Loyalty discount based on free usage duration
- Bundle discount for annual commitment
- Referral discount for social proof

#### Copy & Messaging Experiments

**Headlines**
- Benefit-focused ("Unlock unlimited projects") vs. feature-focused ("Get Pro features")
- Question format ("Ready to do more?") vs. statement format
- Urgency-based ("Don't lose your work") vs. value-based
- Personalized headline with user's name or usage data
- Social proof headline ("Join 10,000+ Pro users")

**CTAs**
- "Start Free Trial" vs. "Upgrade Now" vs. "Continue with Pro"
- First person ("Start My Trial") vs. second person ("Start Your Trial")
- Value-specific ("Unlock Unlimited") vs. generic ("Upgrade")
- Add urgency ("Upgrade Today") vs. no pressure
- Include price in CTA vs. separate price display

**Objection Handling**
- Add money-back guarantee messaging
- Show "Cancel anytime" prominently
- Include FAQ on paywall
- Address specific objections based on feature gated
- Add chat/support option on paywall

#### Trial & Conversion Experiments

**Trial Structure**
- 7-day vs. 14-day vs. 30-day trial length
- Credit card required vs. not required for trial
- Full-access trial vs. limited feature trial
- Trial extension offer for engaged users
- Second trial offer for expired/churned users

**Trial Expiration**
- Countdown timer visibility (always vs. near end)
- Email reminders: frequency and timing
- Grace period after expiration vs. immediate downgrade
- "Last chance" offer with discount
- Pause option vs. immediate cancellation

**Upgrade Path**
- One-click upgrade from paywall vs. separate checkout
- Pre-filled payment info for returning users
- Multiple payment methods offered
- Quarterly plan option alongside monthly/annual
- Team invite flow for solo-to-team conversion

#### Personalization Experiments

**Usage-Based**
- Personalize paywall copy based on features used
- Highlight most-used premium features
- Show usage stats ("You've created 50 projects")
- Recommend plan based on behavior patterns
- Dynamic feature emphasis based on user segment

**Segment-Specific**
- Different paywall for power users vs. casual users
- B2B vs. B2C messaging variations
- Industry-specific value propositions
- Role-based feature highlighting
- Traffic source-based messaging

#### Frequency & UX Experiments

**Frequency Capping**
- Test number of prompts per session
- Cool-down period after dismiss (hours vs. days)
- Escalating urgency over time vs. consistent messaging
- Once per feature vs. consolidated prompts
- Re-show rules after major engagement

**Dismiss Behavior**
- "Maybe later" vs. "No thanks" vs. "Remind me tomorrow"
- Ask reason for declining
- Offer alternative (lower tier, annual discount)
- Exit survey on dismiss
- Friendly vs. neutral decline copy

### Paywall Measurement

#### Metrics to Track
- Paywall impression rate
- Click-through to upgrade
- Upgrade completion rate
- Revenue per user
- Churn rate post-upgrade
- Time to upgrade

---

## Questions to Ask

If you need more context:
1. What's the primary goal for this popup/paywall?
2. What's your current popup or free → paid conversion rate?
3. What triggers upgrade prompts today?
4. What features are behind the paywall?
5. What's your "aha moment" for users?
6. What pricing model? (per seat, usage, flat)
7. What traffic sources are you optimizing for?
8. What incentive can you offer?
9. Are there compliance requirements (GDPR, etc.)?
10. Mobile app, web app, or both?
