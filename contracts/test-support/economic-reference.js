export class EconomicReference {
  constructor({ feeBps, sponsors, solvers, fundingCap = (1n << 256n) - 1n }) {
    this.feeBps = BigInt(feeBps);
    this.sponsorships = new Map(sponsors.map((address) => [address, 0n]));
    this.credits = new Map(solvers.map((address) => [address, 0n]));
    this.claimedGross = new Map(solvers.map((address) => [address, 0n]));
    this.accounted = 0n;
    this.totalFunded = 0n;
    this.totalCredit = 0n;
    this.totalGrossClaimed = 0n;
    this.totalClaimed = 0n;
    this.feeAccrued = 0n;
    this.feePaid = 0n;
    this.sponsorRefunded = 0n;
    this.rolloverPaid = 0n;
    this.forced = 0n;
    this.totalForced = 0n;
    this.forcedRecovered = 0n;
    this.closed = false;
    this.closedPoolBalance = 0n;
    this.paused = false;
    this.expired = false;
    this.rolloverSwept = false;
    this.fundingCap = fundingCap;
    this.acceptingFunds = true;
    this.fundingArmed = true;
    this.fundingWindowOpen = true;
    this.closeReady = false;
    this.openSubmissions = 0;
    this.pausedAll = false;
    this.recoveryWindowOpen = false;
  }

  fund(sponsor, amount) {
    if (
      amount === 0n || this.closed || !this.acceptingFunds || !this.fundingArmed
        || !this.fundingWindowOpen || amount > this.fundingCap - this.accounted
    ) return false;
    this.accounted += amount;
    this.totalFunded += amount;
    this.sponsorships.set(sponsor, this.sponsorships.get(sponsor) + amount);
    return true;
  }

  recordCredit(solver, atoms) {
    if (atoms === 0n || this.closed || this.paused) return false;
    this.credits.set(solver, this.credits.get(solver) + atoms);
    this.totalCredit += atoms;
    return true;
  }

  voidCredit(solver, atoms) {
    const credit = this.credits.get(solver);
    if (this.closed || atoms === 0n || atoms > credit) return false;
    this.credits.set(solver, credit - atoms);
    this.totalCredit -= atoms;
    return true;
  }

  close() {
    if (
      this.closed || !this.closeReady || this.openSubmissions !== 0
        || this.pausedAll || this.recoveryWindowOpen
    ) return false;
    this.closed = true;
    this.closedPoolBalance = this.accounted;
    return true;
  }

  claim(solver) {
    if (!this.closed || this.totalCredit === 0n || this.expired) return false;
    const gross = this.closedPoolBalance * this.credits.get(solver) / this.totalCredit;
    const unclaimed = gross - this.claimedGross.get(solver);
    if (unclaimed === 0n) return false;
    const fee = unclaimed * this.feeBps / 10_000n;
    this.claimedGross.set(solver, gross);
    this.totalGrossClaimed += unclaimed;
    this.totalClaimed += unclaimed - fee;
    this.feeAccrued += fee;
    this.accounted -= unclaimed - fee;
    return true;
  }

  claimFees() {
    const outstanding = this.feeAccrued - this.feePaid;
    if (outstanding === 0n) return false;
    this.feePaid += outstanding;
    this.accounted -= outstanding;
    return true;
  }

  refund(sponsor) {
    const principal = this.sponsorships.get(sponsor);
    if (!this.closed || this.totalCredit !== 0n || principal === 0n) return false;
    this.sponsorships.set(sponsor, 0n);
    this.sponsorRefunded += principal;
    this.accounted -= principal;
    return true;
  }

  sweepRollover() {
    if (!this.closed || this.totalCredit === 0n || !this.expired || this.rolloverSwept) return false;
    const amount = this.accounted - (this.feeAccrued - this.feePaid);
    this.accounted -= amount;
    this.rolloverPaid += amount;
    this.rolloverSwept = true;
    return true;
  }

  force(amount) {
    this.forced += amount;
    this.totalForced += amount;
  }

  recoverForced(amount) {
    if (!this.closed || amount === 0n || amount > this.forced) return false;
    this.forced -= amount;
    this.forcedRecovered += amount;
    return true;
  }
}

export function seeded(seed) {
  let state = BigInt(seed) & ((1n << 64n) - 1n);
  return (bound) => {
    state ^= state << 13n;
    state ^= state >> 7n;
    state ^= state << 17n;
    state &= (1n << 64n) - 1n;
    return Number(state % BigInt(bound));
  };
}
