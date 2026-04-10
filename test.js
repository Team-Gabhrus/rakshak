const snapshots = cbomSnapshots;
const latest = Array.from(new Map(snapshots.map(s => [s.target, s])).values());
