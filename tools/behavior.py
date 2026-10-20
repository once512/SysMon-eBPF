# SPDX-License-Identifier: MIT
"""Bounded observation rule; a match describes evidence, never malicious intent."""
from collections import deque

RULE_ID = 'allowed-access-before-denied-mutation-v1'


class AccessThenDenial:
    """Match each denial at most once, including across reversed log delivery.

    Permission *response* time must strictly precede the mutation hook timestamp.
    Only open/access allows qualify: exec permission does not describe file reading.
    Histories retain the most recently delivered facts, not a complete time window.
    """
    def __init__(self, window_ms, history, samples):
        self.window_ns = window_ms * 1_000_000
        self.history = history
        self.allows, self.pending = deque(), deque()
        self.matches = 0
        self.history_evictions = 0
        self.evidence = deque(maxlen=samples)

    def qualifies(self, allow, denial):
        delta = denial['timestamp_ns'] - allow['responded_ns']
        return 0 < delta <= self.window_ns

    def match(self, allow, denial):
        self.matches += 1
        self.evidence.append(dict(permission=allow, denial=denial,
                                  delta_ns=denial['timestamp_ns'] - allow['responded_ns']))

    def remember(self, queue, fact):
        if len(queue) == self.history:
            queue.popleft()
            self.history_evictions += 1
        queue.append(fact)

    def accept(self, fact):
        if fact['event'] == 'fanotify_decision':
            if fact['decision'] != 'allow' or fact['permission_event'] not in ('open', 'access'):
                return
            self.remember(self.allows, fact)
            remaining = deque()
            for denial in self.pending:
                if self.qualifies(fact, denial):
                    self.match(fact, denial)
                else:
                    remaining.append(denial)
            self.pending = remaining
        else:
            candidates = [allow for allow in self.allows if self.qualifies(allow, fact)]
            if candidates:
                # Deterministic representative, not a claim about causal attribution.
                self.match(max(candidates, key=lambda row: (row['responded_ns'], row['line'])), fact)
            else:
                self.remember(self.pending, fact)

    def report(self):
        return dict(rule=RULE_ID, window_ns=self.window_ns, history_per_kind=self.history,
                    matches=self.matches, history_evictions=self.history_evictions,
                    evidence_samples=list(self.evidence), complete=False,
                    code_identity_verified=False,
                    interpretation='observation-only', response='none')
