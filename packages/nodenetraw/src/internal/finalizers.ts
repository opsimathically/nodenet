export interface InternalFinalizers {
  add(finalizer: () => void): void;
  run(): void;
}

/** Internal ordered, idempotent cleanup used by pending operation settlement. */
export function createInternalFinalizers(): InternalFinalizers {
  const finalizers: (() => void)[] = [];
  let finished = false;

  return {
    add(finalizer): void {
      if (finished) {
        throw new Error("cannot register a finalizer after settlement");
      }
      finalizers.push(finalizer);
    },
    run(): void {
      if (finished) return;
      finished = true;
      const snapshot = finalizers.splice(0);
      for (const finalizer of snapshot) {
        try {
          finalizer();
        } catch {
          // Cleanup invariants are independent; one internal fault must not
          // strand the remaining finalizers or replace the chosen outcome.
        }
      }
    },
  };
}
