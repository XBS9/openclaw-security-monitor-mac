using Xunit;

/// <summary>
/// Marks a collection of tests that must run serially (no parallelism).
///
/// Used by SecurityImprovementTests and MonitorBehaviorTests because they both
/// mutate the static BaselinePersistence.TestBaselineDir property. Parallelism
/// across those two classes would cause race conditions on that property.
/// </summary>
[CollectionDefinition("NoParallel", DisableParallelization = true)]
public class NoParallelCollection { }
