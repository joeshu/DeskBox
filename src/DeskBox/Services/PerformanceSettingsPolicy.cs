using DeskBox.Models;

namespace DeskBox.Services;

public readonly record struct EffectivePerformanceSettings(
    string Mode,
    int HiddenCacheCleanupDelaySeconds,
    int HiddenDeepCleanupDelaySeconds,
    bool AllowTextMarqueeAnimations,
    bool AllowVinylRotationAnimations,
    bool AllowGlanceImageAutoRotation,
    bool AllowCompactAmbientAnimations,
    int VisibleIdleCacheCleanupDelaySeconds,
    int TransientWindowReleaseDelaySeconds,
    string CacheBudget,
    string HiddenCacheCleanupScope)
{
    public bool AllowContinuousDecorativeAnimations =>
        AllowTextMarqueeAnimations ||
        AllowVinylRotationAnimations ||
        AllowGlanceImageAutoRotation ||
        AllowCompactAmbientAnimations;
}

/// <summary>
/// Resolves the user-facing performance preset into narrowly scoped runtime
/// behavior. Interaction, capsule expansion, and widget show/hide animations
/// are intentionally outside this policy.
/// </summary>
public static class PerformanceSettingsPolicy
{
    public const string ModeBestVisual = "BestVisual";
    public const string ModeBalanced = "Balanced";
    public const string ModeResourceSaver = "ResourceSaver";
    public const string ModeCustom = "Custom";

    public const string DecorativeAnimationTextMarquee = "TextMarquee";
    public const string DecorativeAnimationVinylRotation = "VinylRotation";
    public const string DecorativeAnimationGlanceRotation = "GlanceRotation";
    public const string DecorativeAnimationCompactAmbient = "CompactAmbient";

    public static IReadOnlyList<string> SupportedDecorativeAnimationOptions { get; } =
        Array.AsReadOnly(new[]
        {
            DecorativeAnimationTextMarquee,
            DecorativeAnimationVinylRotation,
            DecorativeAnimationGlanceRotation,
            DecorativeAnimationCompactAmbient
        });

    public const string CacheBudgetSmall = "Small";
    public const string CacheBudgetBalanced = "Balanced";
    public const string CacheBudgetLarge = "Large";

    public const string HiddenCacheCleanupScopeWarm = "Warm";
    public const string HiddenCacheCleanupScopeAllRecreatable =
        "AllRecreatable";

    public const int CleanupNever = -1;
    public const int CleanupAfter30Seconds = 30;
    public const int CleanupAfter1Minute = 60;
    public const int CleanupAfter2Minutes = 2 * 60;
    public const int CleanupAfter5Minutes = 5 * 60;
    public const int CleanupAfter10Minutes = 10 * 60;
    public const int CleanupAfter15Minutes = 15 * 60;

    public const string DefaultMode = ModeResourceSaver;
    public const int DefaultHiddenCacheCleanupDelaySeconds = CleanupAfter30Seconds;
    public const int DefaultVisibleIdleCacheCleanupDelaySeconds = CleanupAfter5Minutes;
    public const int DefaultTransientWindowReleaseDelaySeconds = CleanupAfter2Minutes;
    public const string DefaultCacheBudget = CacheBudgetSmall;
    public const string DefaultHiddenCacheCleanupScope =
        HiddenCacheCleanupScopeAllRecreatable;
    public const bool DefaultIdleWorkingSetTrimEnabled = true;
    public const bool DefaultImmediateHiddenWorkingSetTrimEnabled = true;
    public const bool DefaultContinuousDecorativeAnimationsEnabled = false;
    public const bool DefaultTextMarqueeAnimationsEnabled = false;
    public const bool DefaultVinylRotationAnimationsEnabled = false;
    public const bool DefaultGlanceImageAutoRotationEnabled = false;
    public const bool DefaultCompactAmbientAnimationsEnabled = false;

    public static string NormalizeMode(string? mode)
    {
        if (string.Equals(mode, ModeResourceSaver, StringComparison.OrdinalIgnoreCase))
        {
            return ModeResourceSaver;
        }

        if (string.Equals(mode, ModeCustom, StringComparison.OrdinalIgnoreCase))
        {
            return ModeCustom;
        }

        return ModeBalanced;
    }

    public static string NormalizeCacheBudget(string? cacheBudget)
    {
        if (string.Equals(
                cacheBudget,
                CacheBudgetSmall,
                StringComparison.OrdinalIgnoreCase))
        {
            return CacheBudgetSmall;
        }

        if (string.Equals(
                cacheBudget,
                CacheBudgetLarge,
                StringComparison.OrdinalIgnoreCase))
        {
            return CacheBudgetLarge;
        }

        return CacheBudgetBalanced;
    }

    public static string NormalizeHiddenCacheCleanupScope(string? scope)
    {
        if (string.Equals(
                scope,
                HiddenCacheCleanupScopeWarm,
                StringComparison.OrdinalIgnoreCase))
        {
            return HiddenCacheCleanupScopeWarm;
        }

        return HiddenCacheCleanupScopeAllRecreatable;
    }

    public static int ResolveInactiveGroupContentCacheCapacity(
        string? cacheBudget)
    {
        return NormalizeCacheBudget(cacheBudget) switch
        {
            CacheBudgetSmall => 1,
            CacheBudgetLarge => 2,
            _ => 1
        };
    }

    public static int NormalizeHiddenCacheCleanupDelaySeconds(int delaySeconds) =>
        delaySeconds == CleanupNever
            ? CleanupAfter5Minutes
            : delaySeconds is
            CleanupAfter30Seconds or
            CleanupAfter1Minute or
            CleanupAfter5Minutes
                ? delaySeconds
                : DefaultHiddenCacheCleanupDelaySeconds;

    public static int NormalizeVisibleIdleCacheCleanupDelaySeconds(
        int delaySeconds) =>
        delaySeconds == CleanupNever
            ? CleanupAfter15Minutes
            : delaySeconds is
            CleanupAfter30Seconds or
            CleanupAfter1Minute or
            CleanupAfter5Minutes or
            CleanupAfter10Minutes or
            CleanupAfter15Minutes
                ? delaySeconds
                : DefaultVisibleIdleCacheCleanupDelaySeconds;

    public static int NormalizeTransientWindowReleaseDelaySeconds(
        int delaySeconds) =>
        delaySeconds == CleanupNever
            ? CleanupAfter10Minutes
            : delaySeconds is
            CleanupAfter30Seconds or
            CleanupAfter1Minute or
            CleanupAfter2Minutes or
            CleanupAfter10Minutes
                ? delaySeconds
                : DefaultTransientWindowReleaseDelaySeconds;

    public static EffectivePerformanceSettings Resolve(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        string mode = NormalizeMode(settings.PerformanceMode);
        return mode switch
        {
            ModeResourceSaver => new(
                mode,
                CleanupAfter30Seconds,
                CleanupAfter1Minute,
                settings.EnableTextMarqueeAnimations,
                settings.EnableVinylRotationAnimations,
                settings.EnableGlanceImageAutoRotation,
                settings.EnableCompactAmbientAnimations,
                CleanupAfter5Minutes,
                CleanupAfter2Minutes,
                CacheBudgetSmall,
                HiddenCacheCleanupScopeAllRecreatable),
            ModeCustom => ResolveCustom(settings),
            _ => new(
                ModeBalanced,
                CleanupAfter30Seconds,
                CleanupAfter5Minutes,
                settings.EnableTextMarqueeAnimations,
                settings.EnableVinylRotationAnimations,
                settings.EnableGlanceImageAutoRotation,
                settings.EnableCompactAmbientAnimations,
                CleanupAfter10Minutes,
                CleanupAfter10Minutes,
                CacheBudgetBalanced,
                HiddenCacheCleanupScopeAllRecreatable)
        };
    }

    public static bool Normalize(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        string mode = NormalizeMode(settings.PerformanceMode);
        int hiddenDelay = NormalizeHiddenCacheCleanupDelaySeconds(
            settings.HiddenCacheCleanupDelaySeconds);
        int visibleIdleDelay = NormalizeVisibleIdleCacheCleanupDelaySeconds(
            settings.VisibleIdleCacheCleanupDelaySeconds);
        int transientWindowDelay = NormalizeTransientWindowReleaseDelaySeconds(
            settings.TransientWindowReleaseDelaySeconds);
        string cacheBudget = NormalizeCacheBudget(settings.PerformanceCacheBudget);
        string hiddenCleanupScope = NormalizeHiddenCacheCleanupScope(
            settings.HiddenCacheCleanupScope);
        bool allowTextMarqueeAnimations =
            settings.EnableTextMarqueeAnimations;
        bool allowVinylRotationAnimations =
            settings.EnableVinylRotationAnimations;
        bool allowGlanceImageAutoRotation =
            settings.EnableGlanceImageAutoRotation;
        bool allowCompactAmbientAnimations =
            settings.EnableCompactAmbientAnimations;

        if (!string.Equals(mode, ModeCustom, StringComparison.Ordinal))
        {
            EffectivePerformanceSettings preset = ResolvePreset(mode);
            hiddenDelay = preset.HiddenCacheCleanupDelaySeconds;
            visibleIdleDelay = preset.VisibleIdleCacheCleanupDelaySeconds;
            transientWindowDelay = preset.TransientWindowReleaseDelaySeconds;
            cacheBudget = preset.CacheBudget;
            hiddenCleanupScope = preset.HiddenCacheCleanupScope;
        }

        bool changed = false;
        changed |= SetIfChanged(settings.PerformanceMode, mode, value =>
            settings.PerformanceMode = value);
        changed |= SetIfChanged(
            settings.HiddenCacheCleanupDelaySeconds,
            hiddenDelay,
            value => settings.HiddenCacheCleanupDelaySeconds = value);
        changed |= SetIfChanged(
            settings.VisibleIdleCacheCleanupDelaySeconds,
            visibleIdleDelay,
            value => settings.VisibleIdleCacheCleanupDelaySeconds = value);
        changed |= SetIfChanged(
            settings.TransientWindowReleaseDelaySeconds,
            transientWindowDelay,
            value => settings.TransientWindowReleaseDelaySeconds = value);
        changed |= SetIfChanged(
            settings.PerformanceCacheBudget,
            cacheBudget,
            value => settings.PerformanceCacheBudget = value);
        changed |= SetIfChanged(
            settings.HiddenCacheCleanupScope,
            hiddenCleanupScope,
            value => settings.HiddenCacheCleanupScope = value);
        changed |= SetIfChanged(
            settings.EnableTextMarqueeAnimations,
            allowTextMarqueeAnimations,
            value => settings.EnableTextMarqueeAnimations = value);
        changed |= SetIfChanged(
            settings.EnableVinylRotationAnimations,
            allowVinylRotationAnimations,
            value => settings.EnableVinylRotationAnimations = value);
        changed |= SetIfChanged(
            settings.EnableGlanceImageAutoRotation,
            allowGlanceImageAutoRotation,
            value => settings.EnableGlanceImageAutoRotation = value);
        changed |= SetIfChanged(
            settings.EnableCompactAmbientAnimations,
            allowCompactAmbientAnimations,
            value => settings.EnableCompactAmbientAnimations = value);
        bool legacyDecorativeAnimationsEnabled =
            allowTextMarqueeAnimations &&
            allowVinylRotationAnimations &&
            allowGlanceImageAutoRotation &&
            allowCompactAmbientAnimations;
        changed |= SetIfChanged(
            settings.EnableContinuousDecorativeAnimations,
            legacyDecorativeAnimationsEnabled,
            value => settings.EnableContinuousDecorativeAnimations = value);
        return changed;
    }

    public static void ApplyPreset(AppSettings settings, string? mode)
    {
        ArgumentNullException.ThrowIfNull(settings);

        settings.PerformanceMode = NormalizeMode(mode);
        if (string.Equals(
                settings.PerformanceMode,
                ModeCustom,
                StringComparison.Ordinal))
        {
            settings.HiddenCacheCleanupDelaySeconds =
                NormalizeHiddenCacheCleanupDelaySeconds(
                    settings.HiddenCacheCleanupDelaySeconds);
            settings.VisibleIdleCacheCleanupDelaySeconds =
                NormalizeVisibleIdleCacheCleanupDelaySeconds(
                    settings.VisibleIdleCacheCleanupDelaySeconds);
            settings.TransientWindowReleaseDelaySeconds =
                NormalizeTransientWindowReleaseDelaySeconds(
                    settings.TransientWindowReleaseDelaySeconds);
            settings.PerformanceCacheBudget =
                NormalizeCacheBudget(settings.PerformanceCacheBudget);
            settings.HiddenCacheCleanupScope =
                NormalizeHiddenCacheCleanupScope(
                    settings.HiddenCacheCleanupScope);
            settings.EnableContinuousDecorativeAnimations =
                settings.EnableTextMarqueeAnimations &&
                settings.EnableVinylRotationAnimations &&
                settings.EnableGlanceImageAutoRotation &&
                settings.EnableCompactAmbientAnimations;
            return;
        }

        EffectivePerformanceSettings preset = ResolvePreset(
            settings.PerformanceMode);
        settings.HiddenCacheCleanupDelaySeconds =
            preset.HiddenCacheCleanupDelaySeconds;
        settings.VisibleIdleCacheCleanupDelaySeconds =
            preset.VisibleIdleCacheCleanupDelaySeconds;
        settings.TransientWindowReleaseDelaySeconds =
            preset.TransientWindowReleaseDelaySeconds;
        settings.PerformanceCacheBudget = preset.CacheBudget;
        settings.HiddenCacheCleanupScope = preset.HiddenCacheCleanupScope;
        settings.EnableContinuousDecorativeAnimations =
            settings.EnableTextMarqueeAnimations &&
            settings.EnableVinylRotationAnimations &&
            settings.EnableGlanceImageAutoRotation &&
            settings.EnableCompactAmbientAnimations;
    }

    private static EffectivePerformanceSettings ResolvePreset(string mode)
    {
        var settings = new AppSettings
        {
            PerformanceMode = mode
        };
        return Resolve(settings);
    }

    private static EffectivePerformanceSettings ResolveCustom(
        AppSettings settings)
    {
        int hiddenDelay = NormalizeHiddenCacheCleanupDelaySeconds(
            settings.HiddenCacheCleanupDelaySeconds);
        int deepDelay = hiddenDelay switch
        {
            CleanupAfter5Minutes => CleanupAfter10Minutes,
            _ => CleanupAfter5Minutes
        };
        string cacheBudget = NormalizeCacheBudget(
            settings.PerformanceCacheBudget);
        return new(
            ModeCustom,
            hiddenDelay,
            deepDelay,
            settings.EnableTextMarqueeAnimations,
            settings.EnableVinylRotationAnimations,
            settings.EnableGlanceImageAutoRotation,
            settings.EnableCompactAmbientAnimations,
            NormalizeVisibleIdleCacheCleanupDelaySeconds(
                settings.VisibleIdleCacheCleanupDelaySeconds),
            NormalizeTransientWindowReleaseDelaySeconds(
                settings.TransientWindowReleaseDelaySeconds),
            cacheBudget,
            NormalizeHiddenCacheCleanupScope(
                settings.HiddenCacheCleanupScope));
    }

    private static bool SetIfChanged<T>(
        T current,
        T value,
        Action<T> setter)
    {
        if (EqualityComparer<T>.Default.Equals(current, value))
        {
            return false;
        }

        setter(value);
        return true;
    }
}
