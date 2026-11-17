# Knowledge sources and diagnostic KPI definitions

Reviewed 2 November 2026. Added in version 1.6.0.

## Source selection and reuse

The implementation uses original JavaScript and original investigation guidance based on factual code/status meanings from Microsoft primary sources. No third-party scripts, SDK headers, diagnostic executables or automatic repair routines are bundled or executed. Source links are static and reviewed; importing logs does not fetch those pages.

| Source | Added coverage | Reference |
| --- | --- | --- |
| Microsoft public Windows SDK header in microsoft/win32metadata | 0x80240016, 0x80240017, 0x8024001F, 0x8024401B, 0x80246007, 0x80246008 | [Pinned SDK mapping](https://github.com/microsoft/win32metadata/blob/c16762d41f1bd641ff8c4389ebf16ee50747129f/generation/WinSDK/RecompiledIdlHeaders/um/wuerror.h) · [Windows Update reference](https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-error-reference) |
| Microsoft AppX/MSIX troubleshooting documentation | 0x80073CF3, 0x80073D02, 0x80073D06, 0x80073D10 | [Package deployment results](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting) |
| Microsoft Entra dsregcmd status documentation | DeviceAuthStatus FAILED, FAILED. ERROR, AzureAdPrt NO | [Device status semantics](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd) |

The checked Windows Update header blob SHA was `bcffe48e4f44c05a4d0c33cba57acc98059eadac`, at path commit `c16762d41f1bd641ff8c4389ebf16ee50747129f`. The public repository's [license](https://github.com/microsoft/win32metadata/blob/main/LICENSE) explicitly preserves original SDK header licensing. No header code or message table was copied; this app implements a selected factual mapping with separately authored text. Microsoft Learn content is linked for verification, not mirrored.

The new knowledge entries include source identity, reference and review date. The existing catalog is preserved. A recognized code establishes its documented meaning, not the device's current state or the underlying cause. The four AppX entries appear under the existing software-delivery workstream labeled Win32 apps; they do not imply AppX is an MSI/Win32 package.

## KPIs implemented in this app

These formulas are app-defined measures of the currently visible imported evidence. They are not copied health/accuracy scores from another project.

- **Explained signal coverage:** unique records linked to a recognized local rule / (unique rule-explained records + unique unexplained signal records not also rule-explained). Ordinary records and findings retaining only the supplied report's interpretation are outside the denominator. Informational rules can count as explained signals.
- **Priority evidence timed:** unique visible linked records with usable UTC timestamps / unique visible linked records of error/high/critical findings. It does not count findings as devices or imply complete priority evidence; unlinked findings require separate review.
- **Shared identifiers across sources:** distinct `(report ID, identifier)` pairs found in at least two source names in the current selection. Duplicate identifiers within one record count once. Different reports are never joined. An identifier may identify a device, application or tenant rather than one operation. Up to five leads show record/source counts. The index examines at most 100,000 identifier references; a capped result is explicitly a lower bound. Unscoped records are not indexed.

All metrics recompute after filtering. Percentages with an empty eligible denominator show an em dash. These metrics supplement Analysis readiness and archive coverage; they cannot establish completeness, successful remediation, retries or causation.

## Verification

The in-app built-in suite now has 73 synthetic checks, including all 13 additions and negative cases for successful states, quoted documentation and configured return-code mappings. Repository tests additionally exercise HRESULT representations, cross-report identifier isolation, filtered/deduplicated denominators, capped indexing, safe source rendering and exported links. Synthetic examples remain separate from imported endpoint evidence.
