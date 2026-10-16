// Illustrative synthetic data only. These are normalized teaching examples,
// not verbatim Windows log records, a real tenant, or the user's diagnostics.
// All timestamps are UTC. IDs are fictional pseudonyms. A shared trace ID is
// assigned for this demo; real investigations must establish each correlation.
export const scenarios = [
  {
    id: 'win32',
    shortLabel: 'Win32 apps',
    category: 'WIN32 APP DEPLOYMENT',
    title: 'Install succeeded. Detection failed.',
    subtitle: 'Follow a required app from assignment through SYSTEM installation to its detection result.',
    code: '0x87D1041C',
    severity: 'error',
    traceId: '[id:trace-win32-demo-01]',
    expectedSources: [
      { name: 'AppWorkload.log', available: true, note: 'Synthetic assignment, dependency, and detection records.' },
      { name: 'IntuneManagementExtension.log', available: true, note: 'Synthetic policy retrieval and execution-context records.' },
      { name: 'AppActionProcessor.log', available: true, note: 'Synthetic install command, installer output, and exit code.' },
      { name: 'Intune app configuration export', available: true, note: 'Illustrative snapshot of the configured detection rule.' }
    ],
    events: [
      { id: 'w1', time: '2026-10-13T08:00:00Z', source: 'AppWorkload.log', line: 102, stage: 'assignment', context: 'Device assignment', code: 'REQUIRED', message: 'Required app [id:app-demo-01] applies to device [id:device-demo-01]. Assignment filter passed.', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w2', time: '2026-10-13T08:00:03Z', source: 'IntuneManagementExtension.log', line: 241, stage: 'policy', context: 'SYSTEM', code: 'POLICY_RECEIVED', message: 'App policy [id:app-demo-01] received. Install behavior: System. No user session is required.', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w3', time: '2026-10-13T08:00:04Z', source: 'Intune app configuration export', line: 18, stage: 'policy', context: '64-bit file detection', code: 'DETECTION_RULE', message: 'Configured rule: C:\\Program Files\\DemoDeskLegacy\\DemoDesk.exe must exist with file version >= 5.5.0.', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w4', time: '2026-10-13T08:00:06Z', source: 'AppWorkload.log', line: 121, stage: 'execution', context: 'SYSTEM', code: 'DEPENDENCIES_MET', message: 'Dependency [id:dependency-demo-01] detected successfully. Requirements passed for app [id:app-demo-01].', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w5', time: '2026-10-13T08:00:08Z', source: 'AppActionProcessor.log', line: 307, stage: 'execution', context: 'SYSTEM', code: 'INSTALL_STARTED', message: 'Install command for [id:app-demo-01]: msiexec.exe /i DemoDesk-5.4.1.msi /qn /norestart. Working directory: IME content cache.', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w6', time: '2026-10-13T08:01:12Z', source: 'AppActionProcessor.log', line: 328, stage: 'execution', context: 'SYSTEM', code: '0', message: 'Installer returned exit code 0 (success). Installer output reports C:\\Program Files\\DemoDesk\\DemoDesk.exe, file version 5.4.1.', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w7', time: '2026-10-13T08:01:15Z', source: 'AppWorkload.log', line: 151, stage: 'result', context: 'SYSTEM / 64-bit detection', code: 'DETECTION_FALSE', message: 'Post-install detection: C:\\Program Files\\DemoDeskLegacy\\DemoDesk.exe was not found. Version predicate was not evaluated because the target file is absent.', correlationId: '[id:trace-win32-demo-01]' },
      { id: 'w8', time: '2026-10-13T08:01:16Z', source: 'AppWorkload.log', line: 156, stage: 'result', context: 'SYSTEM', code: '0x87D1041C', message: 'App [id:app-demo-01] was not detected after installation completed successfully.', correlationId: '[id:trace-win32-demo-01]' }
    ],
    findings: [
      {
        id: 'wf1', title: 'Detection rule does not describe the installed package', severity: 'error', confidence: 'High',
        observation: 'The installer returned success and reported DemoDesk 5.4.1 in the DemoDesk folder. Detection checked the absent DemoDeskLegacy path and required version 5.5.0 or higher.',
        rootCause: 'The recorded detection configuration is inconsistent with the installed package. The absent configured path directly explains this failed detection. The version threshold would also reject the reported 5.4.1 version if that file were checked.',
        evidenceIds: ['w3', 'w5', 'w6', 'w7', 'w8'],
        checks: [
          'Inspect the configured detection path, filename, minimum version, and 32-bit/64-bit setting without editing them.',
          'Read the installed file version and path under the same SYSTEM context used by detection.',
          'Confirm the intended package version with the application owner; verify whether 5.4.1 or 5.5.0 was approved.'
        ],
        recommendations: [
          'Prepare a reviewed proposal to align package version and detection criteria with the approved application version.',
          'Validate that proposal on a separate test device before any production change.',
          'Track installer success and detection success separately. If a future run returns 3010, interpret the configured return-code mapping; it commonly means success with a reboot required.'
        ]
      }
    ],
    stageNote: {
      collect: 'Inspect the example log inventory and configured rule. The demo reads synthetic records only.',
      correlate: 'Link the same app, device, SYSTEM context, and UTC install window across assignment, policy, execution, and result.',
      findings: 'Compare installer output with the exact detection predicate. A successful install can still produce a detection failure.',
      review: 'Review proposed checks and an isolated validation plan. No installation, rule change, cleanup, or reboot is performed.'
    }
  },
  {
    id: 'patching',
    shortLabel: 'Windows updates',
    category: 'WINDOWS PATCHING',
    title: 'Update scan stopped at name resolution.',
    subtitle: 'Separate policy delivery from an update scan failure and look for corroborating network evidence.',
    code: '0x80072EE7',
    severity: 'error',
    traceId: '[id:trace-update-demo-01]',
    expectedSources: [
      { name: 'DeviceManagement-Enterprise-Diagnostics-Provider → Admin', available: true, note: 'Synthetic update-ring policy delivery records.' },
      { name: 'WindowsUpdateClient → Operational', available: true, note: 'Synthetic scan and scan-failure events.' },
      { name: 'C:\\Windows\\Logs\\UpdateOrchestrator\\', available: true, note: 'Synthetic orchestration and endpoint-resolution records.' },
      { name: 'C:\\Windows\\Logs\\CBS\\CBS.log', available: false, note: 'Not included in this example; servicing corruption cannot be assessed from these records.' }
    ],
    events: [
      { id: 'p1', time: '2026-10-13T09:00:00Z', source: 'DeviceManagement-Enterprise-Diagnostics-Provider → Admin', line: 411, stage: 'assignment', context: 'Device MDM policy', code: 'RING_ASSIGNED', message: 'Update ring [id:ring-demo-01] targets device [id:device-demo-02]. Assignment applies.', correlationId: '[id:trace-update-demo-01]' },
      { id: 'p2', time: '2026-10-13T09:00:05Z', source: 'DeviceManagement-Enterprise-Diagnostics-Provider → Admin', line: 416, stage: 'policy', context: 'Device / Update CSP', code: 'POLICY_APPLIED', message: 'Delivered ring settings: quality-update deferral 3 days; deadline 7 days; grace period 2 days. MDM policy application reported success.', correlationId: '[id:trace-update-demo-01]' },
      { id: 'p3', time: '2026-10-13T09:02:00Z', source: 'C:\\Windows\\Logs\\UpdateOrchestrator\\', line: 70, stage: 'execution', context: 'SYSTEM', code: 'SCAN_REQUESTED', message: 'UpdateOrchestrator requested an update scan for device [id:device-demo-02].', correlationId: '[id:trace-update-demo-01]' },
      { id: 'p4', time: '2026-10-13T09:02:02Z', source: 'WindowsUpdateClient → Operational', line: 84, stage: 'execution', context: 'SYSTEM / Windows Update service', code: 'SCAN_STARTED', message: 'Windows Update began the scan requested at 09:02:00 UTC.', correlationId: '[id:trace-update-demo-01]' },
      { id: 'p5', time: '2026-10-13T09:02:07Z', source: 'C:\\Windows\\Logs\\UpdateOrchestrator\\', line: 91, stage: 'execution', context: 'SYSTEM / service network path', code: '0x80072EE7', message: 'Request to the recorded update endpoint failed: endpoint hostname could not be resolved. No download started.', correlationId: '[id:trace-update-demo-01]' },
      { id: 'p6', time: '2026-10-13T09:02:08Z', source: 'WindowsUpdateClient → Operational', line: 98, stage: 'result', context: 'SYSTEM / Windows Update service', code: '0x80072EE7', message: 'Scan failed: name or address could not be resolved. No applicable-update result was produced.', correlationId: '[id:trace-update-demo-01]' },
      { id: 'p7', time: '2026-10-13T09:02:09Z', source: 'C:\\Windows\\Logs\\UpdateOrchestrator\\', line: 97, stage: 'result', context: 'SYSTEM', code: 'SCAN_ABORTED', message: 'Scan ended before download or installation. This trace contains no servicing attempt or reboot decision.', correlationId: '[id:trace-update-demo-01]' }
    ],
    findings: [
      {
        id: 'pf1', title: 'Name-resolution failure blocks the update scan', severity: 'error', confidence: 'High',
        observation: 'WindowsUpdateClient and UpdateOrchestrator report 0x80072EE7 within the same scan window. The update-ring policy was delivered before the failure.',
        rootCause: 'The observed failure occurs while resolving the recorded update endpoint, before download or servicing. These records do not establish whether DNS configuration, proxy routing, or upstream availability caused the resolution failure.',
        evidenceIds: ['p2', 'p3', 'p4', 'p5', 'p6', 'p7'],
        checks: [
          'Read the exact endpoint hostname from the full failing request and verify name resolution on the affected network.',
          'Inspect effective WinHTTP proxy settings and compare service-context connectivity with user-context connectivity.',
          'Inspect effective update policy for conflicting MDM, Group Policy, or WSUS settings; policy delivery alone does not exclude a conflict.'
        ],
        recommendations: [
          'Share the failing hostname, UTC timestamps, and resolution evidence with the network or proxy owner for a reviewed correction.',
          'After an approved network change, validate one scan on a test device and compare the result with this trace.',
          'Assess deadline and reboot behavior only after scan and installation succeed. No update reset, cache deletion, service change, or forced restart is proposed by this demo.'
        ]
      }
    ],
    stageNote: {
      collect: 'Read the example update-policy and scan logs. Notice that CBS evidence is unavailable.',
      correlate: 'Connect successful policy delivery to the later scan, then compare the matching error and UTC timestamps.',
      findings: 'The supported failure stage is name resolution. Servicing corruption is not established by this scan error.',
      review: 'Review DNS, proxy, and effective-policy checks. Preserve existing settings and validate one approved change at a time.'
    }
  },
  {
    id: 'conditional-access',
    shortLabel: 'Conditional Access',
    category: 'CONDITIONAL ACCESS',
    title: 'A compliant-device requirement blocked sign-in.',
    subtitle: 'Inspect the enforced policy result, authentication details, and the age of the available compliance evidence.',
    code: 'AADSTS53000',
    severity: 'error',
    traceId: '[id:trace-ca-demo-01]',
    expectedSources: [
      { name: 'Microsoft Entra ID → Sign-in logs → Conditional Access', available: true, note: 'Synthetic sign-in details and per-policy evaluation results.' },
      { name: 'Microsoft Intune → Device compliance report', available: true, note: 'Synthetic pending snapshot, recorded two hours before sign-in.' },
      { name: 'dsregcmd /status export', available: false, note: 'No local join-state export is included; current device state is not inferred.' }
    ],
    events: [
      { id: 'c1', time: '2026-10-13T09:45:00Z', source: 'Microsoft Intune → Device compliance report', line: 12, stage: 'policy', context: 'Device [id:device-demo-03]', code: 'PENDING', message: 'Last recorded compliance snapshot: Pending for [id:device-demo-03]. Snapshot is two hours older than the later sign-in; no newer Intune result is included.', correlationId: '[id:trace-ca-demo-01]' },
      { id: 'c2', time: '2026-10-13T11:45:00Z', source: 'Microsoft Entra ID → Sign-in logs → Conditional Access', line: 21, stage: 'assignment', context: 'User [id:user-demo-01] / application [id:resource-demo-01]', code: 'SIGN_IN_STARTED', message: 'Sign-in [id:signin-demo-01] evaluated for device [id:device-demo-03]. Recorded device detail: isManaged=true, isCompliant=false, trustType=AzureAD.', correlationId: '[id:trace-ca-demo-01]' },
      { id: 'c3', time: '2026-10-13T11:45:01Z', source: 'Microsoft Entra ID → Sign-in logs → Conditional Access', line: 25, stage: 'execution', context: 'Authentication details', code: 'MFA_CLAIM_SATISFIED', message: 'Authentication detail: MFA requirement satisfied by claim in the token. This example records no failed MFA step.', correlationId: '[id:trace-ca-demo-01]' },
      { id: 'c4', time: '2026-10-13T11:45:02Z', source: 'Microsoft Entra ID → Sign-in logs → Conditional Access', line: 30, stage: 'policy', context: 'Enabled policy [id:ca-policy-demo-01]', code: 'FAILURE', message: 'Enforced policy "Require compliant device": state=enabled; grant control=requireCompliantDevice; result=failure. The sign-in did not satisfy the compliant-device requirement.', correlationId: '[id:trace-ca-demo-01]' },
      { id: 'c5', time: '2026-10-13T11:45:02Z', source: 'Microsoft Entra ID → Sign-in logs → Conditional Access', line: 34, stage: 'policy', context: 'Report-only policy [id:ca-policy-demo-02]', code: 'REPORT_ONLY_FAILURE', message: 'Policy "Evaluate hybrid join": state=enabledForReportingButNotEnforced; grant control=requireDomainJoinedDevice; result=reportOnlyFailure. This policy result did not enforce a block.', correlationId: '[id:trace-ca-demo-01]' },
      { id: 'c6', time: '2026-10-13T11:45:03Z', source: 'Microsoft Entra ID → Sign-in logs → Conditional Access', line: 39, stage: 'result', context: 'Sign-in [id:signin-demo-01]', code: 'AADSTS53000', message: 'Sign-in failed: device not compliant. Conditional Access status=failure for the enforced compliant-device requirement.', correlationId: '[id:trace-ca-demo-01]' }
    ],
    findings: [
      {
        id: 'cf1', title: 'The enforced policy did not receive acceptable compliance evidence', severity: 'error', confidence: 'High',
        observation: 'The sign-in recorded isCompliant=false and failed the enabled requireCompliantDevice control with AADSTS53000. The available Intune report recorded Pending two hours earlier.',
        rootCause: 'This sign-in did not present a compliant-device claim accepted by the enforced policy. The older Pending snapshot helps identify what to investigate, but does not establish the device’s current compliance state or the underlying failing compliance rule.',
        evidenceIds: ['c1', 'c2', 'c4', 'c6'],
        checks: [
          'Match the sign-in device ID to the Intune device record and inspect the latest per-setting compliance results and check-in time.',
          'Inspect a redacted dsregcmd /status export to verify current Entra join state and token-related device identity.',
          'Review the enabled policy’s grant controls, targeted resource, assignments, and authentication details for this exact sign-in.'
        ],
        recommendations: [
          'Investigate the specific pending or failed compliance setting and propose a reviewed resolution once fresh evidence is available.',
          'Validate a subsequent sign-in after the approved resolution; retain the before-and-after sign-in correlation IDs.',
          'Keep the compliant-device requirement in place during investigation. No policy bypass, device-state change, or credential action is performed.'
        ]
      },
      {
        id: 'cf2', title: 'Report-only and MFA results identify separate checks', severity: 'warning', confidence: 'High',
        observation: 'The hybrid-join policy produced reportOnlyFailure, while the authentication details say MFA was satisfied by a token claim.',
        rootCause: 'The report-only result was not an enforcing block, and the compliance failure does not establish an MFA failure. The recorded block is attributed to the enabled compliant-device policy.',
        evidenceIds: ['c3', 'c4', 'c5', 'c6'],
        checks: [
          'Read each Conditional Access policy’s state and result separately; distinguish failure from reportOnlyFailure.',
          'Use the sign-in authentication details to assess MFA, instead of inferring an MFA result from the compliance error.'
        ],
        recommendations: [
          'Use AADSTS53000 for this compliance investigation. AADSTS53001 indicates a device-join requirement issue; AADSTS53003 indicates a Conditional Access block and needs policy-detail review.',
          'Document report-only findings for policy review without treating them as the cause of this enforced block.'
        ]
      }
    ],
    stageNote: {
      collect: 'Use example cloud exports. Conditional Access decisions come from Entra sign-in logs, not a local Windows log alone.',
      correlate: 'Match device and sign-in IDs, then compare policy mode, authentication detail, and compliance snapshot age.',
      findings: 'Identify the enforcing grant control. An older compliance snapshot cannot prove current state, and a report-only result does not block.',
      review: 'Review fresh compliance and join-state evidence. Preserve access policies while preparing a resolution proposal.'
    }
  },
  {
    id: 'autopilot',
    shortLabel: 'Autopilot & ESP',
    category: 'WINDOWS AUTOPILOT & ESP',
    title: 'ESP timed out while a blocking app stayed undetected.',
    subtitle: 'Trace a valid profile and enrollment through the required application that held the enrollment status page.',
    code: '0x800705B4',
    severity: 'error',
    traceId: '[id:trace-autopilot-demo-01]',
    expectedSources: [
      { name: 'ModernDeployment-Diagnostics-Provider → Autopilot', available: true, note: 'Synthetic profile, TPM-attestation, and ESP records.' },
      { name: 'DeviceManagement-Enterprise-Diagnostics-Provider → Admin', available: true, note: 'Synthetic successful MDM-enrollment record.' },
      { name: 'Provisioning-Diagnostics-Provider → Admin', available: true, note: 'Synthetic provisioning-stage timeout record.' },
      { name: 'AppWorkload.log / AppActionProcessor.log', available: true, note: 'Synthetic blocking-app installation and detection evidence.' },
      { name: 'Autopilot diagnostic CAB', available: false, note: 'Not collected by the demo. A real CAB may contain sensitive identifiers and must be reviewed before sharing.' }
    ],
    events: [
      { id: 'a1', time: '2026-10-13T12:00:00Z', source: 'ModernDeployment-Diagnostics-Provider → Autopilot', line: 42, stage: 'assignment', context: 'Device [id:device-demo-04]', code: 'PROFILE_ASSIGNED', message: 'Registered Autopilot device [id:device-demo-04] received assigned profile [id:profile-demo-01]. Profile download succeeded.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a2', time: '2026-10-13T12:01:00Z', source: 'ModernDeployment-Diagnostics-Provider → Autopilot', line: 59, stage: 'execution', context: 'Device provisioning', code: 'TPM_ATTESTATION_SUCCESS', message: 'TPM attestation completed successfully in this deployment. No TPM failure is recorded in the example.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a3', time: '2026-10-13T12:02:00Z', source: 'DeviceManagement-Enterprise-Diagnostics-Provider → Admin', line: 111, stage: 'execution', context: 'Device MDM enrollment', code: 'ENROLLMENT_SUCCESS', message: 'MDM enrollment completed for device [id:device-demo-04]. Device-management policy retrieval succeeded.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a4', time: '2026-10-13T12:03:00Z', source: 'ModernDeployment-Diagnostics-Provider → Autopilot', line: 71, stage: 'policy', context: 'Device ESP / SYSTEM apps', code: 'BLOCKING_APP', message: 'ESP profile [id:esp-demo-01] tracks required blocking app [id:app-demo-esp-01]. App completion requires successful detection. ESP timeout is 30 minutes.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a5', time: '2026-10-13T12:05:00Z', source: 'AppActionProcessor.log', line: 206, stage: 'execution', context: 'SYSTEM', code: '0', message: 'Blocking app [id:app-demo-esp-01] installer returned exit code 0. Installer output reports C:\\Program Files\\DemoAgent\\DemoAgent.exe, file version 2.1.0.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a6', time: '2026-10-13T12:05:03Z', source: 'AppWorkload.log', line: 220, stage: 'result', context: 'SYSTEM / 64-bit file detection', code: '0x87D1041C', message: 'App [id:app-demo-esp-01] not detected after successful installation. Configured target C:\\Program Files\\DemoAgentLegacy\\DemoAgent.exe is absent; installer reported the DemoAgent folder.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a7', time: '2026-10-13T12:32:55Z', source: 'ModernDeployment-Diagnostics-Provider → Autopilot', line: 129, stage: 'result', context: 'Device ESP', code: 'APP_NOT_COMPLETE', message: 'ESP still waits for blocking app [id:app-demo-esp-01]. No later successful detection is recorded. Remaining tracked blocking apps are complete.', correlationId: '[id:trace-autopilot-demo-01]' },
      { id: 'a8', time: '2026-10-13T12:33:00Z', source: 'Provisioning-Diagnostics-Provider → Admin', line: 149, stage: 'result', context: 'Device ESP', code: '0x800705B4', message: 'Provisioning operation timed out at the configured ESP limit. Blocking app [id:app-demo-esp-01] remained incomplete.', correlationId: '[id:trace-autopilot-demo-01]' }
    ],
    findings: [
      {
        id: 'af1', title: 'A blocking app’s detection failure explains the ESP wait', severity: 'error', confidence: 'High',
        observation: 'ESP tracked [id:app-demo-esp-01] as a blocking app. Its installer succeeded, detection checked an absent path, and the same app remained incomplete immediately before the ESP timeout.',
        rootCause: 'The recorded detection target differs from the installed location, leaving the blocking app undetected and preventing ESP completion in this trace. 0x800705B4 is the resulting timeout; by itself, it would not identify the underlying blocker.',
        evidenceIds: ['a4', 'a5', 'a6', 'a7', 'a8'],
        checks: [
          'Match the app ID in the ESP blocking list with IME install and detection records, including SYSTEM context and timestamps.',
          'Inspect the configured detection path and read the installed file path and version without changing them.',
          'If further evidence is needed, review a securely handled Autopilot diagnostic CAB and the full provisioning window for additional blockers.'
        ],
        recommendations: [
          'Prepare a reviewed detection-rule or packaging proposal for the approved app, then validate it in a separate Autopilot test deployment.',
          'Validate successful blocking-app detection before considering whether the ESP time limit needs an approved change.',
          'Preserve the recorded successful profile, enrollment, and TPM evidence. This finding does not justify a TPM clear, device reset, profile removal, or enrollment deletion.'
        ]
      }
    ],
    stageNote: {
      collect: 'Inspect the example Autopilot, MDM, provisioning, and IME sources. The demo creates no diagnostic CAB.',
      correlate: 'Follow the assigned profile and successful enrollment to the exact app ID in the ESP blocking list.',
      findings: 'Use the app detection evidence to explain the timeout. Successful TPM attestation is not a TPM-failure signal.',
      review: 'Review the app validation plan and handling of sensitive diagnostics. No reset, deletion, or configuration change is performed.'
    }
  }
];
