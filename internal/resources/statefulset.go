/*
Copyright 2026 OpenClaw.rocks

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	openclawv1alpha1 "github.com/openclawrocks/k8s-operator/api/v1alpha1"
)

// BuildStatefulSet creates a StatefulSet for the OpenClawInstance
func BuildStatefulSet(instance *openclawv1alpha1.OpenClawInstance) *appsv1.StatefulSet {
	labels := Labels(instance)
	selectorLabels := SelectorLabels(instance)

	// Calculate config hash for rollout trigger
	configHash := calculateConfigHash(instance)

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      StatefulSetName(instance),
			Namespace: instance.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:             Ptr(int32(1)), // OpenClaw is single-instance
			RevisionHistoryLimit: Ptr(int32(10)),
			ServiceName:          ServiceName(instance),
			PodManagementPolicy:  appsv1.ParallelPodManagement,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: selectorLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"openclaw.rocks/config-hash": configHash,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            ServiceAccountName(instance),
					SecurityContext:               buildPodSecurityContext(instance),
					InitContainers:                buildInitContainers(instance),
					Containers:                    buildContainers(instance),
					Volumes:                       buildVolumes(instance),
					NodeSelector:                  instance.Spec.Availability.NodeSelector,
					Tolerations:                   instance.Spec.Availability.Tolerations,
					Affinity:                      instance.Spec.Availability.Affinity,
					RestartPolicy:                 corev1.RestartPolicyAlways,
					DNSPolicy:                     corev1.DNSClusterFirst,
					SchedulerName:                 corev1.DefaultSchedulerName,
					TerminationGracePeriodSeconds: Ptr(int64(30)),
				},
			},
		},
	}

	// Add image pull secrets
	sts.Spec.Template.Spec.ImagePullSecrets = append(
		sts.Spec.Template.Spec.ImagePullSecrets,
		instance.Spec.Image.PullSecrets...,
	)

	return sts
}

// buildPodSecurityContext creates the pod-level security context
func buildPodSecurityContext(instance *openclawv1alpha1.OpenClawInstance) *corev1.PodSecurityContext {
	psc := &corev1.PodSecurityContext{
		RunAsNonRoot: Ptr(true),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}

	// RunAsRoot shortcut: run everything as UID 0
	if instance.Spec.Security.RunAsRoot {
		psc.RunAsUser = Ptr(int64(0))
		psc.RunAsGroup = Ptr(int64(0))
		psc.FSGroup = Ptr(int64(0))
		psc.RunAsNonRoot = Ptr(false)
		return psc
	}

	// Apply user overrides or defaults
	spec := instance.Spec.Security.PodSecurityContext
	if spec != nil {
		if spec.RunAsUser != nil {
			psc.RunAsUser = spec.RunAsUser
		} else {
			psc.RunAsUser = Ptr(int64(1000))
		}
		if spec.RunAsGroup != nil {
			psc.RunAsGroup = spec.RunAsGroup
		} else {
			psc.RunAsGroup = Ptr(int64(1000))
		}
		if spec.FSGroup != nil {
			psc.FSGroup = spec.FSGroup
		} else {
			psc.FSGroup = Ptr(int64(1000))
		}
		if spec.RunAsNonRoot != nil {
			psc.RunAsNonRoot = spec.RunAsNonRoot
		}
	} else {
		psc.RunAsUser = Ptr(int64(1000))
		psc.RunAsGroup = Ptr(int64(1000))
		psc.FSGroup = Ptr(int64(1000))
	}

	return psc
}

// buildContainerSecurityContext creates the container-level security context
func buildContainerSecurityContext(instance *openclawv1alpha1.OpenClawInstance) *corev1.SecurityContext {
	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: Ptr(false),
		ReadOnlyRootFilesystem:   Ptr(false), // OpenClaw writes to ~/.openclaw/
		RunAsNonRoot:             Ptr(true),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}

	// RunAsRoot shortcut: remove capability restrictions so the container
	// can install packages, switch users, etc.
	if instance.Spec.Security.RunAsRoot {
		sc.RunAsNonRoot = Ptr(false)
		sc.RunAsUser = Ptr(int64(0))
		sc.Capabilities = &corev1.Capabilities{} // don't drop ALL
		return sc
	}

	// Apply user overrides
	spec := instance.Spec.Security.ContainerSecurityContext
	if spec != nil {
		if spec.AllowPrivilegeEscalation != nil {
			sc.AllowPrivilegeEscalation = spec.AllowPrivilegeEscalation
		}
		if spec.ReadOnlyRootFilesystem != nil {
			sc.ReadOnlyRootFilesystem = spec.ReadOnlyRootFilesystem
		}
		if spec.RunAsNonRoot != nil {
			sc.RunAsNonRoot = spec.RunAsNonRoot
		}
		if spec.RunAsUser != nil {
			sc.RunAsUser = spec.RunAsUser
		}
		if spec.Capabilities != nil {
			sc.Capabilities = spec.Capabilities
		}
	}

	return sc
}

// buildInitSecurityContext creates the security context for init containers.
// It inherits runAsNonRoot/runAsUser from the pod-level overrides so that init
// containers don't conflict when the user runs as root.
func buildInitSecurityContext(instance *openclawv1alpha1.OpenClawInstance) *corev1.SecurityContext {
	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: Ptr(false),
		ReadOnlyRootFilesystem:   Ptr(true),
		RunAsNonRoot:             Ptr(true),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}

	// RunAsRoot shortcut
	if instance.Spec.Security.RunAsRoot {
		sc.RunAsNonRoot = Ptr(false)
		sc.RunAsUser = Ptr(int64(0))
		return sc
	}

	// Inherit user overrides from pod/container security context
	spec := instance.Spec.Security.ContainerSecurityContext
	if spec != nil {
		if spec.RunAsNonRoot != nil {
			sc.RunAsNonRoot = spec.RunAsNonRoot
		}
		if spec.RunAsUser != nil {
			sc.RunAsUser = spec.RunAsUser
		}
	}

	return sc
}

// buildContainers creates the container specs
func buildContainers(instance *openclawv1alpha1.OpenClawInstance) []corev1.Container {
	containers := []corev1.Container{
		buildMainContainer(instance),
	}

	// Add Chromium sidecar if enabled
	if instance.Spec.Chromium.Enabled {
		containers = append(containers, buildChromiumContainer(instance))
	}

	// Add custom sidecars
	containers = append(containers, instance.Spec.Sidecars...)

	return containers
}

// buildMainContainer creates the main OpenClaw container
func buildMainContainer(instance *openclawv1alpha1.OpenClawInstance) corev1.Container {
	container := corev1.Container{
		Name:                     "openclaw",
		Image:                    GetImage(instance),
		ImagePullPolicy:          getPullPolicy(instance),
		SecurityContext:          buildContainerSecurityContext(instance),
		TerminationMessagePath:   corev1.TerminationMessagePathDefault,
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		Ports: []corev1.ContainerPort{
			{
				Name:          "gateway",
				ContainerPort: GatewayPort,
				Protocol:      corev1.ProtocolTCP,
			},
			{
				Name:          "canvas",
				ContainerPort: CanvasPort,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Env:       buildMainEnv(instance),
		EnvFrom:   instance.Spec.EnvFrom,
		Resources: buildResourceRequirements(instance),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/home/openclaw/.openclaw",
			},
			{
				Name:      "data",
				MountPath: "/app/skills",
				SubPath:   "skills",
			},
		},
	}

	// Add probes
	container.LivenessProbe = buildLivenessProbe(instance)
	container.ReadinessProbe = buildReadinessProbe(instance)
	container.StartupProbe = buildStartupProbe(instance)

	return container
}

// buildMainEnv creates the environment variables for the main container
func buildMainEnv(instance *openclawv1alpha1.OpenClawInstance) []corev1.EnvVar {
	// Persistent tool prefix: npm/pip global installs go to the PVC so they
	// survive pod restarts.  The bin dir is prepended to PATH.
	toolPrefix := "/home/openclaw/.openclaw/tools"
	toolBin := toolPrefix + "/bin"

	env := []corev1.EnvVar{
		{Name: "HOME", Value: "/home/openclaw"},
		{Name: "NPM_CONFIG_PREFIX", Value: toolPrefix},
		{Name: "PIP_TARGET", Value: toolPrefix + "/pip"},
		{Name: "PATH", Value: toolBin + ":" + toolPrefix + "/pip/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	if instance.Spec.Chromium.Enabled {
		env = append(env, corev1.EnvVar{
			Name:  "CHROMIUM_URL",
			Value: "ws://localhost:9222",
		})
	}

	return append(env, instance.Spec.Env...)
}

// buildInitContainers creates init containers that seed config and workspace
// files into the data volume. Config is always overwritten (operator-managed),
// while workspace files use seed-once semantics (only copied if not present).
func buildInitContainers(instance *openclawv1alpha1.OpenClawInstance) []corev1.Container {
	var initContainers []corev1.Container

	// Config/workspace init container (only if there's something to do)
	if script := BuildInitScript(instance); script != "" {
		mounts := []corev1.VolumeMount{
			{Name: "data", MountPath: "/data"},
		}
		if configSourceKey(instance) != "" {
			mounts = append(mounts, corev1.VolumeMount{Name: "config", MountPath: "/config"})
		}
		if hasWorkspaceFiles(instance) {
			mounts = append(mounts, corev1.VolumeMount{Name: "workspace-init", MountPath: "/workspace-init", ReadOnly: true})
		}

		initContainers = append(initContainers, corev1.Container{
			Name:                     "init-config",
			Image:                    "busybox:1.37",
			Command:                  []string{"sh", "-c", script},
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePath:   corev1.TerminationMessagePathDefault,
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
			SecurityContext:          buildInitSecurityContext(instance),
			VolumeMounts:             mounts,
		})
	}

	// Seed bundled skills from the OpenClaw image into the PVC on first boot.
	// Uses the same image as the main container so we get the correct bundled skills.
	// Only copies if the skills directory is empty (seed-once semantics).
	initContainers = append(initContainers, corev1.Container{
		Name:            "init-skills",
		Image:           GetImage(instance),
		ImagePullPolicy: getPullPolicy(instance),
		Command: []string{"sh", "-c",
			`if [ -z "$(ls -A /data/skills 2>/dev/null)" ]; then
  echo "Seeding bundled skills into persistent volume..."
  mkdir -p /data/skills
  cp -a /app/skills/. /data/skills/
  echo "Done seeding skills."
else
  echo "Skills directory already populated, skipping seed."
fi`,
		},
		TerminationMessagePath:   corev1.TerminationMessagePathDefault,
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		SecurityContext:          buildInitSecurityContext(instance),
		VolumeMounts: []corev1.VolumeMount{
			{Name: "data", MountPath: "/data"},
		},
	})

	return initContainers
}

// BuildInitScript generates the shell script for the init container.
// It handles config copy (always overwrite), directory creation (idempotent),
// and workspace file seeding (only if not present).
// Returns "" if there is nothing to do.
func BuildInitScript(instance *openclawv1alpha1.OpenClawInstance) string {
	var lines []string

	// 1. Config copy (always overwrite — operator-managed)
	if key := configSourceKey(instance); key != "" {
		lines = append(lines, fmt.Sprintf("cp /config/%s /data/openclaw.json", key))
	}

	ws := instance.Spec.Workspace

	// 2. Create workspace directories (idempotent)
	if ws != nil {
		// Sort for deterministic output
		dirs := make([]string, len(ws.InitialDirectories))
		copy(dirs, ws.InitialDirectories)
		sort.Strings(dirs)
		for _, dir := range dirs {
			lines = append(lines, fmt.Sprintf("mkdir -p /data/workspace/%s", dir))
		}
	}

	// 3. Seed workspace files (only if not present)
	if hasWorkspaceFiles(instance) {
		// Sort keys for deterministic output
		files := make([]string, 0, len(ws.InitialFiles))
		for name := range ws.InitialFiles {
			files = append(files, name)
		}
		sort.Strings(files)
		for _, name := range files {
			lines = append(lines, fmt.Sprintf("[ -f /data/workspace/%s ] || cp /workspace-init/%s /data/workspace/%s", name, name, name))
		}
	}

	if len(lines) == 0 {
		return ""
	}

	return strings.Join(lines, "\n")
}

// hasWorkspaceFiles returns true if the instance has workspace files to seed.
func hasWorkspaceFiles(instance *openclawv1alpha1.OpenClawInstance) bool {
	return instance.Spec.Workspace != nil && len(instance.Spec.Workspace.InitialFiles) > 0
}

// configSourceKey returns the key for the config file from ConfigMap, Secret, or Raw config.
// Returns "" if no config is set.
func configSourceKey(instance *openclawv1alpha1.OpenClawInstance) string {
	if instance.Spec.Config.SecretRef != nil {
		if instance.Spec.Config.SecretRef.Key != "" {
			return instance.Spec.Config.SecretRef.Key
		}
		return "openclaw.json"
	}
	if instance.Spec.Config.ConfigMapRef != nil {
		if instance.Spec.Config.ConfigMapRef.Key != "" {
			return instance.Spec.Config.ConfigMapRef.Key
		}
		return "openclaw.json"
	}
	if instance.Spec.Config.Raw != nil {
		return "openclaw.json"
	}
	return ""
}

// buildChromiumContainer creates the Chromium sidecar container
func buildChromiumContainer(instance *openclawv1alpha1.OpenClawInstance) corev1.Container {
	repo := instance.Spec.Chromium.Image.Repository
	if repo == "" {
		repo = "ghcr.io/browserless/chromium"
	}

	tag := instance.Spec.Chromium.Image.Tag
	if tag == "" {
		tag = "latest"
	}

	image := repo + ":" + tag
	if instance.Spec.Chromium.Image.Digest != "" {
		image = repo + "@" + instance.Spec.Chromium.Image.Digest
	}

	return corev1.Container{
		Name:                     "chromium",
		Image:                    image,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePath:   corev1.TerminationMessagePathDefault,
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: Ptr(false),
			ReadOnlyRootFilesystem:   Ptr(false), // Chromium needs writable dirs for profiles, cache, crash dumps
			RunAsNonRoot:             Ptr(true),
			RunAsUser:                Ptr(int64(999)), // browserless built-in user (blessuser)
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Ports: []corev1.ContainerPort{
			{
				Name:          "cdp",
				ContainerPort: ChromiumPort,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Resources: buildChromiumResourceRequirements(instance),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "chromium-tmp",
				MountPath: "/tmp",
			},
			{
				Name:      "chromium-shm",
				MountPath: "/dev/shm",
			},
		},
	}
}

// buildVolumes creates the volume specs
func buildVolumes(instance *openclawv1alpha1.OpenClawInstance) []corev1.Volume {
	volumes := []corev1.Volume{}

	// Data volume (PVC or emptyDir)
	persistenceEnabled := instance.Spec.Storage.Persistence.Enabled == nil || *instance.Spec.Storage.Persistence.Enabled
	if persistenceEnabled {
		pvcName := PVCName(instance)
		if instance.Spec.Storage.Persistence.ExistingClaim != "" {
			pvcName = instance.Spec.Storage.Persistence.ExistingClaim
		}
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: pvcName,
				},
			},
		})
	} else {
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}

	// Config volume
	defaultMode := int32(0o644)
	if instance.Spec.Config.SecretRef != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  instance.Spec.Config.SecretRef.Name,
					DefaultMode: &defaultMode,
				},
			},
		})
	} else if instance.Spec.Config.ConfigMapRef != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: instance.Spec.Config.ConfigMapRef.Name,
					},
					DefaultMode: &defaultMode,
				},
			},
		})
	} else if instance.Spec.Config.Raw != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ConfigMapName(instance),
					},
					DefaultMode: &defaultMode,
				},
			},
		})
	}

	// Workspace init volume (ConfigMap with seed files)
	if hasWorkspaceFiles(instance) {
		volumes = append(volumes, corev1.Volume{
			Name: "workspace-init",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: WorkspaceConfigMapName(instance),
					},
					DefaultMode: &defaultMode,
				},
			},
		})
	}

	// Chromium volumes
	if instance.Spec.Chromium.Enabled {
		volumes = append(volumes,
			corev1.Volume{
				Name: "chromium-tmp",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			corev1.Volume{
				Name: "chromium-shm",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium:    corev1.StorageMediumMemory,
						SizeLimit: resource.NewQuantity(1024*1024*1024, resource.BinarySI), // 1Gi
					},
				},
			},
		)
	}

	// Custom sidecar volumes
	volumes = append(volumes, instance.Spec.SidecarVolumes...)

	return volumes
}

// buildResourceRequirements creates resource requirements for the main container
func buildResourceRequirements(instance *openclawv1alpha1.OpenClawInstance) corev1.ResourceRequirements {
	req := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	// Requests
	cpuReq := instance.Spec.Resources.Requests.CPU
	if cpuReq == "" {
		cpuReq = "500m"
	}
	req.Requests[corev1.ResourceCPU] = resource.MustParse(cpuReq)

	memReq := instance.Spec.Resources.Requests.Memory
	if memReq == "" {
		memReq = "1Gi"
	}
	req.Requests[corev1.ResourceMemory] = resource.MustParse(memReq)

	// Limits
	if cpuLim := instance.Spec.Resources.Limits.CPU; cpuLim != "" {
		req.Limits[corev1.ResourceCPU] = resource.MustParse(cpuLim)
	}

	memLim := instance.Spec.Resources.Limits.Memory
	if memLim == "" {
		memLim = "4Gi"
	}
	req.Limits[corev1.ResourceMemory] = resource.MustParse(memLim)

	return req
}

// buildChromiumResourceRequirements creates resource requirements for the Chromium container
func buildChromiumResourceRequirements(instance *openclawv1alpha1.OpenClawInstance) corev1.ResourceRequirements {
	req := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	// Requests
	cpuReq := instance.Spec.Chromium.Resources.Requests.CPU
	if cpuReq == "" {
		cpuReq = "250m"
	}
	req.Requests[corev1.ResourceCPU] = resource.MustParse(cpuReq)

	memReq := instance.Spec.Chromium.Resources.Requests.Memory
	if memReq == "" {
		memReq = "512Mi"
	}
	req.Requests[corev1.ResourceMemory] = resource.MustParse(memReq)

	// Limits
	cpuLim := instance.Spec.Chromium.Resources.Limits.CPU
	if cpuLim == "" {
		cpuLim = "1000m"
	}
	req.Limits[corev1.ResourceCPU] = resource.MustParse(cpuLim)

	memLim := instance.Spec.Chromium.Resources.Limits.Memory
	if memLim == "" {
		memLim = "2Gi"
	}
	req.Limits[corev1.ResourceMemory] = resource.MustParse(memLim)

	return req
}

// buildLivenessProbe creates the liveness probe
func buildLivenessProbe(instance *openclawv1alpha1.OpenClawInstance) *corev1.Probe {
	spec := instance.Spec.Probes.Liveness
	if spec != nil && spec.Enabled != nil && !*spec.Enabled {
		return nil
	}

	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{"wget", "--spider", "-q", "-T", "2", fmt.Sprintf("http://127.0.0.1:%d/", GatewayPort)},
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       10,
		TimeoutSeconds:      5,
		SuccessThreshold:    1,
		FailureThreshold:    3,
	}

	if spec != nil {
		if spec.InitialDelaySeconds != nil {
			probe.InitialDelaySeconds = *spec.InitialDelaySeconds
		}
		if spec.PeriodSeconds != nil {
			probe.PeriodSeconds = *spec.PeriodSeconds
		}
		if spec.TimeoutSeconds != nil {
			probe.TimeoutSeconds = *spec.TimeoutSeconds
		}
		if spec.FailureThreshold != nil {
			probe.FailureThreshold = *spec.FailureThreshold
		}
	}

	return probe
}

// buildReadinessProbe creates the readiness probe
func buildReadinessProbe(instance *openclawv1alpha1.OpenClawInstance) *corev1.Probe {
	spec := instance.Spec.Probes.Readiness
	if spec != nil && spec.Enabled != nil && !*spec.Enabled {
		return nil
	}

	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{"wget", "--spider", "-q", "-T", "2", fmt.Sprintf("http://127.0.0.1:%d/", GatewayPort)},
			},
		},
		InitialDelaySeconds: 5,
		PeriodSeconds:       5,
		TimeoutSeconds:      3,
		SuccessThreshold:    1,
		FailureThreshold:    3,
	}

	if spec != nil {
		if spec.InitialDelaySeconds != nil {
			probe.InitialDelaySeconds = *spec.InitialDelaySeconds
		}
		if spec.PeriodSeconds != nil {
			probe.PeriodSeconds = *spec.PeriodSeconds
		}
		if spec.TimeoutSeconds != nil {
			probe.TimeoutSeconds = *spec.TimeoutSeconds
		}
		if spec.FailureThreshold != nil {
			probe.FailureThreshold = *spec.FailureThreshold
		}
	}

	return probe
}

// buildStartupProbe creates the startup probe
func buildStartupProbe(instance *openclawv1alpha1.OpenClawInstance) *corev1.Probe {
	spec := instance.Spec.Probes.Startup
	if spec != nil && spec.Enabled != nil && !*spec.Enabled {
		return nil
	}

	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{"wget", "--spider", "-q", "-T", "2", fmt.Sprintf("http://127.0.0.1:%d/", GatewayPort)},
			},
		},
		InitialDelaySeconds: 0,
		PeriodSeconds:       5,
		TimeoutSeconds:      3,
		SuccessThreshold:    1,
		FailureThreshold:    30, // 30 * 5s = 150s startup time
	}

	if spec != nil {
		if spec.InitialDelaySeconds != nil {
			probe.InitialDelaySeconds = *spec.InitialDelaySeconds
		}
		if spec.PeriodSeconds != nil {
			probe.PeriodSeconds = *spec.PeriodSeconds
		}
		if spec.TimeoutSeconds != nil {
			probe.TimeoutSeconds = *spec.TimeoutSeconds
		}
		if spec.FailureThreshold != nil {
			probe.FailureThreshold = *spec.FailureThreshold
		}
	}

	return probe
}

// getPullPolicy returns the image pull policy with defaults
func getPullPolicy(instance *openclawv1alpha1.OpenClawInstance) corev1.PullPolicy {
	if instance.Spec.Image.PullPolicy != "" {
		return instance.Spec.Image.PullPolicy
	}
	return corev1.PullIfNotPresent
}

// calculateConfigHash computes a hash of the config and workspace for rollout detection.
// Changes to either config or workspace spec trigger a pod restart.
func calculateConfigHash(instance *openclawv1alpha1.OpenClawInstance) string {
	h := sha256.New()
	configData, _ := json.Marshal(instance.Spec.Config)
	h.Write(configData)
	if instance.Spec.Workspace != nil {
		wsData, _ := json.Marshal(instance.Spec.Workspace)
		h.Write(wsData)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}
