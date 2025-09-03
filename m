Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBINQ4HCQMGQEDBZ7F2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id A9E09B4243E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 17:00:53 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-61e492dbe35sf281896eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 08:00:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756911652; cv=pass;
        d=google.com; s=arc-20240605;
        b=UXU6i65duhYzXwpHxwfJVxZW0NEGUDbHO08j8sDLYpJYR1IneXMjY6Ge5O9cLLpTDr
         i4fnBUTECQnfIAqTRou5AVEfRjfKxSdxW75SUlm74NMlgmK8yWXbiXlVdbIW9YEc8qVw
         ElDY8PdM7O15GOWegBn9hJGjddNj35rs739khAtWI1N+n86eu1MeQ3+7W02Vu34rt7O+
         9YkacBju4MY+jOAG5zIQbISJ3VO9X8xIv/PWcaru/uZw+gktg4sV4MLXgBBc9CVgOPSM
         28Wy0GONq5nNNOomxx3oxHxTMVE/bV8tbGKUNVrQEFWjETumNnl0jmDhrfMbQ2RjG7lJ
         3BCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9XtvIgtk5VS2hYw+DKTNNnZL6pcmIkCWlS6v14kCwao=;
        fh=y35E0UTABzh9NJj/aWhNHZoqqo4+ij8xttHWFEXlw+8=;
        b=hYme/SLotXtzZCASQaDviiG1DbM4ZQBzRtVMINKN7Wi7wPUepySnphqe7GpyT0r80o
         QsSpe4zX06dmDsnFbZ5ts6MPG7cMWura2ixqJGTBS4nmcboOxGAlwf9kL32LZsNNJwQT
         PIVj21JAXJ/iEcqMG9ZlDOD5bmOxjpnCJW8h7wJPFMq19vpOId9OWH8KVXQt3j70ppNm
         xdJ04C1SRFE/4UZKuRM1oGXm0VGpVPHJk3BiG/1VWwjMVhcmbMhrODO4f7KMiwI7E2ix
         SYM8n51VPf63/9QeLw4ITPwLbRctl5DnACc/pErIEJYGE51c2j3VneQSC5QWyWsxJATC
         A4nQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756911652; x=1757516452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9XtvIgtk5VS2hYw+DKTNNnZL6pcmIkCWlS6v14kCwao=;
        b=gCqxSye2GegIwcCizTgx0cnisgkTfm1g0Ndbl0kNBcSqMzLCcrFOsE1w3EJMQD2K3f
         jRHup/1DF7SwkRpZQMaG2YCDx3Eld82qpaSdi1sr02erwP2nQ/x4KY++jkus9VMhI5Ov
         pqCrf28/KyhiX+0tCjzBpk489OdBGulBu+LDMma6nVuCvl9R45iddUiY43hmNCi4mKvr
         CfZZFy2tGFlzfuFFqCPcjIMoDXISSd68Z6ncitq5R7JdFXG07HJBICq4zLRAfLt/ZqMJ
         8PgPqE7m9Vq5EsjUEoe9l9VVxCmSHpZZz+VNzhlBkMA4dLHyoXYOv+siObPFrRE4UzDS
         JhWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756911652; x=1757516452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9XtvIgtk5VS2hYw+DKTNNnZL6pcmIkCWlS6v14kCwao=;
        b=EsZzF7k1By3l5kUPxK2wYSauKFKSdyBvUSQ1tM68QQK8JA8LdmqBKVLV2Mcvgu09t/
         afRE7N09Yr85gg7fr1r6uleMD3iF9HBJsP8y5h/BbK0ddErDzl0pY6qpfEUVYAR5G8sz
         JMMaSn87kQMbK86Ilh5aMTIm3sGu4pD6qKFjiN8DtFDZ6YQHMdykaRImcr+hGU6hj4Ev
         vxzeactJoozmYnq3mbYYupK9t1pHmyXiZzFSVhUfGbbvJwvnVBy/o3j2hPDcjurUtSUN
         MOcBVdnwV2CXik/bgZfw55/RZS2INp/9Fto4BFYe2tpqf64a0HvfJMnSZBZKT6K4tE3O
         GzvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnBTYDYQ3AGySGlHgPYhfb222xLKgGKeiS0yhaMwI0W8gvXyebGQDSBAUkruEfbZump+M8IA==@lfdr.de
X-Gm-Message-State: AOJu0Yz3O7SZbqo9MdoLRXFZGteNdhFRKM0htHJKnp+83R5m46gSwZyp
	RLQapzv2+ufGOvfsl9NdkATsgMR/R3hQNNGBmuJmVp5c17Edjarc3Nx5
X-Google-Smtp-Source: AGHT+IFsrs3sNDJcK/x2PdiQMMsd5FfzrQ35Z/Ib4vD+soPP02fHBW6pgd96XKTqYDpDjYbRCafddQ==
X-Received: by 2002:a05:6871:7249:b0:30b:c716:405a with SMTP id 586e51a60fabf-31963071df3mr7403051fac.3.1756911650092;
        Wed, 03 Sep 2025 08:00:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfEdxnN50MZkwQNxrV1vcyfL5vvZShnBMcKOSr3VojrOA==
Received: by 2002:a05:6870:fba4:b0:315:531e:fdba with SMTP id
 586e51a60fabf-315961bb027ls3105681fac.1.-pod-prod-02-us; Wed, 03 Sep 2025
 08:00:46 -0700 (PDT)
X-Received: by 2002:a05:6870:f627:b0:315:31e1:82ff with SMTP id 586e51a60fabf-319630c7e8dmr8534313fac.14.1756911646487;
        Wed, 03 Sep 2025 08:00:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756911646; cv=none;
        d=google.com; s=arc-20240605;
        b=Y2Nv3HGoqIL2Y8W8+qhdiR36zLKSYM1bnR8YcnWu3hEbm+q3LcQjekY+ZrVZRJZZ1o
         uIa1WvYYmHVLXkWmNaOJIUY79IKwf5f1vH9yq2prVaPDseQ06hYkHAlP4pxZyFt6l6Mx
         AGGN04JEsaJfY0frd14P4dceRT71/kEo2CSb2VMJ1T/dE5adUOUYR5MztpajbDOmnZIn
         b5tm1R0/yeFoQc9XIxUAIBoRHhKsUmsLuKIBhkry8og6nxkAPNuOF9Aenf3Bmnj4AKB2
         FzWCuQSlAi0xBkmFHG0AJ0dzzVr4WJFWweVTcesNQnQ/aQdb5RjcBeBMTfL92VKWqTSM
         f9Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=X1wYB9K46eYPi5s7wANx2ga2XIxWjoN/QMngcw4glGU=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=Wdjyf+eDaBqp1WIVjY5ZYWzphjA34ehCJsouPGwV1shyJQSY4Y6imoU8sjbLZ0D5H/
         PA3S3gIq0hGxJXk9mmVCkmcwQFLGTSS3THaaaGcv6entmQZm/zf5thDcVWEVchrkE5NB
         M6tYDx0tNa+Cl7iqc/UgOFBgcySHocWRlg5EATY2cdJUWg4pT3B3u8zHenlIoea0kbSk
         RabaQiztLL9qD+apBudkG4Q5yQFTcA/y99Rn7e8/x1ufNtCHsVoJGkUXcMt+Ur7HUcTv
         /2yrGXBfdkA/+Ufz7E2BR3P+lYvOwU++oaPybJe9wHo9yaf2MaV+rLRVTHPDSovX53NT
         +fzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 46e09a7af769-7457434a12asi436181a34.2.2025.09.03.08.00.46
        for <kasan-dev@googlegroups.com>;
        Wed, 03 Sep 2025 08:00:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 68A57168F;
	Wed,  3 Sep 2025 08:00:36 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id DA68F3F694;
	Wed,  3 Sep 2025 08:00:40 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	catalin.marinas@arm.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	scott@os.amperecomputing.com,
	jhubbard@nvidia.com,
	pankaj.gupta@amd.com,
	leitao@debian.org,
	kaleshsingh@google.com,
	maz@kernel.org,
	broonie@kernel.org,
	oliver.upton@linux.dev,
	james.morse@arm.com,
	ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io,
	david@redhat.com,
	yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v7 1/2] kasan/hw-tags: introduce kasan.write_only option
Date: Wed,  3 Sep 2025 16:00:19 +0100
Message-Id: <20250903150020.1131840-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250903150020.1131840-1-yeoreum.yun@arm.com>
References: <20250903150020.1131840-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
raise of tag check fault on store operation only.
Introcude KASAN write only mode based on this feature.

KASAN write only mode restricts KASAN checks operation for write only and
omits the checks for fetch/read operations when accessing memory.
So it might be used not only debugging enviroment but also normal
enviroment to check memory safty.

This features can be controlled with "kasan.write_only" arguments.
When "kasan.write_only=on", KASAN checks write operation only otherwise
KASAN checks all operations.

This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
with other function together.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
 Documentation/dev-tools/kasan.rst  |  3 ++
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  6 +++
 arch/arm64/kernel/cpufeature.c     |  2 +-
 arch/arm64/kernel/mte.c            | 18 ++++++++
 mm/kasan/hw_tags.c                 | 70 +++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                   |  7 +++
 7 files changed, 104 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0a1418ab72fd..a034700da7c4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.write_only=off`` or ``kasan.write_only=on`` controls whether KASAN
+  checks the write (store) accesses only or all accesses (default: ``off``).
+
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 5213248e081b..f1505c4acb38 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
 #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
 #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
+#define arch_enable_tag_checks_write_only()	mte_enable_kernel_store_only()
 #define arch_suppress_tag_checks_start()	mte_enable_tco()
 #define arch_suppress_tag_checks_stop()		mte_disable_tco()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 2e98028c1965..0f9b08e8fb8d 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
 void mte_enable_kernel_asymm(void);
+int mte_enable_kernel_store_only(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
 {
 }
 
+static inline int mte_enable_kernel_store_only(void)
+{
+	return -EINVAL;
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index ef269a5a37e1..1f6e8c87aae7 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2945,7 +2945,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 	{
 		.desc = "Store Only MTE Tag Check",
 		.capability = ARM64_MTE_STORE_ONLY,
-		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
+		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
 		.matches = has_cpuid_feature,
 		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
 	},
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e773844889..54a52dc5c1ae 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -157,6 +157,24 @@ void mte_enable_kernel_asymm(void)
 		mte_enable_kernel_sync();
 	}
 }
+
+int mte_enable_kernel_store_only(void)
+{
+	/*
+	 * If the CPU does not support MTE store only,
+	 * the kernel checks all operations.
+	 */
+	if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
+		return -EINVAL;
+
+	sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
+			 SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
+	isb();
+
+	pr_info_once("MTE: enabled store only mode at EL1\n");
+
+	return 0;
+}
 #endif
 
 #ifdef CONFIG_KASAN_HW_TAGS
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..d5b5fb47d52b 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
+enum kasan_arg_write_only {
+	KASAN_ARG_WRITE_ONLY_DEFAULT,
+	KASAN_ARG_WRITE_ONLY_OFF,
+	KASAN_ARG_WRITE_ONLY_ON,
+};
+
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
+static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
 
 /*
  * Whether KASAN is enabled at all.
@@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 #endif
 EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
 
+/* Whether to check write accesses only. */
+static bool kasan_flag_write_only = false;
+
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
 
@@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 }
 early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
 
+/* kasan.write_only=off/on */
+static int __init early_kasan_flag_write_only(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.write_only", early_kasan_flag_write_only);
+
 static inline const char *kasan_mode_info(void)
 {
 	if (kasan_mode == KASAN_MODE_ASYNC)
@@ -257,15 +284,28 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_write_only) {
+	case KASAN_ARG_WRITE_ONLY_DEFAULT:
+		/* Default is specified by kasan_flag_write_only definition. */
+		break;
+	case KASAN_ARG_WRITE_ONLY_OFF:
+		kasan_flag_write_only = false;
+		break;
+	case KASAN_ARG_WRITE_ONLY_ON:
+		kasan_flag_write_only = true;
+		break;
+	}
+
 	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s)\n",
 		kasan_mode_info(),
 		str_on_off(kasan_vmalloc_enabled()),
-		str_on_off(kasan_stack_collection_enabled()));
+		str_on_off(kasan_stack_collection_enabled()),
+		str_on_off(kasan_arg_write_only));
 }
 
 #ifdef CONFIG_KASAN_VMALLOC
@@ -392,6 +432,26 @@ void kasan_enable_hw_tags(void)
 		hw_enable_tag_checks_asymm();
 	else
 		hw_enable_tag_checks_sync();
+
+	/*
+	 * CPUs can only be in one of two states:
+	 *   - All CPUs support the write_only feature
+	 *   - No CPUs support the write_only feature
+	 *
+	 * If the first CPU attempts hw_enable_tag_checks_write_only() and
+	 * finds the feature unsupported, kasan_arg_write_only is set to OFF
+	 * to avoid further unnecessary calls on other CPUs.
+	 *
+	 * Although this could be tracked with a single variable, both
+	 * kasan_arg_write_only (boot argument) and kasan_flag_write_only
+	 * (hardware state) are kept separate, consistent with other options.
+	 */
+	if (kasan_arg_write_only == KASAN_ARG_WRITE_ONLY_ON &&
+	    hw_enable_tag_checks_write_only()) {
+		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_OFF;
+		kasan_flag_write_only = false;
+		pr_err_once("write-only mode is not supported and thus not enabled\n");
+	}
 }
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
@@ -404,4 +464,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
 }
 EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
 
+VISIBLE_IF_KUNIT bool kasan_write_only_enabled(void)
+{
+	return kasan_flag_write_only;
+}
+EXPORT_SYMBOL_IF_KUNIT(kasan_write_only_enabled);
+
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..844eedf2ef9c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -431,6 +431,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
 #define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
+#define hw_enable_tag_checks_write_only()	arch_enable_tag_checks_write_only()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
 #define hw_set_mem_tag_range(addr, size, tag, init) \
@@ -451,11 +452,17 @@ void __init kasan_init_tags(void);
 #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_force_async_fault(void);
+bool kasan_write_only_enabled(void);
 
 #else /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
 
 static inline void kasan_force_async_fault(void) { }
 
+static inline bool kasan_write_only_enabled(void)
+{
+	return false;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250903150020.1131840-2-yeoreum.yun%40arm.com.
