Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB5XKSXCQMGQERNY2NRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 32D34B2D48E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 09:12:56 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88432cb7985sf1547985939f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 00:12:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755673975; cv=pass;
        d=google.com; s=arc-20240605;
        b=FC39qI31n2jvKaR+kKfHAjlLkEv40mVX8ect0dicYhnDaz43pN+723jypMxB7FbjDp
         mh7mLm56K6fNmUdyioL2BZHhm3/eqouFR/b6P8LB25pHBQ+BhoSiab7MkafKW9+5Wk1r
         pzdbsy2OuH9R8i4t70qcbYlDPTx9wnsBke1lJs2+/WokVcdaQmoHg1qIk+B7BQoH8boY
         HCkOjyLT0pN4gMHVlUnc+9xLQnYD5OI9uWx0s0XXse9dMGtGHYlNLg01/M4fPFDqV8GR
         s9ZPCv36jUV/c4hMFyy6QtIZ7UCCgJWm3jahhfccLRBlwvZdgR0lTWvMtETTfDoxh97P
         kSIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JiLs5sOOQCJb4EF4MxjEc1L7m6FYP1/9q20iAyfE5Y0=;
        fh=tvi59ClZ9IcxwnHsG1NkQsTa+ntQQJiSAMXw3QY1H6s=;
        b=kakxvr8tYskKMH2m3NzK9rdgB0b9e3pV3SKkIdchJAh/ZcN9MAPnURNJE27IE8yr3v
         k08GAZ4yAl3UjlWP1g30Xj9cJMiXPpncAhNIKZcbJMZEEEhW25ztbamrQIHsDY5Rw6+J
         IX8qZR7ZTPMgfn3zR7ftM5riq0og4ofrQfYmAVrvBLOKkYnQQsVQMZCfK+Yan52huTn9
         lgM1YhIGX1LBKU339T2p9mDRvJ0FGJf7sxkXXqUNpGvjt3RZU50ZVaA28BgklpKo4GAT
         QsCCrqKjeqfG7jGWQ+J1mNwoJl5B/W4+7FW0GC1foiaXTuYgc0beuKAzdJ8aly3A4ZLy
         5xVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755673975; x=1756278775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JiLs5sOOQCJb4EF4MxjEc1L7m6FYP1/9q20iAyfE5Y0=;
        b=KmXglBBaho0eORnSZl3pVQEy8IEy8bCM6m5McMdvxQwDYkH+WW5pWSZsK2WsniNxSq
         jpSSEIrJaSVYhKBDJQfd+QJhi596dmoyY8GXnoyCcG/44lCx14qc00JZjiZ/pjhrYQ6+
         E6vWRxNPkmxcny6rpMNfD/c+LN8Dh4eLa40IundLQklKjwNAnUiLYVoWOALDsLuv3M8S
         7I7J8QEEc5ruju1JpHNtYO08zCfQ4fE+G4g6y5jb5b2hd/KVZHy8co4B8D0LYGpep6kT
         U+jbg4hCRCItodYJTayaUYWE0rKBSvLolbaXnWx9vmsLG9FJlFWWM05TvXjFyBJw5Pdi
         yuXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755673975; x=1756278775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JiLs5sOOQCJb4EF4MxjEc1L7m6FYP1/9q20iAyfE5Y0=;
        b=rk+DgojV6X2gi/vlRyWWIR2yfaAAsAi2UIU2s+3vARE8lS5SUPF4LFKMVlv9LVUF4q
         HArSJcnxvToOUgMfhzDSW4QkZKluVr+xnaFry0VIapeHZNKfOFBmwKYs76hpQIxeyVgm
         rsTdSQAqZRLvwuIKDmNNndnG+OGilEGeNfwhpgnT/ss6IziHI3r/vx/dFwDz2zWzRe74
         4mM0qCXx7ZxdjuMTHRNkB6r3XJjyia1cTbYlfOlV1otClLfRC4uX9BXnuQ4QIc4qKaC1
         vs13JoKbFPMp4zIFeQGT7UUVTfiACzyT5uxlyMshw8cw+TelJF+4Tw9Zzl6oQqimaH1I
         XOxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEeJbts1X7S4eJicB+KPnirxt6Ewvno9GYRL8/F2W7Yy1gdnQi4JTq1KskCBzFOgb8A8pc+w==@lfdr.de
X-Gm-Message-State: AOJu0YwD859ESO1svpSwM5ZqcSnogz6KjNPYB4dnOc3cp961a1+zGwFI
	dLpp6AcUCSx1BGvkAwVm+9V1DRmkQQZPg6ujpr11ylw3+7N/5RVHDO/m
X-Google-Smtp-Source: AGHT+IE77XAhMZ1hq9/Ar9NGGieZqpv8O+rFEaKlxgzV8C/3YFcOTB4QzTikWqvSQxjbxdwrAVK3/w==
X-Received: by 2002:a05:6e02:1aa9:b0:3e3:ef06:674c with SMTP id e9e14a558f8ab-3e67cab3390mr34136175ab.20.1755673974858;
        Wed, 20 Aug 2025 00:12:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdfWUVgzPMGSq1MUQfe3HCnS95YVaPa5hCp+qEMoN1yaQ==
Received: by 2002:a05:6e02:1a0a:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e56fb53fecls67146405ab.2.-pod-prod-02-us; Wed, 20 Aug 2025
 00:12:54 -0700 (PDT)
X-Received: by 2002:a05:6e02:188a:b0:3e5:3a15:93ae with SMTP id e9e14a558f8ab-3e67ca0893fmr37353055ab.6.1755673973893;
        Wed, 20 Aug 2025 00:12:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755673973; cv=none;
        d=google.com; s=arc-20240605;
        b=i+FtbShlM0DDv6Gn6WF7fJwubtGl4o4HqDZlcQffqpYI4Vsg6JUrtqvS/qDmbTnt0v
         TUvQD5wbpKYNmwQC8NXTKt+etjguSr0ehnj2NTQaGE6Jlf2vf0GF0oCLvy0T7ng319GQ
         irBIOITIiU1aQ0KzDKl3NgRXGsPqsSCt3lvmzvOm5aIRQazi+grVEcFMvv4w/ScK6m99
         jaty3QiSu52a4yH20NE/45BT6aencFirH5KDeCm88QKfAptfn6QMvC/qMvt9CorB/rQV
         +wT5w4Hvx5AXMnA0AcCP2hRqKFaGoq2lCX5Zu1OgDGumtYYDvs2sxeUfF/rMW5dsR195
         j90A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=M2C6r5BJpglJYzz5+EWJhInfvCmd+vFPmp3AQ+FGdsg=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=W1YN5AtJpwzbBKTVamcPB2NtkX+853AMym4lNIKjelsdpSKxoEPhEz+RanqLN4m/dR
         +wYU/y+v173sTHaiYO4/gunIkVxPnoxWHRJcKS8fr2+EmIvUNaptFAxg/S7SgDnTfgRS
         AfO2i2HnGxjz8IOmVClmzKIXbuZMZdfkq7Rxl2xQnF9Yf2eGqWn/MI5nXCs7nB8rM0vP
         QkC5sAXgkE8VwyOeW3xzGDh7BC4EATxaORsCpFAw5y8GmD9hc6OT9ukeBR7uYlu4VdsZ
         4NlvYowBOjDKPPAr1dy+dY03xhD+/Ja3KAjVYT6NY4876xAARGWJZHlj/26oTzKlCM03
         SZOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 8926c6da1cb9f-50c948f5320si584608173.1.2025.08.20.00.12.53
        for <kasan-dev@googlegroups.com>;
        Wed, 20 Aug 2025 00:12:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F09681D31;
	Wed, 20 Aug 2025 00:12:44 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 4938B3F58B;
	Wed, 20 Aug 2025 00:12:49 -0700 (PDT)
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
Subject: [PATCH v5 1/2] kasan/hw-tags: introduce kasan.write_only option
Date: Wed, 20 Aug 2025 08:12:42 +0100
Message-Id: <20250820071243.1567338-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250820071243.1567338-1-yeoreum.yun@arm.com>
References: <20250820071243.1567338-1-yeoreum.yun@arm.com>
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
index 0a1418ab72fd..fe1a1e152275 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.write_only=off`` or ``kasan.write_only=on`` controls whether KASAN
+  checks the write (store) accesses only or all accesses (default: ``off``)
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
index 9ad065f15f1d..505bd56e21a2 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2920,7 +2920,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
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
index 9a6927394b54..334e9e84983e 100644
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
 
+/* Whether to check write access only. */
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
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s\n",
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820071243.1567338-2-yeoreum.yun%40arm.com.
