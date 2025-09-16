Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB56IU7DAMGQEWH4QK4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 12CE8B8029F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 16:44:36 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-78e0ddd918asf28823466d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 07:44:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758120275; cv=pass;
        d=google.com; s=arc-20240605;
        b=BxhVlr/qxDVxQErro7mPaOS5ODpvzT5hyPYZQIsj1pQmKRI+A9CUy4unKWB6r0roqj
         w+YdKHmdl+gv1UUwcjKM3IP1a6MHYafHcERG3O7QHCphKTMjUG0TEuEL/cPUojSttzS8
         QUS303fDEoAoiZBDXbw89R0vSYnBZIObJIFsKzceDmqnI1tPiz0qsOFb/Bi/Keazm7eK
         HKxcaJotyP/QxfNEu/7mQRNA18B/37A8JRpIRkSpccSaPhSgBNulmWxzLWxCNgBfKQ0g
         NCRcKIYj7xqZ7y6ymEY0mE5WhNxsIt2763yW2fArNrtE9LwFOuQyKbKrkIn+CN90Tz1P
         DdHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2akJnorppU1BApKgvPinvGdxjjgmQBlnuB3D1NgazqM=;
        fh=UFvC0cphSBID1rRX2dEZR+tRNLpp3VYJd5hR+gokm7I=;
        b=ZJHbaQdc1d+6VMd+E1Ls63VKbvzSzdLi8k4zDMWTh3M81zi7zE6HInDNZYSuVXa5zP
         42jWha/+Ayfk8dv5lntXDhy4la8VsAR1/zn1G+M4Jn5RooMSkXpSIbJqCZJTOpmVoQdE
         Sdy8HN9awnOUyxJH3ocFb/DsirPN9z9oYZm53rbyF3IGhMpWpOIVE3/FRcxZtxfk34Pm
         GTkWIeGVx5KSKRrvQ16CyXlXXsjhiZicY2qxwKyvmHXHND1FbETzuQjbFKajtoLbdb58
         97ShU2Jl+FXRw171x4iufcutJd7rkGpOxWQvXmetHC/LglWHb3f6RY2yf2H5hMHzvb32
         JJ4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758120275; x=1758725075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2akJnorppU1BApKgvPinvGdxjjgmQBlnuB3D1NgazqM=;
        b=gQOxNFoyTBLKR4iSnvEyfXj9cNK6CSwY6Ir8H6lK9bj3pCCk20fDvvws8m/D3mLx7Z
         eIks2reOZyKXypT3nN//THj2+MeZMUI3GntlepZRYENoCieL3/NU7kjicWPvlIvHHClN
         3xP+SAiDodAtYDcGv0lzJmBfPLc9Va2iRF0kfIBGfDCxGpaIkGvOmkqbSLJ3UlVHGYav
         Xi0qNw8APY5Sm46w/lOD1C0/vd9lCCIiKArfDDkhbLKNH1ckdILQtKTa0+XC1Wg+8eYe
         Mlgqp05znphb4/Cvgfh7vDbLJ5IjP2IMu5LJtHtrIa2efgAGdaEXLo3XN6Qn27UkG5Ko
         kMkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758120275; x=1758725075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2akJnorppU1BApKgvPinvGdxjjgmQBlnuB3D1NgazqM=;
        b=vdftT0z8zNlYtFe/9N331aIKVFHSMG1u5ceqoxDKxung8LtoKcbchPeZvSZ/1rApO2
         wzcGJdkitDXoPssd27HT2+vLCqQZm/i4qu3k2uPrEQSy+0VTA+JS5cqb+ZYg2lgkHb5T
         p6fdJY7Nnu88pq+biNM+Q4O21obKkOVJHo8E8QK6SdGSM4gXoKOyI8u7W4cFpCHq7GIJ
         qg1nq/10nxHRuNCqToHECNk9ugEviuY6Hl6xXH13wT+47REGNTR2sucv3PRQfmRl1EdQ
         y7JrtAHXrMXJAMCcq8vYYP6Epr3x16HBkjOVMNkmTw5Ngj7M8U5bwzn+Zqi2WFsj44bA
         PhAw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVqI0K8NWZNG1FGWPCQAa7d8cj13uK5Pk16DV4OfCxT84SPXaq55Jt1pyUKeYE48VfUblBWNQ==@lfdr.de
X-Gm-Message-State: AOJu0Yymly64TGtGsTYDVwDrzQizzbYAcrICe3P24FFxCnbjkn0ErGzP
	qTM+FM2/K/6psR3noPULxxSlLLlJFb2V1Zj3kaGKOrIEEv74vyFZujrM
X-Google-Smtp-Source: AGHT+IFFWvvcZ0EPYlHboT+0AqDOJZDrfYLr89sJauvgzjadalib4b9PTJw8xkTkZrZQj9yRlf21dg==
X-Received: by 2002:a05:6870:5ccf:b0:333:507d:8cca with SMTP id 586e51a60fabf-335bfc4324amr53445fac.36.1758061687413;
        Tue, 16 Sep 2025 15:28:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd76oCG5UJ9Ggl3WTz9nqXMJz73R65DQiPC91q6h7/IPDQ==
Received: by 2002:a05:687c:3188:b0:31d:71b5:3ff8 with SMTP id
 586e51a60fabf-32d019a4324ls2062381fac.0.-pod-prod-09-us; Tue, 16 Sep 2025
 15:28:06 -0700 (PDT)
X-Received: by 2002:a05:6871:54b:b0:31d:6b5b:6b57 with SMTP id 586e51a60fabf-335bf82124fmr47714fac.30.1758061686514;
        Tue, 16 Sep 2025 15:28:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758061686; cv=none;
        d=google.com; s=arc-20240605;
        b=eYinsEJNeuyr4hlnAiQVzPkiiyP11tKf+RLeoCPxEUMfdth//q3s/rOFp/wG2N93b8
         CIfHdvEjv4qQTGKwX+E5MsxmvNiV2F5oLS/ni15gG3Rr2j6v18jIEoyj9mV+GDry8eZ3
         fShqH7hQLS1VLkn5fmA+KKJ+Dby1F64RXOsuoQs9FJQx+87af2A8NN/ZcSET/5WFa7gZ
         5v5nM62C5r4jY5hhMjkESse9sXrtaskRHvQIeic0ez5gNn0ogaXOhXjUqMPJ1/pj+5vM
         5SNdynJW76dJkaqt8ziDWUt0EVOxrX+1DunLeUQuyC3JFJCIjLyaVeD6qwyfq54K79w0
         a29w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=QoFLm1mUwDbkOZ3mRiJRZe/3mv5Dh4fC7JZcxAR0hDs=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=dTSbZpwAbrbQHYv/rlCN6Mw2x4GJ5NEBgrjWNHPIP+8vcsnR6h4wVyQKiaSoNdbJ91
         aOgk4kDKbB0ESDbshrw9SsyTAgekOgtNSJX9i8mo+UcPCKMVUfEaPr8D+DMY/qNSlztI
         7cJMmQ+CcXwrH0InX66MvCjmmCh/VrLuMAnbYoX7iczDjimzCNqazea3Ts7YVsDSMQ86
         4ncZ/qCy/VVcIB0ERBVCRy4zl32iT5KxA1+dBPzfa+sg4DQAvMZ0ou7+BhtAFoptlTRd
         6LQ0+NNpCo71tOLqhfbBbmoW7/vfLGZxzUD/oTppH/TF/mxHyGquQaMnReAFAx0Lm/w/
         m4Uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-32d3515f633si722671fac.4.2025.09.16.15.28.06
        for <kasan-dev@googlegroups.com>;
        Tue, 16 Sep 2025 15:28:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BD874152B;
	Tue, 16 Sep 2025 15:27:57 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 0F9D63F673;
	Tue, 16 Sep 2025 15:28:01 -0700 (PDT)
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
Subject: [PATCH v8 1/2] kasan/hw-tags: introduce kasan.write_only option
Date: Tue, 16 Sep 2025 23:27:54 +0100
Message-Id: <20250916222755.466009-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250916222755.466009-1-yeoreum.yun@arm.com>
References: <20250916222755.466009-1-yeoreum.yun@arm.com>
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
Introduce KASAN write only mode based on this feature.

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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
 Documentation/dev-tools/kasan.rst  |  3 ++
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  6 ++++
 arch/arm64/kernel/cpufeature.c     |  2 +-
 arch/arm64/kernel/mte.c            | 18 ++++++++++++
 mm/kasan/hw_tags.c                 | 45 ++++++++++++++++++++++++++++--
 mm/kasan/kasan.h                   |  7 +++++
 7 files changed, 79 insertions(+), 3 deletions(-)

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
index 9a6927394b54..646f090e57e3 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -67,6 +67,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 #endif
 EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
 
+/* Whether to check write accesses only. */
+static bool kasan_flag_write_only = false;
+
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
 
@@ -141,6 +144,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 }
 early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
 
+/* kasan.write_only=off/on */
+static int __init early_kasan_flag_write_only(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_flag_write_only = false;
+	else if (!strcmp(arg, "on"))
+		kasan_flag_write_only = true;
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
@@ -262,10 +282,11 @@ void __init kasan_init_hw_tags(void)
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s)\n",
 		kasan_mode_info(),
 		str_on_off(kasan_vmalloc_enabled()),
-		str_on_off(kasan_stack_collection_enabled()));
+		str_on_off(kasan_stack_collection_enabled()),
+		str_on_off(kasan_flag_write_only));
 }
 
 #ifdef CONFIG_KASAN_VMALLOC
@@ -392,6 +413,20 @@ void kasan_enable_hw_tags(void)
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
+	 * finds the feature unsupported, kasan_flag_write_only is set to OFF
+	 * to avoid further unnecessary calls on other CPUs.
+	 */
+	if (kasan_flag_write_only && hw_enable_tag_checks_write_only()) {
+		kasan_flag_write_only = false;
+		pr_err_once("write-only mode is not supported and thus not enabled\n");
+	}
 }
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
@@ -404,4 +439,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916222755.466009-2-yeoreum.yun%40arm.com.
