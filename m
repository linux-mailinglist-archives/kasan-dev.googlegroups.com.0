Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBCXT2XCQMGQEMUHXFNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5679CB3E08E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 12:46:36 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70ddd80d02fsf43579446d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 03:46:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756723595; cv=pass;
        d=google.com; s=arc-20240605;
        b=gES2Udi6hKW18KEPwlsNQ5i/rkLgJFrsmM5AE65ezxevyK6N3HmPY0INyrY3uQ1Bdj
         xWRtGKtwM+esECzsjebghn7oPNjHFp0PCFORrdlfsXqrBpeyRZ5Js4+Zl1zGgSO5uXI6
         p0XhL3uDJjpoErrpugn6BOdW/nazEw/W7N0Um3UUCBRoNrQKqUL1BKJFlxgZPOf+3Jcd
         VFONKYPntUyY7xawPqK+mhri6IiQRIVwUxBTKBANsbOt1k8I0yQPWSRPUEk6lINBFfz1
         LOFi/hpUwHNVOgMxjts/4bmhYjozXhqPvzKFHSqJION0BPI5jnkqP+Seq+oBAzixQ1B0
         v0Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EHVEaD6+2wz5Fx011BK+a/qRuHJNF2PfjWcDVtGO/Ro=;
        fh=Mo0HS/s2le0Gjxii+KG1Fi5jT+xZslRLxMUgeNlxmPE=;
        b=SyPJ3i75ReVjs7TY7wc5jOA0xr3u5AI/v+P5XCxIHPUz7SfxZ4DKScb458LGhen4Wm
         CJm4UgLIKzGoHhexHinqc5JMw0Kg91pRauTd7/tsvUz7DkTDf7h+tmlFZu1lW/9wMY7b
         uCnBwTvBigtVHz6UcHfiLa6cqnDcVQ89CZAx40AhJSrUV+XACCVWPk6aWY2JJTL3g61K
         RvkQVIMIBNedpNnApiMl8f8SvAvLkqadJmlJmYu2AlQakIoc94wN6Q3uSQP8FX3RwmfZ
         GykrfnY8dGW7oN/dGRtnAXP52jApM28+OQejuU99Jy98OytLg8ZpCKF0Y3y2MUoESeUd
         D7JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756723595; x=1757328395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EHVEaD6+2wz5Fx011BK+a/qRuHJNF2PfjWcDVtGO/Ro=;
        b=GVXMG00IkP8ivVB+ExHgx8/dSGi3b3n5Nw2BnoFgfQ6EaX8qZTRX8Svi+89T7tBmih
         Kzw0ffeIiVzIunCGH7dZml0X5sNLc5LVUsjN3VVX8JF1LvYubjgSWZp1DsNstr9REHUm
         Z1smTgxiHoO2vRzgdbJA2I5+/TBwwxQOAzCPu/MRY0jExRLUHbC1f3C3neHn3Z8FFUih
         2+mABCswN7W7WcwuIPfq5z+JNU+V6MgwNyILWBOW1q9GSVCoi99cO/94Ifv0q2zQR0Pd
         uDJWRkzmq7I+BQ+hnaz57WtaY0saPDWtukwukq/OIBJ35MxIGu/dfH/kOzWl7ezc1PU1
         CWxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756723595; x=1757328395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EHVEaD6+2wz5Fx011BK+a/qRuHJNF2PfjWcDVtGO/Ro=;
        b=VwcAmAtFc+yaY+NXteOhjGW1ReoPLiyfL6z/PegYk/8EWpSvLmP+CUB2qKmbKV8UqD
         +dTFILFU96GkoZ/7eYryfqb0DZ6yO8fslLaOybovSoq04sSl5sA0nHwfXtyr7ErA/Ic1
         efTt9+ECRLEC/2W3NKXbNeeFulI3q2aY7ToAXnFjIIbNphD+QcULS/C1iUk1vCW853nN
         v7lVC6doed0ikdd8qWUa22qK6d1hVNRD65YSh6cGt7/732Xgy+4+Ka61z2idxRSAcxzT
         mk0h6ArPng86cUdT/HnZlaT+aoMklCA+F+FrRZjEa/cesByinFEkGYfZ+dAf3K41qEfc
         6WIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoAdXQXWLEC1oinom/NmITS3wwjtTar9qZBTw6ni525ADj8tQ/6859QKoInEnSKPo4pmw9gA==@lfdr.de
X-Gm-Message-State: AOJu0Yx6GlTh50x+A/lVc6ZRszOincroCnMMtsJfaWZqhj4TnHbr86kq
	bh0ASY4CWT5Hhu5Mqt3jHrNvdhs5p9u2jWUuTFBT+uKpZS5JM1JpXae4
X-Google-Smtp-Source: AGHT+IE0IZHp0emqjs76NKXw/d8axjBzDRLdtur0WDEO7ohY7IIr7xO6F3nARCMLbOeWdVk2l6zLQg==
X-Received: by 2002:ad4:5de5:0:b0:718:39f4:857d with SMTP id 6a1803df08f44-71839f488f1mr29791906d6.12.1756723594762;
        Mon, 01 Sep 2025 03:46:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEH4Tt38Xnalws1GxhnfTlfpecFmzUUv3Q3qmDey+soA==
Received: by 2002:a05:6214:f66:b0:70d:9340:3384 with SMTP id
 6a1803df08f44-70df054c526ls49518446d6.2.-pod-prod-08-us; Mon, 01 Sep 2025
 03:46:34 -0700 (PDT)
X-Received: by 2002:a05:6102:3350:b0:522:255d:4d19 with SMTP id ada2fe7eead31-52b1be31896mr1603979137.23.1756723594018;
        Mon, 01 Sep 2025 03:46:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756723594; cv=none;
        d=google.com; s=arc-20240605;
        b=bgr+MOhFUmKqMcOUALY4WYTFUH3yAvRDjebSW0HrCuKKnhRfVaHSZZrnhnV1TLAHK8
         OZh9J63uB6lvcx+NSihNpAFCLN72AmvWkbr0YP+T8Hb6x8rVNmcadtGTxSIlb7msJRwP
         bClbzz8knsyYmHZq0gfIQgtcO2UYcX6UNLamjOysjCZ0fc/Q9VCd5/ulg9ymxyQNnuPL
         FTi9I9CdGqOwC1rDuUFc5u0+LPXP9bRXQJN/jWpQ8bCii3CUqnUeBPhYrVQwIXDwx4yP
         RpadtGD61K9dKOIct1PXxMHYnnJ+cGtLSX0xo1dppkOWx6sdmTIgEO0OoldJeXZAlVRY
         npvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=NpM1/eWJJ2noDPeFMVPYJ9eJ6Ch1jmWcdsDAK0nI9f0=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=GekC+xAma3QdwvZb+rjmbV2qsczaQ13QJXwxnLy5sLvIJe4pueZ0F0i7xlr3jmGCr+
         lqfeLDNiUoW3RX4euihXUFccKlDZJnPsJ7i3YtDJSKU4QmKiaefbqL93SuV3iWnLeqlW
         nUQ2g5RHait2UB14v8ThiNFsBOYDTvWw0/Px4tvw8YoRbtvVsMOvkEdSx8DGOIRSREOh
         uKCEDJdlWEAqL3Q/imuLPVEjO+SYCXHPJbEbwB0Pt7K6/R3AKxbG3K0Nxp1tG7WazBsO
         MHu6BhdN+XuIucR6ynVMO/4GJCULUhBq0LRSTbrY0/r5OmyMZFmnpJfCkOHawbPPmIsT
         VzRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ada2fe7eead31-52aef99551asi253178137.2.2025.09.01.03.46.33
        for <kasan-dev@googlegroups.com>;
        Mon, 01 Sep 2025 03:46:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A90C71A25;
	Mon,  1 Sep 2025 03:46:24 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 224823F6A8;
	Mon,  1 Sep 2025 03:46:29 -0700 (PDT)
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
Subject: [PATCH v6 1/2] kasan/hw-tags: introduce kasan.write_only option
Date: Mon,  1 Sep 2025 11:46:22 +0100
Message-Id: <20250901104623.402172-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250901104623.402172-1-yeoreum.yun@arm.com>
References: <20250901104623.402172-1-yeoreum.yun@arm.com>
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
index 9a6927394b54..ef2bec55ec14 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901104623.402172-2-yeoreum.yun%40arm.com.
